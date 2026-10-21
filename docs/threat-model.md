# Threat model

**Status:** unaudited. No third party has reviewed this code. It is proven
byte-for-byte against `@stellar/stellar-sdk@17.1.0` by golden vectors, and
proven against a live host by the testnet scenarios in `e2e/RESULTS.md` — but
agreeing with a reference implementation and being accepted by a host are not
the same thing as having been audited. See [parity.md](parity.md) for what each
suite covers and what none of them rule out.

## Trust boundaries

This library sits between the caller and the Soroban host. The following trust
boundaries enumerate what the library assumes, what it checks, and what it
cannot check. Each claim cites the code that enforces the check.

### 1. Caller

**What the library assumes:**

- The caller has derived valid credentials (nonce, expiration, invocation tree)
- The caller will not mutate the returned entry except through the provided
  `AuthorizeEntry` / `AuthorizeAll` API
- The caller will pass a non-empty network passphrase when building preimages

**What the library checks:**

- `AuthorizeEntry` validates that `validUntilLedger != 0` (returns
  `ErrInvalidExpiration` otherwise) — `authorize.go:78`
- `AuthorizeEntry` validates that the target address matches the signer's
  address or the `ForAddress` option (returns `ErrNoMatchingCredentialNode`
  otherwise) — `authorize.go:92`
- `AuthorizeEntry` rejects already-signed nodes unless `AllowResign()` is
  passed, preventing silent invalidation of delegate signatures —
  `authorize.go:104`
- `AuthorizeAll` returns a `nil` slice on any error, never a partial result —
  `batch.go:55`
- `AuthorizeAll` requires every address-arm entry to have a signer whose
  `Address()` matches its top-level address, otherwise returns
  `ErrMissingSigner` — `batch.go:42`

**What it cannot check:**

- Whether the caller's invocation tree is semantically valid for the target
  contract — the library only structurally walks the XDR
- Whether the caller's nonce has already been consumed on-chain — the host
  consumes nonces during application; offline code cannot know
- Whether the caller's fee configuration is sufficient for the enforcing pass
- Whether the caller's expiration is still valid at the time of submission — the
  host rejects when `current_ledger > signatureExpirationLedger`, but the
  library only stores the value the caller provided

**Code citations:**

- `authorize.go:78` — `ErrInvalidExpiration` check
- `authorize.go:92` — target-address matching
- `authorize.go:104` — already-signed node guard
- `batch.go:42` — `ErrMissingSigner` check
- `batch.go:55` — all-or-nothing error policy

### 2. Signer

**What the library assumes:**

- The signer's `Address()` returns the correct account or contract address
- The signer's `Sign()` method returns a valid `ScVal` map with the expected
  shape (public_key + signature for ed25519, or a custom map for `SignerFunc`)
- The signer will not mutate the preimage or payload arguments

**What the library checks:**

- `NewEd25519Signer` self-verifies its own signature and returns
  `ErrSignatureMismatch` on failure — `signer.go:61`
- `NewAccountMultiSigner` enforces keys sorted strictly ascending by 32-byte
  pubkey, rejects duplicate keys, zero keys, and more than 20 keys
  (`ErrTooManySignatures`) — `signer.go:92`
- Every `Signer.Sign()` call passes the context through (`ctx.Err()` checked
  before work) — so a cancelled context fails closed even on a path that never
  reaches a signer — `signer.go:38`
- `SignerFunc` is an adapter with no verification possible — the caller owns the
  signature shape — `signer.go:116`

**What it cannot check:**

- Whether the signer's key actually controls the address it claims — a
  misconfigured KMS key alias or wrong account address produces a service that
  starts cleanly and fails every submission on-chain, after fees. The library
  has no offline way to verify key-address ownership for custom accounts
- Whether the signer's output is deterministic across process boundaries — the
  library assumes ed25519 is deterministic but cannot enforce this for custom
  signers
- Whether a remote signer is honest or compromised — the library transmits the
  preimage and payload as-is; it does not validate the signer's correctness

**Code citations:**

- `signer.go:38` — context cancellation check
- `signer.go:61` — self-verification and `ErrSignatureMismatch`
- `signer.go:92` — multisig key validation (sorting, cap, duplicates)
- `signer.go:116` — `SignerFunc` advisory: "No verification is possible here"

### 3. RPC endpoint

**What the library assumes:**

- The RPC endpoint returns honest simulation results that match what the host
  would produce at execution time
- The network passphrase passed to preimage building matches the network the RPC
  serves (testnet vs public mainnet)
- The RPC response includes the correct credential arm per entry

**What the library checks:**

- The `e2e` test harness verifies RPC connectivity with a live call before
  relying on it — `e2e_test.go:28`
- Simulation responses are validated for the presence of authorization entries
  and resource footprints — `rpcflow` (if used) reports missing fields

**What it cannot check:**

- Whether the RPC endpoint is compromised or returning fabricated results — the
  library trusts the simulation output as-is. A hostile RPC can lie about the
  entries to sign, and `--network` from an endpoint makes that sharper
- Whether the RPC's protocol version matches the library's expectations — the
  library depends on the pinned `go-stellar-sdk` version for protocol details
- Whether the simulation was run in recording mode vs enforcing mode — the
  library does not re-run the enforcing pass; it only signs what was returned

**Code citations:**

- `e2e_test.go:28` — RPC liveness check: "Read the RPC URL from
  `SOROAUTH_RPC_URL` (default `https://soroban-testnet.stellar.org`) and verify
  with a live call before relying on it."
- `protocols/rpc/simulate_transaction.go` (pinned SDK) — the response shape and
  credential arm determination

### 4. Entry source

**What the library assumes:**

- The authorization entry XDR is well-formed and decodable
- The entry's `RootInvocation`, `Credentials`, `Nonce`, and
  `SignatureExpirationLedger` fields are consistent with each other
- The entry's credential arm is one of the four supported arms

**What the library checks:**

- `ParseAddress` rejects `M…` muxed addresses for address credentials —
  `address.go:43`
- `Preimage` returns `ErrUnsupportedCredentials` for unsupported credential arms
  — `preimage.go:53`
- `ValidateDelegateOrder` checks delegate ordering and duplicate rules
  recursively — `delegates.go:38`
- `Inspect` reports structural errors (not panics) on arbitrary entry bytes —
  `inspect.go:38`
- `AuthorizeEntry` deep-copies the entry first with `internal/xdrcopy` — so the
  caller's input is never mutated — `authorize.go:41`

**What it cannot check:**

- Whether the entry's signature was produced by the claimed signer — the library
  verifies the signature shape but not the key ownership
- Whether the entry's invocation tree is complete or well-formed from the
  contract's perspective — the library structurally walks the XDR but does not
  interpret the contract's runtime logic
- Whether the entry's nonce has been consumed or will be consumed on-chain —
  offline code cannot know the ledger's nonce state
- Whether the entry's expiration is still valid at submission time — the host
  enforces `current_ledger > signatureExpirationLedger`, but the library only
  stores the value provided

**Code citations:**

- `address.go:43` — muxed address rejection
- `preimage.go:53` — `ErrUnsupportedCredentials`
- `delegates.go:38` — `ValidateDelegateOrder` sorting/duplicate validation
- `inspect.go:38` — structural inspection that never panics
- `authorize.go:41` — deep-copy via `internal/xdrcopy` before modification

### 5. Network

**What the library assumes:**

- The network passphrase is one of the well-known Stellar passphrases (testnet:
  "Public Global Stellar Network ; September 2015", public: "Friendbot Test
  Network ; September 2015")
- The protocol version active on the network supports the credential arms being
  used (CAP-46-11, CAP-71-01, CAP-71-02)

**What the library checks:**

- `UpgradeToV2` is a best-effort conversion; the caller must check or upgrade
  themselves — `upgrade.go:21`
- The `e2e` suite reads the RPC URL from `SOROAUTH_RPC_URL` and verifies it with
  a live call — `e2e_test.go:28`

**What it cannot check:**

- Whether the network's `max_live_until_ledger` ("signature expiration is too
  late") rejects the entry — this is a network setting the library cannot know
  offline. The host also rejects values above this cap
- Whether the current ledger sequence will cause the host to reject the
  signature — the library stores `validUntilLedger` as provided; the host
  rejects when `current_ledger > signatureExpirationLedger`
- Whether protocol upgrades (e.g., CAP-85 / Protocol 28) change the wire format
  or credential arm rules — the library pins `go-stellar-sdk` v0.7.3 and
  documents the pin in `docs/sdk-support.md`

**Code citations:**

- `upgrade.go:21` — "callers who need V2 must check or upgrade"
- `e2e_test.go:28` — RPC URL verification
- `docs/sdk-support.md` — pinned Go toolchain and SDK version policy
- `expiration.go` — doc comment: host rejects when
  `current_ledger > signatureExpirationLedger`; values above
  `max_live_until_ledger` are also rejected by the network; the library does not
  cap

## Summary

| Boundary     | Library assumes                                         | Library checks                                                                                               | Library cannot check                                                           |
| ------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| Caller       | Valid credentials, no input mutation                    | `ErrInvalidExpiration`, target-address match, already-signed guard, all-or-nothing batch, `ErrMissingSigner` | nonce consumption, fee sufficiency, expiration validity at submission          |
| Signer       | Correct address, valid ScVal shape, no mutation of args | Self-verification, key sorting/capping, context cancellation, `SignerFunc` advisory                          | key-address ownership, output determinism, signer honesty                      |
| RPC endpoint | Honest simulation results, correct passphrase           | RPC liveness check, response validation                                                                      | fabricated results, protocol version mismatch, recording vs enforcing mode     |
| Entry source | Well-formed XDR, consistent fields, supported arms      | Address muxed rejection, unsupported credentials, delegate ordering, structural inspection, deep-copy        | key ownership, contract runtime logic, nonce consumption, expiration validity  |
| Network      | Well-known passphrase, supporting protocol version      | RPC URL verification, SDK pinning                                                                            | `max_live_until_ledger` cap, current ledger sequence, protocol upgrade effects |

**Bottom line:** The library is unaudited. Signature-correctness bugs are
critical (see (see SECURITY.md). What the library does guarantee — byte-for-byte
agreement with the pinned SDK reference implementation for the preimage and
payload hash — is strong evidence but not an audit. Neither golden vectors nor
e2e testnet acceptance rules out a class of bug shared by both implementations
or a host configuration that diverges from the library's expectations. Judge
accordingly before signing anything valuable.
