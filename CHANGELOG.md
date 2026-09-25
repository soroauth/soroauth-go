# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

**`ParseAddress` — canonical strkey input (issue #122)**

- `ParseAddress` refuses non-canonical SEP-23 base32 spellings of an address —
  lower- or mixed-case, base32 padding, surrounding whitespace, extra
  characters, and non-zero unused trailing bits — rather than recovering the
  same version byte and payload from them. This was already the behaviour,
  inherited from `go-stellar-sdk` `strkey.DecodeAny`/`decodeString`; it is now
  pinned by `TestParseAddressRejectsNonCanonicalEncodings`, which asserts the
  decoder's own reason for each form, by a case-altered property in the gopter
  suite, and by `ExampleParseAddress`/`ExampleFormatAddress`, and is documented
  on the function. A caller can therefore rely on an accepted address string
  being the one canonical spelling of a key, not merely one of several strings
  that decode to it.
- Added `BenchmarkParseAddress` and `BenchmarkFormatAddress` with committed
  alloc/byte budgets, and added a budget for the previously unbudgeted
  `BenchmarkDecodeAuthorizationEntry`. The existing signing-path benchmarks are
  unchanged and within budget: on Intel(R) Core(TM) i5-6300HQ, linux/amd64,
  go1.25.4, `BenchmarkAuthorizeEntry` measured 71/74/101/160 allocs per arm and
  `BenchmarkAuthorizeAll` 1360 allocs, all below the committed budgets.

  **Migration:** none. No accepted input changes meaning and no input that was
  accepted before is refused now; this change is tests, docs and benchmarks.
  No emitted signature or entry bytes change, so golden vectors are unaffected.

### Added (docs correctness)

- The README's three Go examples (Quickstart, Delegates, the inline
  `AllowResign` snippet) are now extracted verbatim, at test time, from real,
  compiling source in `internal/readmesnippets/`, instead of living only as
  free-standing markdown text nothing checked. `TestReadmeSnippetsMatchTheirSource`
  fails and names the snippet if the README drifts from its source; the
  source itself is compiled by the `go build ./...` / `go vet ./...` CI
  already runs, since it carries no build tag, so a snippet that stops
  compiling fails the same way any other compile error does. See
  CONTRIBUTING.md § Verifying README snippets compile. In the course of this,
  the Quickstart and Delegates examples gained the error checks they were
  previously missing (three unchecked errors in Quickstart; the Delegates
  loop swallowed its error entirely, which would not even have compiled once
  wrapped in a real function — `declared and not used: err`).

### Security

- CI: every GitHub Action is now pinned to a full commit SHA (with the
  version recorded in a trailing comment), replacing mutable tags like
  `@v7`. A retagged or compromised action can no longer silently gain this
  repository's CI permissions. `.github/dependabot.yml` keeps the pins
  current by opening a PR that updates the SHA and its comment together.

### Added

**`soroauth doctor`**

- New CLI subcommand checking the local environment for the failures that are
  usually the real cause of a confusing `sign` or `payload` error: an old Go
  toolchain, an unreachable RPC endpoint, or a mistyped `--secret-env`
  variable name. Reports each check as pass/fail, with `--json` for
  structured output, and never prints a secret's value — only whether it is
  set. Exit code reflects overall status (0 all passed, 1 something failed).

**Scoped `AllowResign`**

- `AllowResign` now accepts optional addresses:
  `AllowResign(addresses ...string)`. With no arguments it behaves exactly as
  before — the guard is lifted for whatever address the call targets. With one
  or more addresses, the guard is lifted only when the call's target
  (`ForAddress`, or the signer's own `Address()`) is among them; a target that
  is not named still refuses with `ErrAlreadySigned`, even though
  `AllowResign` was passed. This lets a caller replacing one delegate's
  signature grant the override to just that address, instead of every
  already-signed node an `AuthorizeEntry` call in the same batch might touch.
  The delegates arm's expiration guard (§5.4) is unaffected either way: no
  address list can lift it.

  **Migration:** none required. `AllowResign()` with no arguments is
  unchanged, so every existing call site keeps its current behaviour. No
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Typed address errors**

- `NoMatchingCredentialNodeError`, `DuplicateDelegateError` and
  `MissingSignerError`: error types that wrap the existing
  `ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate` and `ErrMissingSigner`
  sentinels and expose the offending address as an `Address` field.
  `errors.Is` keeps matching the sentinels unchanged, and `errors.As`
  recovers the address without parsing the error string:

  ```go
  var addrErr *soroauth.MissingSignerError
  if errors.Is(err, soroauth.ErrMissingSigner) && errors.As(err, &addrErr) {
      log.Printf("no signer for %s", addrErr.Address)
  }
  ```

  **Migration:** none required. Error messages are byte-identical to v0.1.0,
  and every existing `errors.Is(err, Err…)` check continues to work. Callers
  that previously extracted an address by substring-matching the message may
  switch to `errors.As`; that is optional. No emitted signature or entry bytes
  change, so golden vectors are unaffected.

- Go doc examples for each of the three typed errors, showing the
  `errors.Is` + `errors.As` recovery pattern.
- Signing-path benchmarks covering `Preimage`, `Payload`, `AuthorizeEntry` on
  all three arms (legacy, V2, flat delegates, depth-8 delegate chain),
  `AuthorizeAll` over a 12-entry realistic batch, and
  `AuthorizeInvocation`. CI gates allocs/op and B/op against
  `testdata/bench/budgets.json` via `scripts/checkbench`; `ns/op` is reported
  in PRs but never fails the build. See CONTRIBUTING.md § Benchmarks.

**Envelopes end to end**

- `EnvelopeEntries`, `InspectEnvelope`, `AuthorizeEnvelope`, `EnvelopePayloads`
  and `EnvelopeEntry`: the entry-shaped functions applied to a whole
  `TransactionEnvelope`, each entry reported with the operation index and entry
  index it came from. A fee-bump envelope is read through to its inner
  transaction, because a fee-bump transaction has no operations of its own
  (CAP-15). An envelope with no `invokeHostFunction` operation is refused with
  the new `ErrNoInvokeOperation` rather than reported as an empty result, and an
  envelope type this build does not implement with the new
  `ErrUnsupportedEnvelope`. The unwrapping is done in this library rather than
  through `xdr.TransactionEnvelope.Operations()`, which panics on an
  unrecognised envelope type and on a fee-bump envelope whose inner arm is
  empty.
- The CLI's `inspect`, `payload` and `sign` now accept either an authorization
  entry or a whole transaction envelope, and work out which they were handed. A
  lone entry still prints a single JSON object, so existing scripts keep
  working; an envelope prints one report per entry. `sign --for` is refused for
  an envelope, where one target address would be ambiguous.

  **Migration:** none required. No existing function changes behaviour and no
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Delegation fixtures: session keys, and M-of-N**

- Two new contract fixtures under `e2e/contracts/`, each with unit tests:
  `session-keys`, whose delegates are valid only inside their own ledger window,
  and `threshold-account`, which requires M of its N registered signers. Both
  are test fixtures, not products: no policies, no upgradability, not for
  mainnet.
- E2E scenarios F to I drive them against a live host. F proves an in-window
  session key is accepted; G asserts the contract's own `SessionExpired` error
  code for an expired one; H proves an M-of-N account accepts exactly M signed
  delegates, which is the partial-signing case `AuthorizeAll` deliberately
  permits; I asserts the contract's `InsufficientSignatures` code for M-1.
- Both fixtures document the two clocks a session key lives under:
  `signature_expiration_ledger` is checked by the **host**, in
  `verify_and_consume_nonce`, and only after `__check_auth` has returned `Ok`
  (rs-soroban-env-host 27.0.1, `src/auth.rs:2492-2515`, `:2586-2602`); the
  contract's own window is checked by the **contract**, inside `__check_auth`.
  `delegatesFlow` sets the entry's expiration well past the window, so scenario
  G's refusal is the contract's, on the contract's clock, and the test says so.

**`adapters/walletsdk`, a separate module**

- A wallet-SDK-shaped adapter presenting soroauth the way a wallet holds it: an
  envelope and a keypair. It is a Go module of its own, so importing soroauth
  never drags a wallet SDK in, and CI builds and tests it in a job of its own
  because `./...` at the repository root stops at a nested module.
- `NewSigner` (and `FromOKXKeypair` for the worked integration) adapt a wallet
  SDK keypair into a `soroauth.Signer`; `Requirements` answers "what does this
  envelope want from me?" per entry, with `Wanted` and `Signed`; `Sign` signs
  every entry the key owns; `VerifyEntry` and `VerifyEnvelope` check a signature
  that is already present, comparing the **stored public key** rather than
  trusting the address a node is filed under.
- The two-pass simulation requirement is not hidden. `Sign` returns a `Signed`
  whose `Entries` are what the enforce pass needs, and whose `Envelope` refuses
  with `ErrEnforcePassMissing` until `MarkEnforced` records that the pass ran,
  so a wallet cannot obtain a submittable envelope without saying in code that
  the second simulation happened.
- The worked integration is `github.com/okx/go-wallet-sdk`
  (`coins/stellar/keypair.Full`), bound by name in `okx.go`. The adapter writes
  the same `{public_key, signature}` encoding `NewEd25519Signer` writes;
  `TestSignerMatchesNewEd25519Signer` asserts the two are byte-identical for one
  key and payload, which is what keeps the duplicate encoding honest, and
  `TestOKXKeypairEndToEnd` runs a key from that SDK through the whole adapter and
  checks the result against `crypto/ed25519`.

  **Migration:** none required. The root module gains no new dependency; the
  adapter is optional and versioned with its own module path.

### Changed

**Pooled buffers in the entry deep copy**

- `xdrcopy.Copy` — the deep copy every entry-returning function performs
  before writing — no longer allocates a fresh encoding buffer, encoder,
  reader and decoder on each call. The round-trip now reuses one pooled
  `xdr.EncodingBuffer` and one pooled `xdr.BytesDecoder` per call. They are
  transport scratch only: the copied tree is still allocated fresh (which is
  what keeps the no-aliasing guarantee), and a buffer is not returned to the
  pool until the decode has read it. Measured on INTEL XEON PLATINUM 8573C
  (2 vCPU), linux/amd64, `go test -run '^$' -bench . -benchmem`:

  - `BenchmarkXDRCopy/entry`: 26 allocs / 1632 B → 20 allocs / 1064 B
  - `BenchmarkXDRCopy/preimage`: 24 allocs / 1472 B → 18 allocs / 856 B
  - `BenchmarkAuthorizeEntry/v2`: 85 allocs / 5688 B → 73 allocs / 4504 B
  - `BenchmarkAuthorizeAll`: 1501 allocs / 93505 B → 1348 allocs / 77587 B

- The copy now fails closed if the decode step does not consume exactly the
  bytes the encode step produced — the generated `UnmarshalBinary` it
  replaced discarded that count. Two regression fixtures guard the new
  code: one for that partial-round-trip guard, one for concurrent reuse of
  the pooled buffers.
- CI runs the test suite under `-race` (`go test -race ./...`), and the
  `BenchmarkXDRCopy` budgets sit *below* the pre-pooling cost, so reverting
  the pooling fails the build rather than only a local run. See
  CONTRIBUTING.md § Reproducing a budget failure locally.

  **Migration:** none required. Public API unchanged; no emitted signature
  or entry bytes change — all nine golden vectors pass byte-for-byte.

## [0.1.0] — 2026-09-16

First release. Unaudited.

### Added

**Signing payloads**

- `Preimage` builds the `HashIdPreimage` for an entry, choosing the variant from
  the credentials arm: `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` for legacy
  `SOROBAN_CREDENTIALS_ADDRESS` (CAP-46-11), and
  `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` for both
  `SOROBAN_CREDENTIALS_ADDRESS_V2` and
  `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71-01).
- `Payload` returns the 32 bytes a signer signs.

**Signers**

- `Signer` interface, receiving both the preimage and its payload hash so a
  remote or hardware signer can inspect what it is approving.
- `NewEd25519Signer` for a classic account with one key. It verifies its own
  signature before returning it.
- `NewAccountMultiSigner` for a classic account with several keys, sorted
  strictly ascending by raw public key and capped at 20, as the host requires.
  No JS SDK equivalent.
- `SignerFunc` for custom account contracts whose signature shape the caller
  owns.

**Authorizing**

- `AuthorizeEntry` with `ForAddress` and `AllowResign`.
- `AuthorizeInvocation` for building and signing an entry from scratch,
  defaulting to the V2 arm.
- `AuthorizeAll` for signing a batch, all or nothing.
- `UpgradeToV2` for converting an unsigned legacy entry.

**Delegates (CAP-71-01)**

- `Delegate`, `WithDelegates` and `ValidateDelegateOrder`, supporting arbitrarily
  nested trees, sorting every level by the XDR encoding of the address and
  rejecting duplicates within a level.

**Everything else**

- `Inspect` reporting an entry's structure, `ExpirationAfter`, `ParseAddress`
  and `FormatAddress`.
- Nine exported sentinel errors, each with a test that produces it.
- `soroauth` CLI with `payload`, `sign`, `delegates` and `inspect`. Secrets are
  read only from a named environment variable, never a flag value.

### Proven

- Nine golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert that the
  preimage, payload hash and final signed entry are byte-identical to the
  reference, across both networks, legacy and V2 arms, sub-invocation and
  create-contract trees, the int64 nonce edges, and three delegate cases
  including one address at two nesting depths. The delegate vectors reproduce
  `WithDelegates` itself from the recorded unsorted input rather than re-reading
  an entry the reference already built. CI regenerates them on every push and
  fails on drift.
- Six scenarios on Stellar testnet, protocol version 28, covering all three
  address arms plus multisig, and two rejection scenarios that assert the host's
  specific reason. Transaction hashes in [e2e/RESULTS.md](e2e/RESULTS.md).

### Known limitations

- Unaudited.
- The CLI's `delegates` subcommand takes a flat list; nested delegates are
  library-only.
- No secp256r1 / WebAuthn signer. See `docs/ISSUE_BACKLOG.md`.
- `AuthorizeAll` does not require every delegate node to be signed, because it
  cannot know an account's delegation policy. Check `Inspect`'s per-node
  `Signed` flags before submitting.

[0.1.0]: https://github.com/soroauth/soroauth-go/releases/tag/v0.1.0
