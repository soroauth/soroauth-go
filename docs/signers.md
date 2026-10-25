# Signers

`soroauth` defines a single interface for producing signatures:

This repository ships several signer modes. It currently includes the root
signing API plus three adapter modules (`adapters/awskms`, `adapters/gcpkms`,
and `adapters/walletsdk`), and they are all built on the same signing API, but
they do not carry the same threat model or the same level of evidence.

````

## Choosing a signer

| Signer                  | Threat model it addresses | Evidence and caveats | Recommendation |
|-------------------------|---------------------------|----------------------|----------------|
| `NewEd25519Signer`      | Local private key signing for classic accounts | Golden vectors and live testnet scenarios prove wire format and signature validity | Standard local signer for development and secure environments |
| `NewAccountMultiSigner` | Multi-signature classic accounts | Unit-tested and live testnet scenario C proves a 2-of-2 threshold works | Use for multi-party classic accounts |
| `NewPasskeySigner`      | Passkey / WebAuthn contract authentication | Unit tests and passkey vector checks prove the built-in shape | Use for passkey wallet contracts |
| `NewLedgerSigner`       | Hardware-backed ed25519 signing via Ledger | Unit tests cover the APDU protocol; **no live transaction proof in this repo** | Use for hardware wallet integration |

## Short answer

For standard local usage, `NewEd25519Signer` wrapping a `keypair.Full` is the primary entry point. Note that `remote.NewSigner`'s shipped example is intentionally a local reference, not production network security.

## Memory Hygiene & Key Material

Key material (seeds, private keys, secret environment variables) held in memory presents exposure risks via memory dumps, swapping, and garbage collection.

### Key Material Audit

This repository does not claim that any signer is audited. The library as a
whole remains `unaudited`. The ones with real live proof in this repo are the
ones used in the live testnet scenarios and golden vectors:

- `NewEd25519Signer`
- `NewAccountMultiSigner`
- passkey signer path
- delegated-signer path

Those paths have direct live transaction evidence in `e2e/RESULTS.md` and
corresponding golden-vector checks.

The hardware, remote, Vault, and cloud KMS signers are all well-tested in their
own ways, but they are not all proven by the same live e2e path. In particular,
do not recommend a signer for production use when the repository has no live e2e
evidence for it; the right choice is to require your own operational review and
a contract-specific verification path.

## Threat model by signer type

### 1. Single-key in-memory signing

`NewEd25519Signer` keeps the key in the process. This is the simplest model and
the easiest to reason about, but it is also the easiest to compromise if the
host is compromised or the application is misconfigured.

Use it when:

- the application already owns the signing secret;
- the process is trusted;
- the runtime is short-lived or tightly controlled.

Do not use it when:

- the secret must survive beyond the process boundary;
- you need operator approval or device-level custody;
- the key is not allowed to be extracted by a compromised host.

### 2. Multi-key classic accounts

`NewAccountMultiSigner` solves a different problem: a single compromised key
should not grant access. A classic Stellar account can require several
signatures and enforce ordering and caps exactly as the host expects.

Use it when:

- the account is a classic account with separate signing keys;
- your policy is threshold-based or separates operator roles;
- you need the host's ordering rules enforced in code.

The most important rule is that the host rejects unordered or duplicate vectors,
and this library enforces that before the entry is submitted.

### 3. Passkeys and custom account contracts

A passkey signer is not a classic-account signer. A custom account decides what
`ScVal` shape it accepts and what bytes it verifies. The passkey shape is
therefore contract-specific, not protocol-defined.

Use it when:

- the account's `__check_auth` is a wallet contract that expects a
  WebAuthn/P-256 signature shape;
- the browser or authenticator is the trusted source of the challenge and
  signature;
- you have verified the contract's exact `ScVal` layout and challenge-binding
  rules.

This repository's passkey path has evidence for the wallet signature shape and
for the challenge-binding logic, but it is still not a general-purpose approval
layer for every custom wallet contract.

### 4. Hardware signing

`NewLedgerSigner` removes the seed from the host and asks the device to review
and sign the payload. That materially reduces the risk of host compromise, but
it shifts the trust model to the device, the user, and the wallet app's review
flow.

Use it when:

- the operator is physically present or the device review is part of the control
  plane;
- you need the private key out of the application process from the start;
- your workflow accepts the extra operational steps and the device-specific
  failure modes.

### 5. Vault, KMS, and remote signers

Vault, AWS KMS, and GCP KMS all aim to keep the key material under somebody
else's custody. That is valuable, but the trust boundary changes:

- Vault requires correct policy, token rotation, and key naming.
- AWS and GCP require IAM, key versioning, and key usage policies.
- A remote signer requires authenticated transport and a clear authorization
  model.

These signers are useful when company policy requires secrets to be outside the
application runtime, but they are not magic. They still need operational reviews
and contract-specific validation before production use.

### 6. CLI exec-based external signer (`--signer-cmd`)

From the command line, `soroauth sign --signer-cmd <executable>` delegates
signing to an external program over `stdin` and `stdout` using the same JSON
message shapes as `remote/protocol.go`:

```json
{"version":1,"address":"G...","preimage":"<base64 HashIdPreimage>","payload":"<64-char hex sha256>"}
````

The helper writes `{"signature":"<base64 XDR ScVal>"}` (or `{"error":"..."}`) to
`stdout`. Because the full `HashIdPreimage` is passed alongside the 32-byte
digest, the helper can recompute the SHA-256 payload and show the operator which
contract function, arguments, nonce, and expiration ledger they are approving.
The CLI validates the returned `ScVal` before writing it into the authorization
entry, distinguishes non-zero exit, timeout (`--signer-timeout`), and malformed
output as separate errors, and strips secret-bearing variables from the helper's
environment.

## Do not use these as blanket recommendations

The following patterns are useful in local tests or in expert-controlled
deployments, but they are not safe blanket recommendations for production
without additional review:

- bare in-memory ed25519 keys in long-lived services;
- remote signers without authenticated TLS and explicit authorization;
- custom `SignerFunc` implementations whose format was never reviewed against
  the contract;
- any signer for which the repository has no live e2e proof and you cannot
  explain the operational control plane.

## Practical guidance

1. For a single app-owned account key, start with `NewEd25519Signer`.
2. For a classic account that uses multiple keys, use `NewAccountMultiSigner`.
3. For user-owned credentials, use a passkey signer bound to the wallet contract
   you actually deploy.
4. For operator-controlled custody, choose `NewLedgerSigner` or a KMS/Vault
   signer and keep the rest of the runtime minimal.
5. For service separation, use `remote.NewSigner` only behind authenticated
   transport and with a clear trust model for the remote signer.

## Status

The library as a whole is v0.1.0 and **unaudited**. That is not a recommendation
to avoid them; it is a reminder that the difference between a signer type and a
safe production deployment is the operating model around the key, not just the
Go implementation.

## Memory hygiene and key material

An audit of where key material lives in this library, and what can honestly be
done about it. The short answer is that Go gives less here than it first
appears, and for the most exposed path it gives nothing at all.

### Where key material is held

1. **`NewEd25519Signer` and `keypair.Full`.** The seed and private key live
   inside the SDK's `keypair.Full`. This library does not own those internals
   and cannot zero them.

2. **`AccountMultiSigner`.** Holds a slice of keypairs. Same position as above
   for each element, and the slice header itself carries no key bytes.

3. **The CLI's `--secret-env` read path.** This is the one worth stating
   precisely, because it is the most exposed and the easiest to describe
   wrongly:

   ```go
   seed := getenv(secretEnv)      // cmd/soroauth/sign.go
   parsed, err := keypair.Parse(seed)
   ```

   `os.Getenv` returns a **Go string**, which is immutable. There is no
   library-owned mutable buffer on this path to overwrite, so zeroing it is not
   something this library declines to do — it is not expressible without
   `unsafe`, and would not help if it were: the same bytes remain in the process
   environment block for the lifetime of the process, where any code in the
   process and anything that can read `/proc/<pid>/environ` can still see them.

4. **The adapter modules.** AWS KMS, GCP KMS and the wallet SDK never hold a
   private key in this process at all. That is the real mitigation, and it is a
   property of where the key lives rather than of anything this library does
   with memory.

### What Go can and cannot guarantee

- **Nothing is zeroed today.** No code path in this library overwrites key
  material after use, and the sections above say why for each one.
- **The garbage collector may copy a value before any zeroing runs**, so even
  where a mutable buffer exists, zeroing removes one copy rather than all of
  them.
- **Swap and core dumps** capture whatever is resident, which zeroing does not
  reach.

### What this means in practice

Treat process memory as readable by anything that can read the process. If that
is not acceptable for your threat model, the answer is not memory hygiene inside
this library — it is keeping the key outside the process, which is what the KMS,
Vault, Ledger and passkey signers are for. `docs/signers.md`'s table above says
which of those have live proof in this repository.
