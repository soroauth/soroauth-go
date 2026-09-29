# What the parity suites prove

"Proven byte-for-byte" is strong evidence and it is not an audit. This page
states exactly what each agreement suite covers, and what none of them rule out.
The honest framing is the same one in
[SECURITY.md](../SECURITY.md#status-of-this-library): agreeing with a reference
implementation and being accepted by a host are not the same thing as having
been audited, and neither rules out a class of bug that more than one
implementation shares.

## What each suite covers

| Suite                                               | It proves                                                                                                                                                                                                                                                                                                                    | How to run it        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| Golden vectors (`testdata/vectors/`)                | soroauth reproduces `@stellar/stellar-sdk@17.1.0` byte for byte: for every vector, the preimage bytes, the payload hash, and the final signed entry are identical. The generator (`testdata/gen/gen.mjs`) refuses to run against any other SDK version, and CI regenerates on every push and fails on drift.                 | `make vectors-check` |
| Python parity (`testdata/parity-python/`)           | The vectors' preimages and payloads recompute identically under a third, separately maintained implementation (`stellar-sdk==16.1.0` on PyPI, pinned in `requirements.txt`, refused if anything else is installed). This is the suite that can say "no" to a bug the Go library and the JS reference share.                  | `make parity`        |
| Rust parity (`testdata/parity-rust/`)               | The same recomputation against `stellar-xdr =28.0.0` (pinned exactly, `Cargo.lock` committed, `--locked` enforced) — the XDR implementation `rs-soroban-env` itself decodes with. Agreement here is the strongest offline evidence available short of submitting a transaction.                                              | `make parity-rust`   |
| Differential fuzzing (`testdata/differential/`)     | Agreement beyond the cases someone wrote down: `cmd/difffuzz` generates a deterministic corpus of random structurally valid entries (every arm, random delegate and sub-invocation depth, both nonce signs, the `int64` edges) and requires Go, JS, and Python to agree on every payload. A divergence is a release blocker. | `make differential`  |
| Wasm parity (`wasm/parity.mjs`)                     | The browser build emits the same bytes as the native one: every golden vector replayed through `wasm/dist/soroauth.wasm`. Note the direction — the wasm core is a thin binding over this same Go code, so this proves the build, not independence.                                                                           | `make wasm-check`    |
| Live testnet scenarios (`e2e/RESULTS.md`)           | A real host accepted (or, for the rejection scenarios, refused for the asserted reason) transactions carrying these entries. This is the only suite where the Soroban host itself renders a verdict.                                                                                                                         | `make e2e`           |
| Passkey shape vectors (`testdata/vectors/passkey/`) | The P-256 `{public_key, signature}` map is byte-identical to what `smart-account-kit@0.8.0`, a real passkey wallet library, builds — asserted for both the inner map and the library's complete output. Live acceptance of that shape is scenarios J and K, not this suite.                                                  | `make vectors-check` |

Three behaviors are uniform across the offline suites, by design: cases with no
preimage (today the source-account vectors — arm 0 is authenticated by the
transaction envelope, CAP-46-11) are skipped loudly, named, and counted; a run
that checks nothing exits non-zero, so no suite can pass by doing nothing; and
no suite ever writes to the vectors — a disagreement means an implementation is
wrong, and editing a vector to make a harness pass destroys the evidence (see
[CONTRIBUTING.md](../CONTRIBUTING.md#golden-vectors)).

## What none of them rule out

- **A bug every offline implementation shares.** Each new implementation narrows
  the window — the Rust harness shares the host's own decoder, the differential
  corpus reaches entries nobody wrote down — but all of them are still readers
  of the same CAPs. If every reader misreads the same sentence, every suite
  stays green. Only the host's verdict closes that gap, and only for the entries
  actually submitted.
- **Anything the ledger knows and offline code cannot.** Whether a signing key
  is currently a signer of the account, whether weights meet the threshold,
  whether a nonce was already consumed, whether the expiration is still valid
  (or past `max_live_until_ledger`) at submission time, and whether the fee
  covers the resources — none of these are in the bytes being compared. The same
  boundary, stated per-verdict, is in
  [verification-limits](verification-limits.md).
- **Custom-account acceptance.** The parity suites compare classic ed25519
  payload bytes. A smart wallet's signature is whatever its `__check_auth`
  accepts; only the contract, running on a host, can say whether a given value
  is valid. The passkey shape vectors pin a wallet library's output; the live
  proof that a host accepts that shape is e2e scenarios J and K.
- **The future.** The e2e results record what a host accepted on a date, on
  testnet, at one protocol version. A protocol upgrade, a changed network
  setting, or mainnet state can all invalidate what was true then. The scheduled
  e2e runs exist for exactly this reason.
- **Being audited.** No third party has reviewed this code. Four implementations
  agreeing, plus a host accepting the output, is the best evidence this
  repository can produce — and it is still not a review. Judge accordingly
  before signing anything valuable, and read the code.
