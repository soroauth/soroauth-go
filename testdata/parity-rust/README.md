# Rust `stellar-xdr` parity harness

The golden vectors in `../vectors/` prove that soroauth reproduces what
`@stellar/stellar-sdk` emits, byte for byte. They cannot prove that agreement is
*correct*. A bug shared by the Go library and the JS reference would be frozen
into the vectors, and every test in the repository would keep passing.

This harness closes that gap by recomputing each vector's preimage and payload
with the implementation closest to the host itself: the
[`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate, which is what
`rs-soroban-env` decodes with. Agreement here is the strongest offline evidence
available short of submitting a transaction.

For every `../vectors/*.json` it:

1. decodes `unsigned_entry_xdr` into a `SorobanAuthorizationEntry`;
2. rebuilds the `HashIDPreimage` from that entry, `valid_until_ledger` and
   `network_passphrase` — the same construction `Preimage` performs;
3. asserts the base64 marshalling of the preimage equals `preimage_xdr`;
4. asserts `sha256(preimage.to_xdr()).to_hex() == payload_hex`.

The expiration is taken from `valid_until_ledger`, not from the value stored on
the entry, because that is the parameter the signer commits to. The legacy arm
builds `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (CAP-46-11); the V2 and delegates
arms build `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` bound to the
top-level address (CAP-71-01).

## Running it

```sh
cd testdata/parity-rust
cargo test --locked          # unit tests, including the real-vector check
cargo run --locked --bin parity
```

Or, equivalently, `make parity-rust` from the repository root. `--locked` makes
the committed `Cargo.lock` authoritative: the run fails rather than silently
re-resolving to a different `stellar-xdr`.

`rust-toolchain.toml` pins the toolchain to 1.93.0, the same channel the e2e
contract workspace uses, so a clean checkout builds with a known compiler.

## The pinned version

`Cargo.toml` requires `stellar-xdr` exactly (`=28.0.0`) and `Cargo.lock` is
committed. The build script reads the version cargo actually resolved out of
`Cargo.lock` and bakes it into the binary; the harness refuses to run unless
that value is exactly the pinned one, the way `testdata/gen/gen.mjs` refuses to
run against a non-pinned JS SDK and `testdata/parity-python/parity.py` refuses a
non-pinned Python SDK. A parity result is only evidence when the reference that
produced it is the reference named in the repository.

## Skips are loud, and a run that checks nothing fails

Some vectors have no preimage to recompute. Today those are the source-account
vectors: `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` is authenticated by the transaction
envelope, so the generator records an empty `preimage_xdr` and an empty
`payload_hex`.

Skipped cases are printed on **stderr**, named, with the reason, and counted
separately in the summary. A run in which nothing was checked exits non-zero, so
the harness cannot pass by silently skipping everything.

Current coverage on the committed vectors: 11 checked (legacy, V2,
address-with-delegates, create-contract, sub-invocations, expiration boundaries,
negative nonce, both network passphrases), 2 skipped (the two source-account
cases). That is the same coverage the Python harness reports, from a different
implementation.

## If Rust disagrees

Do **not** edit a vector to make the harness pass. A disagreement means one of
the implementations — possibly the one the vectors were built from — is wrong.
Open an issue with the protocol reference (CAP-46-11, CAP-71-01, CAP-71-02) and
the exact bytes, and investigate. The whole value of a second implementation is
that it is allowed to say "no".

The harness never writes to `../vectors/`. It opens the files read-only, and a
test asserts a file's bytes are unchanged around a check.
