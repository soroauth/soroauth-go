# Python stellar-sdk parity harness

The golden vectors in `../vectors/` prove that soroauth reproduces what
`@stellar/stellar-sdk` emits, byte for byte. They cannot prove that agreement is
*correct*. A bug shared by the Go library and the JS reference would be frozen
into the vectors, and every test in the repository would keep passing.

This harness closes that gap by recomputing each vector's preimage and payload
with a third implementation: the Python [`stellar-sdk`](https://github.com/StellarCN/py-stellar-base)
(`stellar-sdk` on PyPI, module `stellar_sdk`), which is maintained separately
from the JS SDK.

For every `../vectors/*.json` it:

1. decodes `unsigned_entry_xdr` into a `SorobanAuthorizationEntry`;
2. rebuilds the `HashIDPreimage` from that entry, `valid_until_ledger` and
   `network_passphrase` using `stellar_sdk.auth.build_authorization_preimage`;
3. asserts `preimage.to_xdr() == preimage_xdr`;
4. asserts `stellar_sdk.auth.authorization_payload_hash(preimage).hex() == payload_hex`.

## Running it

```sh
python3 -m venv .venv                  # if you have not already
. .venv/bin/activate
pip install -r testdata/parity-python/requirements.txt
python3 testdata/parity-python/parity.py
```

Or, equivalently, `make parity`. Its unit tests use only the standard library:

```sh
python3 testdata/parity-python/test_parity.py
```

## The pinned version

`requirements.txt` pins `stellar-sdk==16.1.0` and its XDR runtime, `xdrlib3`. The
harness reads the version that is *actually installed* and refuses to run
against anything else, exactly as `testdata/gen/gen.mjs` refuses to run against
a non-pinned JS SDK. A parity result is only evidence when the reference that
produced it is the reference named in the repository.

The Python SDK version numbers are independent of the JS SDK's, so
`stellar-sdk==16.1.0` is the correct pin even though the vectors come from
`@stellar/stellar-sdk@17.1.0`. What matters is that each is pinned; they do not
need to share a number.

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
cases). That is complete enough to be meaningful, which is why it runs in CI.

## If Python disagrees

Do **not** edit a vector to make the harness pass. A disagreement means one of
the two implementations — possibly the one the vectors were built from — is
wrong. Open an issue with the protocol reference (CAP-46-11, CAP-71-01,
CAP-71-02) and the exact bytes, and investigate. The whole value of a third
implementation is that it is allowed to say "no".

The harness never writes to `../vectors/`. It opens the files read-only.
