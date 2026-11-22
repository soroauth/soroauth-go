# Cross-language conformance suite

One committed case list every binding runs, with a shared output format and a
per-binding thin runner. See issue #545 for the design.

## Why this exists

Each binding has its own tests, so each proves something slightly different and
a behaviour can diverge in one language without any test disagreeing.
`signertest` does this for Go `Signer` implementations; the bindings had no
equivalent. Divergence between a Node client and a Rust client is exactly where
it is most likely and least visible.

## Contract

- **One data file.** `cases.json` is the only source of cases. Each case has a
  stable `id`, an `op` (one of `preimage`, `payload`, `authorize_with_seed`),
  and either a reference to an existing golden vector (`vector`) or an explicit
  `input` map. Expected outcomes are either derived from the referenced vector
  or stated explicitly in `expect`. Error cases list the `kind` strings any of
  which the binding may return (bindings vary on the exact sentinel when a
  failure is not a library-exported one).

- **One output format.** A binding's runner reads `cases.json` and writes one
  JSON object per line to stdout, in the order the cases are declared:

  ```ndjson
  {"id":"preimage.v2_single_testnet","ok":true,"preimage_xdr":"...","payload_hex":"..."}
  {"id":"error.preimage_empty_entry","ok":false,"kind":"ERROR"}
  ```

  Keys on `ok:true` rows are the operation's outputs (`preimage_xdr`,
  `payload_hex`, `signed_entry_xdr`); `ok:false` rows carry `kind` and an
  `error` string. The `id` is always present and is the key a diff uses.

- **One diff.** A binding's CI job runs its runner and diffs the output against
  the expected outcomes `cases.json` declares. A mismatch fails that job and
  names the failing case by `id`.

- **Error cases are in.** A binding that returns a wrong `kind` for an error
  case fails here, not in a per-binding test with its own interpretation.

## Operations

| `op`                  | Inputs                                                                                            | Successful output             |
| --------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------- |
| `preimage`            | `entry_xdr_b64`, `valid_until_ledger`, `network_passphrase`                                       | `preimage_xdr`, `payload_hex` |
| `payload`             | `preimage_xdr_b64`                                                                                | `payload_hex`                 |
| `authorize_with_seed` | `entry_xdr_b64`, `valid_until_ledger`, `network_passphrase`, `seed_hex`, `for_address` (optional) | `signed_entry_xdr`            |

`seed_hex` is 32-byte hex for a single ed25519 seed. `for_address` defaults to
the entry's top-level address when omitted.

## Case schema

```jsonc
{
  "id": "preimage.v2_single_testnet",   // stable, matches [a-z0-9_.]
  "op": "preimage",
  "vector": "v2_single_testnet",        // optional: load inputs from
                                        //           testdata/vectors/<name>.json
  "input": {...},                       // optional: explicit inputs
                                        //           (used instead of `vector`)
  "override": {...},                    // optional: modify vector inputs
                                        //           (adds or replaces keys)
  "expect": {                           // optional for happy-path cases:
                                        //   vector-derived output is the
                                        //   expected value
    "ok": false,                        // for error cases
    "kind_in": ["ERROR", "DECODE_LIMIT"]
  }
}
```

A case with `vector` and no `expect` is a happy-path case: the expected output
is whatever the vector's own `preimage_xdr` / `payload_hex` / `signed_entry_xdr`
says. A case with `expect.ok: false` is an error case.

## Per-binding runner

Each binding ships a runner under its own directory that implements the contract
above. The runner reads `testdata/conformance/cases.json` and writes NDJSON to
stdout; nothing else.

| Binding | Runner                               | Invocation                                                                 |
| ------- | ------------------------------------ | -------------------------------------------------------------------------- |
| Go      | `conformance/cmd/conformance-run`    | `go run ./conformance/cmd/conformance-run testdata/conformance/cases.json` |
| Python  | `bindings/python/conformance/run.py` | `python -m conformance.run testdata/conformance/cases.json`                |
| Node    | `bindings/node/conformance/run.mjs`  | `node bindings/node/conformance/run.mjs testdata/conformance/cases.json`   |
| Rust    | `bindings/rust/conformance/run.rs`   | `cargo run -p soroauth-conformance -- testdata/conformance/cases.json`     |
| JVM     | `bindings/jvm/conformance/Run.java`  | `mvn -pl conformance exec:java`                                            |

The Go runner is the oracle: it uses the native Go library (not the C ABI) and
its output is treated as the expected baseline by every other binding's CI job.
A disagreement between the Go runner and a vector is a bug in the vector or in
the library — the suite surfaces it either way.

## Adding a case

1. Add a row to `cases.json` with a new `id`. Prefer `vector` over `input` where
   an existing vector covers the case.
2. Run the Go oracle against the file to confirm the shape is parseable and the
   expected outputs resolve.
3. Each binding's CI job picks up the new case automatically; no per-binding
   change is required unless the case exercises a new operation.
