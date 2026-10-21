# Performance characteristics

**Machine:** measured on `INTEL XEON PLATINUM 8573C (2 vCPU), linux/amd64` **Go
versions:** `go1.25.4` (the toolchain CI installs, from the `toolchain` line in
`go.mod`) and `go1.27.1`, taking the higher of the two where they differ (the
delegates paths differ by up to 7 allocs between the toolchains). **Benchmark
tool:**
`go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out && go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json`

## Signing path

All signing-path budgets carry ~40% headroom over the measured maximum, so a Go
minor bump does not flake CI. Baselines were re-measured on
`INTEL XEON PLATINUM 8573C (2 vCPU), linux/amd64, go1.27.1`.

### Per-operation, per-arm budgets

| Benchmark name                                | Operation    | Arm                                    | allocs/op | B/op   |
| --------------------------------------------- | ------------ | -------------------------------------- | --------- | ------ |
| `BenchmarkPreimage`                           | signing      | preimage                               | 28        | 1490   |
| `BenchmarkPayload`                            | signing      | payload                                | 10        | 760    |
| `BenchmarkAuthorizeEntry/legacy`              | signing      | legacy                                 | 100       | 6200   |
| `BenchmarkAuthorizeEntry/v2`                  | signing      | v2                                     | 105       | 6400   |
| `BenchmarkAuthorizeEntry/delegates`           | signing      | delegates (flat, 3 nodes)              | 140       | 9300   |
| `BenchmarkAuthorizeEntry/delegates_deep`      | signing      | delegates (chain, depth 8)             | 225       | 15200  |
| `BenchmarkDelegateTree/nodes_1`               | signing      | delegates_tree (1 node)                | 120       | 7450   |
| `BenchmarkDelegateTree/nodes_4`               | signing      | delegates_tree (4 nodes)               | 160       | 10400  |
| `BenchmarkDelegateTree/nodes_16`              | signing      | delegates_tree (16 nodes)              | 330       | 26300  |
| `BenchmarkDelegateTree/nodes_63`              | signing      | delegates_tree (63 nodes)              | 990       | 157500 |
| `BenchmarkVerifyEntry/legacy`                 | verification | legacy                                 | 52        | 2800   |
| `BenchmarkVerifyEntry/v2`                     | verification | v2                                     | 56        | 3100   |
| `BenchmarkVerifyEntry/delegates`              | verification | delegates (3 nodes)                    | 70        | 3850   |
| `BenchmarkDiffEntries/legacy`                 | diffing      | legacy                                 | 70        | 5450   |
| `BenchmarkDiffEntries/v2`                     | diffing      | v2                                     | 70        | 5450   |
| `BenchmarkDiffEntries/delegates`              | diffing      | delegates (3 nodes)                    | 104       | 9200   |
| `BenchmarkXDRCopy/entry`                      | copy         | entry                                  | 23        | 1250   |
| `BenchmarkXDRCopy/preimage`                   | copy         | preimage                               | 21        | 1050   |
| `BenchmarkAuthorizeAll`                       | signing      | all (12-entry, 4-signer realistic mix) | 1900      | 109000 |
| `BenchmarkAuthorizeBatch`                     | signing      | batch (bounded concurrency, same mix)  | 3200      | 190000 |
| `BenchmarkAuthorizeInvocation`                | signing      | invocation (from-scratch V2)           | 112       | 7000   |
| `BenchmarkParseAddress`                       | address      | parse                                  | 6         | 176    |
| `BenchmarkFormatAddress`                      | address      | format                                 | 2         | 95     |
| `BenchmarkDecodeAuthorizationEntry`           | decode       | authorization_entry                    | 30        | 5000   |
| `BenchmarkThresholdSigner/threshold-sign`     | signing      | threshold-sign                         | 6         | 325    |
| `BenchmarkCoordinatorState/coordinator-state` | coordination | state                                  | 16        | 760    |

### Delegate tree scaling

The delegate tree benchmarks (`BenchmarkDelegateTree/nodes_{1,4,16,63}`) expose
the per-node allocation cost. The jump from 16 to 63 nodes shows super-linear
growth:

| Nodes | allocs/op | B/op   | vs-nodes-16               |
| ----- | --------- | ------ | ------------------------- |
| 1     | 120       | 7450   | —                         |
| 4     | 160       | 10400  | +33% allocs, +39% bytes   |
| 16    | 330       | 26300  | +106% allocs, +153% bytes |
| 63    | 990       | 157500 | +200% allocs, +500% bytes |

The `allocs/op` count roughly triples from 16 to 63 nodes, and `B/op` grows
nearly 6x. This is the one super-linear risk in the signing path — the recursive
walk and deep copy scale with delegate count. The budgets carry ~40% headroom so
that a Go minor version change does not cause flakes, but a significant increase
in delegate tree depth should be evaluated carefully.

### Cost relative to signer latency

The library's allocation cost is deterministic and relatively small compared to
what a remote signer introduces. Consider:

- `BenchmarkPreimage` / `BenchmarkPayload`: ~1500 B allocated, dominated by XDR
  marshal and SHA-256. These are one-shot costs with no network.
- `BenchmarkAuthorizeEntry/*`: 100–225 allocs/op. The ed25519 signing itself
  dominates the runtime; the allocation numbers above are per-iteration
  overhead.
- `BenchmarkAuthorizeAll` (12 entries, 4 signers): ~1900 allocs/op, ~109 KB/op.
  The cost grows linearly with the number of entries and signers.
- `BenchmarkDelegateTree/nodes_63`: 990 allocs/op, ~157 KB/op. This is the
  heaviest library-only cost, but it is still a single-process operation.

**Key point:** A remote signer's latency (RPC round-trip + ed25519 signing time)
dwarfs the library's allocation cost. A single testnet RPC call typically costs
10–100 ms, while the entire `AuthorizeEntry` path on a local machine takes well
under 1 ms. When signing many entries per transaction, the library's cost scales
with entry count, but the signer's cost dominates per-entry latency.

**How to reproduce:** Run the benchmarks locally:

```sh
go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
```

The first command writes the raw benchmark output; the second validates every
budget against the measured values and exits 0 if all budgets are met (or 1 if
any budget is exceeded, printing the benchmark path, the measured value, and the
baseline). Budgets carry ~40% headroom; an intentional increase requires raising
the budget in the same commit with the measurement in the commit body and a
statement of which function got more expensive and why.

## RPC and network round-trip cost

The library itself makes no RPC calls during signing — it operates on in-memory
XDR. The dominant cost in a real transaction is the RPC round-trip for
`simulateTransaction` (recording pass) and the on-chain fee market. These are
out of the library's control and are not reflected in the benchmarks above.

**How to measure:** Use the e2e test harness (`make e2e`) which runs two-pass
simulation on testnet and reports the ledger, transaction hash, and observed
credential arm. The RPC latency can be approximated by probing
`https://soroban-testnet.stellar.org` with `curl -w "%{time_total}"`.

## Summary of cost drivers

| Cost domain                  | Dominant operation                                         | Relative cost                            |
| ---------------------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Library allocations          | `BenchmarkXDRCopy/entry`, `BenchmarkDelegateTree/nodes_63` | Deterministic, ~40% headroom in CI       |
| Library SHA-256 + XDR        | `BenchmarkPreimage`, `BenchmarkPayload`                    | Small, single-shot                       |
| ed25519 signing (in-process) | `BenchmarkAuthorizeEntry/*`                                | Dominates runtime but still < 1 ms/local |
| RPC round-trip               | `simulateTransaction` (e2e)                                | 10–100 ms per call, dwarfs library cost  |
| Delegate tree walk           | `BenchmarkDelegateTree/nodes_63`                           | Super-linear: 990 allocs/op at 63 nodes  |
| Batch signing                | `BenchmarkAuthorizeAll`                                    | Linear in entry count and signer count   |

## Reproduction recap

Every number in this document is reproduced by the two-command sequence above,
run on the machine named. The budgets in `testdata/bench/budgets.json` are the
committed baselines; `scripts/checkbench` gates CI on allocs/op and B/op. If a
budget fails, reproduce locally with the same two commands, identify the
regressed function with `go tool pprof`, and raise the budget in the same commit
with the measurement and explanation.
