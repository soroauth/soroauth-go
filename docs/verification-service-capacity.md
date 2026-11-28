# Verification service capacity planning

<!-- cspell:ignore benchtime -->

Size `POST /verify` by the entry shapes the service handles. A single-account
entry is a useful baseline. Delegate verification also walks the tree and
returns a verdict for each credential node.

## Measured handler cost

Measurements taken on 2026-11-26 at
[`c6c97f11f06d0da5e640dfa6503df6d9b18cc62c`](https://github.com/soroauth/soroauth-go/commit/c6c97f11f06d0da5e640dfa6503df6d9b18cc62c)
with Go 1.26.3 on Windows/amd64, an Intel Core i5-6300U at 2.40 GHz (2 physical
cores, 4 logical processors), and 15.9 GiB RAM.

| Signed fixture             | Median latency | Range of run means | Estimated requests/s per worker |
| -------------------------- | -------------: | -----------------: | ------------------------------: |
| `legacy_single_testnet`    |        1.20 ms |       0.71–1.36 ms |                             836 |
| `delegates_from_legacy`    |        6.03 ms |       4.10–7.60 ms |                             166 |
| `delegates_chain_depth_54` |        2.60 ms |       2.32–3.63 ms |                             384 |

Times are median mean latency across three serial benchmark runs. The requests
per second column is the reciprocal of that latency, rounded. It is a one-worker
estimate for this handler on the measured machine. The benchmark includes JSON
and bounded XDR decoding, offline verification, metrics, and JSON response
encoding. The benchmark uses an in-process HTTP recorder and a discard logger,
so budget separately for network I/O, TLS, log shipping, and queuing at the
edge.

The depth-54 fixture exercises the deepest delegate chain in the set. The
shallower delegate fixture was the slowest of these measured cases. Include both
when testing your workload. Tree depth, credential count, and the mix of
signatures affect the cost. Use the range of run means to account for run-to-run
variation and measure tail latency in a deployment load test.

## Size a deployment

1. Group your expected peak traffic by entry shape. Multiply the requests per
   second in each group by its mean handler time in seconds and sum the
   products. This estimates how many cores the handler would keep busy on
   hardware comparable to the benchmark.
2. Divide by a target utilization to leave room for other service work and
   traffic variation. Start with 60% for an initial estimate, then validate
   under concurrent load on your deployment hardware.
3. Test typical and deep-tree mixes. Include multi-entry envelopes separately if
   callers use them. Observe p95 and p99 latency, CPU, memory, and the
   [limit-rejection metrics](verification-service.md#metrics) before setting a
   production target.

For example, 1,000 legacy requests and 100 depth-54 requests per second, spread
across multiple callers, would use about
`1,000 × 0.00120 + 100 × 0.00260 = 1.46` cores in the handler. At 60% target
utilization, start a load test with three comparable cores
(`1.46 / 0.60 ≈ 2.43`, rounded up). A workload with more of the slower delegate
shape needs more capacity at the same request rate.

## Allow for the configured limits

- The default `RATE_LIMIT_PER_SECOND` is 50 per caller and `RATE_LIMIT_BURST`
  is 100. A caller identity has one quota shared by its requests. Compare each
  caller's sustained and burst traffic with its quota. Requests refused with
  `429` consume neither body decoding nor a handler slot. The quota is per
  caller, so size aggregate admission for all callers.
- The default `MAX_CONCURRENT_REQUESTS` is 64 in-flight handlers. Slow body
  reads hold slots too. Choose a bound against measured service latency and
  memory under concurrent load. `503` responses indicate requests exceeded the
  in-flight bound.
- The default `MAX_BODY_BYTES` caps the JSON request at 1 MiB. The library also
  caps decoded XDR at 1 MiB and XDR nesting at 64 levels. Its delegate tree
  policy limits depth to 54. These bounds restrict accepted input. Validate the
  work your accepted entry shapes require at the intended request mix.

See [service configuration](verification-service.md#configuration) and the
[operator runbook](verification-service-runbook.md) for active limits and
operating signals.

## Repeat the measurements

Run the existing per-arm library benchmark to isolate verification cost from
HTTP handling.

```sh
go test -run '^$' -bench '^BenchmarkVerifyEntry$' -cpu 1 -benchtime 300ms -count 3 -benchmem .
```

Run the service benchmark with the same golden vectors, body limit, and
concurrency bound. The benchmark raises the per-caller rate limit so it measures
admitted requests.

```sh
go test -run '^$' -bench '^BenchmarkVerifyHTTP$' -cpu 1 -benchtime 800ms -count 3 -benchmem ./server
```

Record the date, Git revision, Go version, hardware, fixture names, and measured
statistics when updating the table.
