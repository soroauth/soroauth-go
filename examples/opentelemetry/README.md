# OpenTelemetry: the whole flow as one trace

`rpcflow.SignAndSubmit` makes four kinds of call to the network and one to your
signer: the record pass, signing, the enforcing pass, submission and polling.
This example runs that flow as **one OpenTelemetry trace**, one span per stage,
so the latency and the two-pass requirement are visible rather than described.

It is its own Go module. OpenTelemetry is a dependency of this example only and
never of the root `github.com/soroauth/soroauth-go` module.

## Run it on testnet

```sh
cd examples/opentelemetry
go run ./cmd/trace-transfer          # tree view
go run ./cmd/trace-transfer -json    # tree view plus every span as JSON
```

It generates three accounts (payer, sender, recipient), funds them from
friendbot, and has the payer submit a 1 XLM native-SAC `transfer` from the
sender to the recipient. The payer and the sender are different accounts on
purpose: that is what makes the sender's authorization an address credential,
and so what makes both simulation passes necessary.

No key is read from the environment, written to disk or printed. The program
refuses to run on any network whose passphrase is not testnet's.

| Variable                 | Default                                                      |
| ------------------------ | ------------------------------------------------------------ |
| `SOROAUTH_RPC_URL`       | `https://soroban-testnet.stellar.org`                        |
| `SOROAUTH_FRIENDBOT_URL` | the friendbot the RPC advertises, else the testnet friendbot |

To send the spans to a real backend, replace the `stdouttrace` exporter in
`cmd/trace-transfer/main.go` with your own (OTLP, Jaeger, a vendor SDK): the
spans and attributes are the same whatever exports them.

## A captured trace

A real run against testnet on 2026-11-23 (RPC reporting protocol 30):

<!-- cspell:disable -->

```text
soroauth.sign_and_submit  4.119s  simulate.record_min_resource_fee=130770  simulate.enforce_min_resource_fee=15365  simulate.resource_fee_delta=-115405  tx.hash=2e8e779073f23221f3444a400187edb03d218b4dfb4e231e847127706bcf93d1  tx.status=SUCCESS  tx.ledger=5879165  credential_arm=address
├─ soroauth.simulate.record  269ms  simulate.auth_mode=record  simulate.min_resource_fee=130770  simulate.auth_entries=1  ledger.latest=5879164
├─ soroauth.latest_ledger  431ms  ledger.latest=5879164
├─ soroauth.sign  1ms  signer.address=GDOQ7VRQ7FLLL7M6JAGJ5M5XCAXDRULC5AOS3YOIW5KGJK7MTXJJ7NTU  preimage.type=EnvelopeTypeEnvelopeTypeSorobanAuthorization
├─ soroauth.simulate.enforce  257ms  simulate.auth_mode=enforce  simulate.min_resource_fee=15365  simulate.auth_entries=1  ledger.latest=5879164  simulate.record_min_resource_fee=130770  simulate.resource_fee_delta=-115405
├─ soroauth.send  254ms  tx.hash=2e8e779073f23221f3444a400187edb03d218b4dfb4e231e847127706bcf93d1  tx.status=PENDING
└─ soroauth.poll  2.907s  tx.hash=2e8e779073f23221f3444a400187edb03d218b4dfb4e231e847127706bcf93d1  tx.status=SUCCESS  tx.ledger=5879165
```

<!-- cspell:enable -->

[The transaction on stellar.expert](https://stellar.expert/explorer/testnet/tx/2e8e779073f23221f3444a400187edb03d218b4dfb4e231e847127706bcf93d1)

What it shows:

- **Signing is not where the time goes.** It took 1 ms. The two simulations and
  the submission took about a quarter of a second each, and polling for a
  terminal status took almost three of the four seconds.
- **The two passes priced the transaction differently.** The record pass
  reported a minimum resource fee of 130770 stroops and the enforcing pass, run
  over the signed entries, 15365, so `resource_fee_delta` is -115405. The
  difference is the reason the second pass exists: the transaction that is
  submitted is priced from the enforcing pass, the one simulated with the
  entries it actually carries. Here a record-pass price would have overpaid; the
  sign of the delta is whatever the network reports, and the attribute is there
  so you can see it rather than assume it.
- **`latest_ledger`** appears because the run left `ValidUntilLedger` at zero,
  so rpcflow read the current ledger to set a default expiration.
- **`credential_arm=address`** is read back off the submitted envelope, not
  assumed. This run recorded the legacy `SOROBAN_CREDENTIALS_ADDRESS` arm, and
  `preimage.type` agrees: `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION`.

## How it is wired

`SignAndSubmit` in [`flow.go`](flow.go) does not fork rpcflow. `rpcflow.Client`
and `soroauth.Signer` are both interfaces, so it wraps the RPC client and each
signer in a decorator that opens a child span per call, then calls
`rpcflow.SignAndSubmit` unchanged. The trace therefore shows the stages exactly
as rpcflow runs them.

rpcflow has no hook of its own, and `soroauth.Hook` (see [`hook.go`](hook.go))
only covers the phases inside one `AuthorizeEntry` call, so it cannot see the
simulations, the submission or the poll. Wrapping the two interfaces is what
reaches the whole flow.

| Span                        | Stage                                                 |
| --------------------------- | ----------------------------------------------------- |
| `soroauth.sign_and_submit`  | the root; carries the fees, the delta and the outcome |
| `soroauth.simulate.record`  | record pass                                           |
| `soroauth.latest_ledger`    | only when `ValidUntilLedger` is zero                  |
| `soroauth.sign`             | one per signed credential node                        |
| `soroauth.simulate.enforce` | enforcing pass; carries both fees and the delta       |
| `soroauth.send`             | `sendTransaction`                                     |
| `soroauth.poll`             | polling `getTransaction` to a terminal status         |

## What never goes into a span

No span carries a secret, an authorization entry, an envelope, a preimage, a
payload or a signature. Attributes are addresses, counts, fees, ledgers,
statuses and the transaction hash. A failed call records only its Go error type
and a fixed description, never the error text, because an RPC or host message is
not under this example's control.

`TestNoSpanCarriesASecretAnEntryOrASignature` in [`flow_test.go`](flow_test.go)
enforces this. It runs the flow offline, then scans every exported span name,
status, attribute and event for the seeds, the recorded entry, the signed
entries, the submitted envelope and every signature in base64 and hex.

```sh
go test -race ./...
```
