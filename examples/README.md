# Examples

Three runnable examples, each for a different kind of integration. Pick by what
you are holding: a browser and a passkey, a signer behind a network boundary, or
a process you need to observe.

These are the long-form ones. For short, API-level examples of a single
function, read the Go doc examples in the package itself — `go doc` and
[pkg.go.dev](https://pkg.go.dev/github.com/soroauth/soroauth-go) show them
beside the function they illustrate, and `go test` verifies them, so they cannot
drift from the code.

| Example                             | Shows                                                                   | Needs                         |
| ----------------------------------- | ----------------------------------------------------------------------- | ----------------------------- |
| [browser-passkey](browser-passkey/) | Signing in a browser with a WebAuthn passkey, via the WASM signing core | A browser, a passkey, testnet |
| [remote-signer](remote-signer/)     | A signer behind HTTP, where the key never reaches the calling process   | Go, loopback only             |
| [opentelemetry](opentelemetry/)     | The whole sign-and-submit flow as one OpenTelemetry trace               | Go, testnet                   |

## browser-passkey

A self-contained page that derives the signing payload **in the browser** with
`@soroauth/wasm`, signs it with a WebAuthn passkey, and submits the transaction
to testnet.

The point of deriving the payload in the browser rather than on a server is that
nothing has to be trusted to tell the page what it is signing. It computes the
payload from the entry itself.

## remote-signer

Runs the reference HTTP server and its client signer together on loopback:

```sh
go run ./examples/remote-signer
```

This is the shape to copy if the key lives somewhere the calling process cannot
reach — an HSM host, a separate service, another machine. The protocol sends the
**preimage** alongside the payload, so the remote end can inspect what it is
being asked to approve rather than blind-signing a digest. That is the whole
reason it is not just "POST a hash".

Loopback only, and unauthenticated. A real deployment needs transport security
and authentication; the example is about the signing protocol, not the
transport.

## opentelemetry

Runs `rpcflow.SignAndSubmit` on testnet as one OpenTelemetry trace: record pass,
signing, enforcing pass, submission and polling, one span each, with the
resource-fee difference between the two passes as an attribute.

```sh
cd examples/opentelemetry && go run ./cmd/trace-transfer
```

It is its own Go module, so OpenTelemetry never becomes a dependency of the
library. The README there shows a real captured trace, and a test asserts that
no span carries a secret, an entry or a signature. The narrower `Hook` seam,
which observes the phases inside one `AuthorizeEntry` call with only the
standard library, is in the same package.

## What none of them do

None of these is a transaction builder, and none wraps `txnbuild` or
`clients/rpcclient`. soroauth signs authorization entries; assembling and
submitting a transaction stays the caller's job, using the Go SDK directly. The
examples use the SDK that way rather than hiding it, so what you copy is what
you would have written.
