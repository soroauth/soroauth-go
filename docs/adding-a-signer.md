# Adding a signer

This guide is for a signer adapter that belongs in the soroauth repository. A
signer is a security boundary: the adapter must preserve the `Signer` contract
without exposing key material or changing the authorization-entry wire shape.

## Choose the module boundary first

Keep a signer in the root module when it only needs dependencies already used by
the library. Put a cloud or hardware integration in its own submodule when its
SDK would add a large or operationally specific dependency to ordinary users.
Follow the existing layout:

```text
signer.go                 # shared Signer contract and small in-process signers
signertest/               # reusable conformance checks
adapters/awskms/          # provider-specific adapter and its go.mod
adapters/gcpkms/          # provider-specific adapter and its go.mod
```

An adapter submodule has its own `go.mod`, names the root module at the version
it was tested against, and keeps provider credentials out of examples and test
fixtures. Update the root module's documentation and `docs/signers.md` with the
adapter's threat model and evidence.

## Implement the contract

Implement `soroauth.Signer` exactly: `Address()` is stable, `Sign(ctx, payload)`
honours cancellation, signs the supplied bytes without mutating them, and
returns no usable partial value when signing fails. Return the provider error
with context, but do not wrap it in a way that loses `errors.Is` or `errors.As`.
A signer must never log seeds, private-key bytes, KMS request payloads, or
complete authorization entries.

Be careful with typed nils. A non-nil interface can contain a nil pointer, so
constructor validation must reject both a nil interface and a typed-nil client
before the first network call. Validate required key names, projects, regions,
and endpoints at construction time. Treat an empty provider response as an error
rather than manufacturing a signature.

Run the shared conformance suite from the adapter's tests:

```go
func TestSignerContract(t *testing.T) {
    signertest.Run(t, func(t *testing.T) soroauth.Signer {
        t.Helper()
        return newTestSigner(t)
    })
}
```

The suite checks address stability, context cancellation without a signing
side-effect, an untouched preimage, failure atomicity, and determinism only
where the signer declares it. Add provider-specific tests for malformed
responses, context propagation, key-selection errors, signature conversion, and
network failures. Tests must use fake clients; they must not require cloud
credentials.

## GCP KMS example

The GCP adapter is the reference for a remote signer. It sends the digest to
Cloud KMS, converts the returned DER signature to the fixed-width Stellar
signature form, and verifies the result before returning it. A caller wires it
with a provider client and a versioned key name, then passes it anywhere a
`Signer` is accepted:

```go
client, err := kms.NewKeyManagementClient(ctx)
if err != nil { return err }
defer client.Close()

signer, err := gcpkms.NewSigner(client, gcpkms.Config{
    ResourceName: "projects/my-project/locations/global/keyRings/app/cryptoKeys/soroauth/cryptoKeyVersions/1",
})
if err != nil { return err }

signed, err := signer.Sign(ctx, payload)
```

The resource name identifies a key version, not a secret. IAM should grant only
the asymmetric-sign permission required by the service. Rotate by creating a new
key version and changing configuration; do not put private key material in the
application or in a test fixture. The AWS and GCP adapters use the same contract
but are not interchangeable in deployment or IAM policy.

## Documentation checklist

Before opening a PR, update `docs/signers.md` with the signer’s custody model,
the exact evidence available, and the caveats that remain. Include the adapter
in the docs index, state whether it has live-network evidence, and add a
shortened example that uses placeholders rather than real credentials.
