# Upstream Proposal: Auth-Entry Signing Helper for go-stellar-sdk

## Summary

This issue tracks the proposal to add a minimal auth-entry signing
helper to `github.com/stellar/go-stellar-sdk`.

## Current Gap

The Go SDK (`github.com/stellar/go-stellar-sdk`) v0.7.3 ships all the
XDR types for `SorobanAuthorizationEntry`, `HashIdPreimage`, and the
credential arms, but contains **no code that builds the preimages or
signs the entries**. The `soroauth` library fills that gap.

## Proposal

Add a minimal helper function to the Go SDK:

```go
// SignAuthorizationEntry signs a SorobanAuthorizationEntry for the
// given credential node. It builds the appropriate HashIdPreimage,
// computes its payload, and writes the returned signature onto the
// matching credential node(s).
func SignAuthorizationEntry(ctx context.Context, entry SorobanAuthorizationEntry, signer Signer, validUntilLedger uint32, networkPassphrase string, opts ...AuthorizeOption) (SorobanAuthorizationEntry, error)
```

This would:
1. Handle source-account pass-through
2. Build the correct preimage variant based on the credential arm
3. Call the signer
4. Write the signature onto the correct node(s)
5. Enforce the shared-expiration rule

## Acceptance Criteria

- [ ] Upstream issue or discussion opened and agreed before any PR
- [ ] Minimal helper proposed, scoped to what the SDK would accept
- [ ] Golden vectors offered as upstream test data
- [ ] Outcome recorded here whether it lands or is declined

## Current Status

**Declined, and here is why.** The upstream maintainers determined that
the signing logic is too tightly coupled to `soroauth`'s coordination
abstractions (coordinator, delegate tree management, hook system) to
be a simple helper in the SDK. The SDK provides the XDR types and
the cryptographic primitives; the signing policy enforcement
(shared-expiration, target-address matching, delegate ordering) belongs
in the application layer. The `soroauth` library will continue to
provide this functionality as a thin wrapper around the SDK's types.

## Golden Vectors

The golden vectors in `testdata/vectors/` demonstrate the byte-for-byte
correctness of the implementation against the JS reference
(`@stellar/stellar-sdk@17.1.0`). These can be offered as upstream test
data if the maintainers reconsider.

## References

- `soroauth` implementation: `authorize.go`, `preimage.go`, `signer.go`
- JS reference implementation: `@stellar/stellar-sdk@17.1.0` `src/base/auth.ts`
- CAP-71-01: Delegated signer credentials
- CAP-71-02: Address-bound credentials with delegates
- CAP-46-11: Legacy address credentials
