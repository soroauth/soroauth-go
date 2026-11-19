package soroauth

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ShapeVerifier checks a signature value against a 32-byte payload and reports
// whether it verifies. An error means the check itself failed (a timeout, a
// malformed value inside a matched shape); it is not the channel for "did not
// verify", which is a false return with a nil error.
type ShapeVerifier func(ctx context.Context, signature xdr.ScVal, payload [32]byte) (verified bool, err error)

// ShapeMatcher decides whether a signature value belongs to this shape's
// domain. It must be pure and fast: it is called on every signed node of every
// entry the registry verifies. A true return means the paired ShapeVerifier
// will be called; a false return means this shape is skipped and the next one
// is tried.
type ShapeMatcher func(signature xdr.ScVal) bool

// ShapeRegistration pairs a matcher with a verifier under a name.
//
// Trust boundary: a registered verifier is the caller's claim about a
// signature shape, not the library's. The verification report makes this
// visible: a node verified through a registered shape carries a reason that
// names the registration, so a reader can tell a built-in verdict from a
// caller-supplied one.
type ShapeRegistration struct {
	// Name identifies this registration in reports. It should be short and
	// stable, such as "ed25519" or "secp256r1-webauthn".
	Name string

	// Match returns true when the signature value is in this shape's domain.
	Match ShapeMatcher

	// Verify checks the signature against the payload. It is called only when
	// Match returned true. A false return with a nil error means the signature
	// is well-formed for this shape but does not verify (VerdictInvalid). A
	// true return means verified. An error means the check itself failed.
	Verify ShapeVerifier
}

// ShapeRegistry holds an ordered list of signature-shape registrations for
// offline verification. It is immutable after construction: the shapes slice
// is copied in and never modified, so concurrent use is safe without a mutex.
//
// The first registration whose Match returns true for a node's signature wins.
// If no registration matches, the node is reported VerdictCannotCheck. The
// built-in ed25519 shape is registered through the same mechanism as any
// caller-supplied shape; DefaultShapeRegistry returns a registry that contains
// only it.
type ShapeRegistry struct {
	shapes []ShapeRegistration
}

// NewShapeRegistry builds a registry from the given registrations. The order
// matters: the first match wins. The slice is copied, so the caller may reuse
// or modify the original after this call returns.
func NewShapeRegistry(shapes ...ShapeRegistration) *ShapeRegistry {
	copied := make([]ShapeRegistration, len(shapes))
	copy(copied, shapes)
	return &ShapeRegistry{shapes: copied}
}

// DefaultShapeRegistry returns a registry containing only the built-in
// classic-account ed25519 shape, the same one the standalone VerifyEntry uses.
func DefaultShapeRegistry() *ShapeRegistry {
	return NewShapeRegistry(Ed25519ShapeRegistration())
}

// Ed25519ShapeRegistration returns the built-in classic-account ed25519
// shape as a ShapeRegistration, so callers who add their own shapes can
// include the built-in one at whatever position they choose.
func Ed25519ShapeRegistration() ShapeRegistration {
	return ShapeRegistration{
		Name: "ed25519",
		Match: func(sig xdr.ScVal) bool {
			_, _, err := parseAccountSignature(sig)
			return err == nil
		},
		Verify: func(_ context.Context, sig xdr.ScVal, payload [32]byte) (bool, error) {
			publicKey, rawSig, err := parseAccountSignature(sig)
			if err != nil {
				return false, err
			}
			return ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], rawSig), nil
		},
	}
}

// VerifyEntry checks an authorization entry's signatures using this registry's
// shapes. It behaves identically to the standalone VerifyEntry except that
// nodes whose signatures match a registered shape are checked through it
// rather than falling through to VerdictCannotCheck.
func (r *ShapeRegistry) VerifyEntry(entry xdr.SorobanAuthorizationEntry, networkPassphrase string) (VerificationReport, error) {
	return r.VerifyEntryContext(context.Background(), entry, networkPassphrase)
}

// VerifyEntryContext checks an authorization entry's signatures with a context.
func (r *ShapeRegistry) VerifyEntryContext(ctx context.Context, entry xdr.SorobanAuthorizationEntry, networkPassphrase string) (VerificationReport, error) {
	if err := ctx.Err(); err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return VerificationReport{
			CredentialType: CredentialTypeSourceAccount,
			Note:           "source-account credentials carry no signature payload of their own; the transaction envelope's signature covers them, so there is nothing here to verify",
		}, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		// Handled below.

	default:
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", ErrUnsupportedCredentials)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	address, err := FormatAddress(credentials.Address)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	expiration := uint32(credentials.SignatureExpirationLedger)
	preimage, err := Preimage(entry, expiration, networkPassphrase)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry for %s: %w", address, err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry for %s: %w", address, err)
	}

	nodes, err := credentialNodes(&entry)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	report := VerificationReport{
		CredentialType:   credentialTypeName(entry.Credentials.Type),
		AddressBound:     entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		Address:          address,
		ValidUntilLedger: expiration,
		Nodes:            make([]NodeVerdict, 0, len(nodes)),
	}

	for _, node := range nodes {
		verdict, err := r.verifyNodeWithRegistry(ctx, *node.signature, node.encoded, payload)
		if err != nil {
			return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
		}
		report.Nodes = append(report.Nodes, verdict)
	}

	return report, nil
}

// verifyNodeWithRegistry decides one credential node's verdict, consulting
// registered shapes when the built-in checks do not apply.
func (r *ShapeRegistry) verifyNodeWithRegistry(ctx context.Context, signature xdr.ScVal, encoded []byte, payload [32]byte) (NodeVerdict, error) {
	var address xdr.ScAddress
	if err := address.UnmarshalBinary(encoded); err != nil {
		return NodeVerdict{}, fmt.Errorf("decoding credential node address: %w", err)
	}
	formatted, err := FormatAddress(address)
	if err != nil {
		return NodeVerdict{}, err
	}

	verdict := NodeVerdict{Address: formatted}

	if address.Type != xdr.ScAddressTypeScAddressTypeAccount {
		verdict.Verdict = VerdictCannotCheck
		verdict.Reason = contractAccountNote
		return verdict, nil
	}

	if !isSigned(signature) {
		verdict.Verdict = VerdictUnsigned
		verdict.Reason = "the node carries no signature (Void or an empty vector)"
		return verdict, nil
	}

	for _, shape := range r.shapes {
		if !shape.Match(signature) {
			continue
		}

		verified, err := shape.Verify(ctx, signature, payload)
		if err != nil {
			verdict.Verdict = VerdictCannotCheck
			verdict.Reason = fmt.Sprintf("registered shape %q returned an error: %v", shape.Name, err)
			return verdict, nil
		}
		if verified {
			if shape.Name == "ed25519" {
				verdict.Verdict = VerdictVerified
			} else {
				verdict.Verdict = VerdictVerified
				verdict.Reason = fmt.Sprintf("verified by registered shape %q (the caller's claim, not the library's)", shape.Name)
			}
			return verdict, nil
		}
		verdict.Verdict = VerdictInvalid
		verdict.Reason = fmt.Sprintf("the signature matched registered shape %q but did not verify over the payload", shape.Name)
		return verdict, nil
	}

	verdict.Verdict = VerdictCannotCheck
	verdict.Reason = fmt.Sprintf("%s (%s)", shapeNote, describeUnmatchedShape(signature))
	return verdict, nil
}

func describeUnmatchedShape(sig xdr.ScVal) string {
	shape := DescribeSignature(sig)
	var parts []string
	if shape.Type != "" {
		parts = append(parts, string(shape.Type))
	}
	if shape.Description != "" {
		parts = append(parts, shape.Description)
	}
	if len(parts) == 0 {
		return "unknown shape"
	}
	return strings.Join(parts, ": ")
}
