package soroauth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// rotatingFakeSigner is a fake KMS whose key version changes after the first
// call. It wraps an Ed25519Signer so its signatures are valid; KeyVersion
// returns "v1" for the first Sign call and "v2" for every call thereafter.
type rotatingFakeSigner struct {
	inner   Signer
	calls   int
	version string
}

func newRotatingFakeSigner(inner Signer) *rotatingFakeSigner {
	return &rotatingFakeSigner{inner: inner}
}

func (s *rotatingFakeSigner) Address() string { return s.inner.Address() }

func (s *rotatingFakeSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	s.calls++
	if s.calls == 1 {
		s.version = "v1"
	} else {
		s.version = "v2"
	}
	return s.inner.Sign(ctx, preimage, payload)
}

func (s *rotatingFakeSigner) KeyVersion() string { return s.version }

// stableFakeSigner always reports the same version.
type stableFakeSigner struct {
	inner   Signer
	version string
}

func newStableFakeSigner(inner Signer, version string) *stableFakeSigner {
	return &stableFakeSigner{inner: inner, version: version}
}

func (s *stableFakeSigner) Address() string { return s.inner.Address() }

func (s *stableFakeSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	return s.inner.Sign(ctx, preimage, payload)
}

func (s *stableFakeSigner) KeyVersion() string { return s.version }

// TestAuthorizeAllRotationDetected verifies that AuthorizeAll refuses a batch
// when a VersionedSigner reports two different key versions for two entries
// for the same address.
func TestAuthorizeAllRotationDetected(t *testing.T) {
	label := "soroauth-rotation-detect"
	kp := testKeypair(t, label)
	inner := NewEd25519Signer(kp)
	rotator := newRotatingFakeSigner(inner)

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 101),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 102),
	}

	_, err := AuthorizeAll(context.Background(), entries, []Signer{rotator},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("expected rotation error, got nil")
	}
	if !errors.Is(err, ErrSignerRotation) {
		t.Errorf("errors.Is ErrSignerRotation: got %v, want match", err)
	}
	var rotErr *SignerRotationError
	if !errors.As(err, &rotErr) {
		t.Fatalf("errors.As *SignerRotationError: not found in %v", err)
	}
	if rotErr.Address != kp.Address() {
		t.Errorf("Address: got %q, want %q", rotErr.Address, kp.Address())
	}
	if rotErr.FirstEntry != 0 {
		t.Errorf("FirstEntry: got %d, want 0", rotErr.FirstEntry)
	}
	if rotErr.SecondEntry != 1 {
		t.Errorf("SecondEntry: got %d, want 1", rotErr.SecondEntry)
	}
	if rotErr.FirstVersion != "v1" {
		t.Errorf("FirstVersion: got %q, want v1", rotErr.FirstVersion)
	}
	if rotErr.SecondVersion != "v2" {
		t.Errorf("SecondVersion: got %q, want v2", rotErr.SecondVersion)
	}
}

// TestAuthorizeAllStableVersionPasses verifies that a VersionedSigner that
// reports the same key version for every entry in the batch does not cause
// an error.
func TestAuthorizeAllStableVersionPasses(t *testing.T) {
	label := "soroauth-rotation-stable"
	inner := NewEd25519Signer(testKeypair(t, label))
	stable := newStableFakeSigner(inner, "prod-key-v3")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 201),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 202),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 203),
	}

	_, err := AuthorizeAll(context.Background(), entries, []Signer{stable},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("stable versioned signer: unexpected error: %v", err)
	}
}

// TestAuthorizeAllNonVersionedSignerIgnored verifies that a plain Signer (one
// that does not implement VersionedSigner) passes through without any rotation
// check.
func TestAuthorizeAllNonVersionedSignerIgnored(t *testing.T) {
	label := "soroauth-rotation-plain"
	plain := NewEd25519Signer(testKeypair(t, label))

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 301),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 302),
	}

	_, err := AuthorizeAll(context.Background(), entries, []Signer{plain},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("plain signer: unexpected error: %v", err)
	}
}

// TestAuthorizeAllRotationTwoDifferentAddresses verifies that two different
// VersionedSigners with different key versions for two different addresses do
// not trigger a rotation error (each address is tracked independently).
func TestAuthorizeAllRotationTwoDifferentAddresses(t *testing.T) {
	labelA := "soroauth-rotation-addr-a"
	labelB := "soroauth-rotation-addr-b"
	signerA := newStableFakeSigner(NewEd25519Signer(testKeypair(t, labelA)), "v-a")
	signerB := newStableFakeSigner(NewEd25519Signer(testKeypair(t, labelB)), "v-b")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, labelA, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 401),
		entryForSigner(t, labelB, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 402),
	}

	_, err := AuthorizeAll(context.Background(), entries, []Signer{signerA, signerB},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("two different addresses with different versions: unexpected error: %v", err)
	}
}
