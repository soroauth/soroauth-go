package soroauth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestCheckBatchNoncesPassesOnEmptyBatch verifies that an empty slice does not error.
func TestCheckBatchNoncesPassesOnEmptyBatch(t *testing.T) {
	if err := CheckBatchNonces(nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{}); err != nil {
		t.Fatalf("empty slice: %v", err)
	}
}

// TestCheckBatchNoncesPassesSourceAccountEntries verifies that source-account
// entries, which carry no nonce, are skipped rather than treated as a collision
// on the zero value.
func TestCheckBatchNoncesPassesSourceAccountEntries(t *testing.T) {
	a := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	b := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	if err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{a, b}); err != nil {
		t.Fatalf("two source-account entries: %v", err)
	}
}

// TestCheckBatchNoncesPassesDifferentNonceSameAddress verifies that the same
// address with different nonces is not a collision.
func TestCheckBatchNoncesPassesDifferentNonceSameAddress(t *testing.T) {
	label := "soroauth-nonce-check-same-addr"
	a := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	b := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)
	if err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{a, b}); err != nil {
		t.Fatalf("same address, different nonces: %v", err)
	}
}

// TestCheckBatchNoncesPassesSameNonceDifferentAddress verifies that different
// addresses sharing a nonce is not a collision.
func TestCheckBatchNoncesPassesSameNonceDifferentAddress(t *testing.T) {
	a := entryForSigner(t, "soroauth-nonce-check-addr-a", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 7)
	b := entryForSigner(t, "soroauth-nonce-check-addr-b", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 7)
	if err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{a, b}); err != nil {
		t.Fatalf("different addresses, same nonce: %v", err)
	}
}

// TestCheckBatchNoncesRejectsDuplicateNonceSameAddress verifies that two entries
// for the same address with the same nonce are refused, with the error naming the
// address, both entry indices and the nonce.
func TestCheckBatchNoncesRejectsDuplicateNonceSameAddress(t *testing.T) {
	label := "soroauth-nonce-check-dup"
	a := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	b := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{a, b})
	if !errors.Is(err, ErrNonceDuplicate) {
		t.Fatalf("got %v, want it to wrap ErrNonceDuplicate", err)
	}

	var dup *NonceDuplicateError
	if !errors.As(err, &dup) {
		t.Fatalf("error does not carry a *NonceDuplicateError")
	}
	if dup.FirstIndex != 0 || dup.SecondIndex != 1 {
		t.Errorf("indices: got first=%d second=%d, want first=0 second=1", dup.FirstIndex, dup.SecondIndex)
	}
	if dup.Nonce != 42 {
		t.Errorf("nonce: got %d, want 42", dup.Nonce)
	}
	if dup.Address != testKeypair(t, label).Address() {
		t.Errorf("address: got %q, want %q", dup.Address, testKeypair(t, label).Address())
	}
}

// TestCheckBatchNoncesRejectsLegacyArmDuplicate verifies that the collision
// check works for legacy ADDRESS entries, not just V2.
func TestCheckBatchNoncesRejectsLegacyArmDuplicate(t *testing.T) {
	label := "soroauth-nonce-check-legacy-dup"
	a := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 99)
	b := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 99)

	if err := CheckBatchNonces([]xdr.SorobanAuthorizationEntry{a, b}); !errors.Is(err, ErrNonceDuplicate) {
		t.Fatalf("got %v, want ErrNonceDuplicate for legacy-arm duplicate", err)
	}
}

// TestAuthorizeAllRefusesNonceDuplicate verifies that AuthorizeAll delegates to
// CheckBatchNonces before invoking any signer.
func TestAuthorizeAllRefusesNonceDuplicate(t *testing.T) {
	label := "soroauth-authorizeall-nonce-dup"
	a := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 55)
	b := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 55)

	_, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{a, b},
		[]Signer{NewEd25519Signer(testKeypair(t, label))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrNonceDuplicate) {
		t.Fatalf("got %v, want ErrNonceDuplicate from AuthorizeAll", err)
	}
}
