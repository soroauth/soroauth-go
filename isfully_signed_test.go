package soroauth

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// signedScVal returns a non-empty ScvVec that isSigned treats as signed.
func signedScVal() xdr.ScVal {
	inner := xdr.ScVal{Type: xdr.ScValTypeScvBool, B: boolPtr(true)}
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec(inner)}
}

func boolPtr(b bool) *bool { return &b }

// TestIsFullySigned_SourceAccount asserts that a source-account entry is
// reported as fully signed (it does not require a signature).
func TestIsFullySigned_SourceAccount(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(source_account): unexpected error: %v", err)
	}
	if !ok {
		t.Error("IsFullySigned(source_account) = false; want true (source account does not require a signature)")
	}
}

// TestIsFullySigned_UnsignedLegacy asserts that a legacy address entry with
// no signature returns false.
func TestIsFullySigned_UnsignedLegacy(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(unsigned legacy): unexpected error: %v", err)
	}
	if ok {
		t.Error("IsFullySigned(unsigned legacy) = true; want false")
	}
}

// TestIsFullySigned_SignedLegacy asserts that a legacy address entry with a
// real signature returns true.
func TestIsFullySigned_SignedLegacy(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	entry.Credentials.Address.Signature = signedScVal()
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(signed legacy): unexpected error: %v", err)
	}
	if !ok {
		t.Error("IsFullySigned(signed legacy) = false; want true")
	}
}

// TestIsFullySigned_UnsignedV2 asserts that an address_v2 entry with no
// signature returns false.
func TestIsFullySigned_UnsignedV2(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(unsigned v2): unexpected error: %v", err)
	}
	if ok {
		t.Error("IsFullySigned(unsigned v2) = true; want false")
	}
}

// TestIsFullySigned_SignedV2 asserts that an address_v2 entry with a real
// signature returns true.
func TestIsFullySigned_SignedV2(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	entry.Credentials.AddressV2.Signature = signedScVal()
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(signed v2): unexpected error: %v", err)
	}
	if !ok {
		t.Error("IsFullySigned(signed v2) = false; want true")
	}
}

// TestIsFullySigned_EmptyScvVecIsUnsigned asserts that an empty ScvVec counts
// as unsigned, consistent with Inspect.
func TestIsFullySigned_EmptyScvVecIsUnsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	// testAddressCredentials already uses an empty ScvVec — just confirm.
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(empty ScvVec): unexpected error: %v", err)
	}
	if ok {
		t.Error("IsFullySigned(empty ScvVec) = true; empty ScvVec must count as unsigned")
	}
}

// TestIsFullySigned_DelegatesFullySigned asserts that a delegates arm entry
// where both the top-level account and all delegates are signed returns true.
func TestIsFullySigned_DelegatesFullySigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = signedScVal()
	for i := range entry.Credentials.AddressWithDelegates.Delegates {
		entry.Credentials.AddressWithDelegates.Delegates[i].Signature = signedScVal()
	}
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(fully-signed delegates): unexpected error: %v", err)
	}
	if !ok {
		t.Error("IsFullySigned(fully-signed delegates) = false; want true")
	}
}

// TestIsFullySigned_DelegatesPartiallySignedDelegate asserts that a delegates
// arm entry where the top-level is signed but a delegate is not returns false.
func TestIsFullySigned_DelegatesPartiallySignedDelegate(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	// Sign the top level but leave the delegate's Void signature as-is.
	entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = signedScVal()
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(partially-signed delegates): unexpected error: %v", err)
	}
	if ok {
		t.Error("IsFullySigned(partially-signed delegates) = true; want false when a delegate is unsigned")
	}
}

// TestIsFullySigned_DelegatesTopLevelUnsigned asserts that a delegates arm
// entry where the top-level is unsigned returns false regardless of delegates.
func TestIsFullySigned_DelegatesTopLevelUnsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	for i := range entry.Credentials.AddressWithDelegates.Delegates {
		entry.Credentials.AddressWithDelegates.Delegates[i].Signature = signedScVal()
	}
	ok, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned(unsigned top-level, signed delegate): unexpected error: %v", err)
	}
	if ok {
		t.Error("IsFullySigned(unsigned top-level) = true; want false when top-level is unsigned")
	}
}
