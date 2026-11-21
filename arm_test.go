package soroauth

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestCredentialArmString asserts that String returns the same identifiers
// as EntryInfo.CredentialType so the two cannot disagree.
func TestCredentialArmString(t *testing.T) {
	cases := []struct {
		arm      CredentialArm
		wantType string
	}{
		{ArmSourceAccount, CredentialTypeSourceAccount},
		{ArmAddress, CredentialTypeAddress},
		{ArmAddressV2, CredentialTypeAddressV2},
		{ArmAddressWithDelegates, CredentialTypeAddressWithDelegates},
	}
	for _, tc := range cases {
		if got := tc.arm.String(); got != tc.wantType {
			t.Errorf("CredentialArm(%q).String() = %q, want %q", tc.arm, got, tc.wantType)
		}
	}
}

// TestCredentialArmStringUnknownIsMarked asserts that an unknown arm returns a
// clearly-marked value and not an empty string.
func TestCredentialArmStringUnknownIsMarked(t *testing.T) {
	unknown := CredentialArm("not_a_real_arm")
	got := unknown.String()
	if got == "" {
		t.Error("unknown CredentialArm.String() returned an empty string; want a clearly-marked unknown value")
	}
	if got == string(unknown) {
		t.Errorf("unknown CredentialArm.String() = %q is indistinguishable from the raw value; want a marked unknown", got)
	}
}

// TestCredentialArmStringMatchesInspectCredentialType asserts the String method
// and the inspect report use the same values by cross-checking every arm's
// CredentialTypeName against its String output.
func TestCredentialArmStringMatchesInspectCredentialType(t *testing.T) {
	for arm, behavior := range armBehaviors {
		if arm.String() != behavior.CredentialTypeName() {
			t.Errorf("CredentialArm(%q).String() = %q but ArmBehavior.CredentialTypeName() = %q; they must match",
				arm, arm.String(), behavior.CredentialTypeName())
		}
	}
}

// TestAuthorizedFunctionTypeRoundTrip verifies that every XDR function type
// converts to and from AuthorizedFunctionType without loss.
func TestAuthorizedFunctionTypeRoundTrip(t *testing.T) {
	xdrTypes := []xdr.SorobanAuthorizedFunctionType{
		xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
		xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
		xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn,
	}
	for _, xdrType := range xdrTypes {
		ft, err := AuthorizedFunctionTypeFromXDR(xdrType)
		if err != nil {
			t.Fatalf("AuthorizedFunctionTypeFromXDR(%v) error: %v", xdrType, err)
		}
		got, err := ft.ToXDR()
		if err != nil {
			t.Fatalf("AuthorizedFunctionType(%q).ToXDR() error: %v", ft, err)
		}
		if got != xdrType {
			t.Errorf("round-trip %v → %q → %v; want the original value", xdrType, ft, got)
		}
	}
}

// TestAuthorizedFunctionTypeFromXDRUnknown asserts that an unrecognised XDR
// function type returns ErrUnsupportedFunctionType (fail-closed, not a zero
// value).
func TestAuthorizedFunctionTypeFromXDRUnknown(t *testing.T) {
	_, err := AuthorizedFunctionTypeFromXDR(xdr.SorobanAuthorizedFunctionType(999))
	if err == nil {
		t.Error("expected ErrUnsupportedFunctionType for unknown XDR type, got nil")
	}
	if err != ErrUnsupportedFunctionType {
		t.Errorf("got error %v, want ErrUnsupportedFunctionType", err)
	}
}

// TestAuthorizedFunctionTypeToXDRUnknown asserts that an unrecognised string
// returns ErrUnsupportedFunctionType.
func TestAuthorizedFunctionTypeToXDRUnknown(t *testing.T) {
	ft := AuthorizedFunctionType("not_a_real_type")
	_, err := ft.ToXDR()
	if err == nil {
		t.Error("expected ErrUnsupportedFunctionType for unknown AuthorizedFunctionType, got nil")
	}
	if err != ErrUnsupportedFunctionType {
		t.Errorf("got error %v, want ErrUnsupportedFunctionType", err)
	}
}

// TestAuthorizedFunctionTypeCoversAllXDRValues asserts that every value in the
// SDK's SorobanAuthorizedFunctionType enum has a corresponding constant here.
// This test fails if the SDK gains a new function type with no constant in this
// package.
func TestAuthorizedFunctionTypeCoversAllXDRValues(t *testing.T) {
	// Enumerate XDR values by probing ValidEnum; the SDK-generated ValidEnum
	// returns true for every defined value and false otherwise.
	var sample xdr.SorobanAuthorizedFunctionType
	uncovered := 0
	for i := int32(0); i <= 100; i++ {
		if !sample.ValidEnum(i) {
			continue
		}
		xdrVal := xdr.SorobanAuthorizedFunctionType(i)
		_, err := AuthorizedFunctionTypeFromXDR(xdrVal)
		if err != nil {
			t.Errorf("XDR SorobanAuthorizedFunctionType value %d is valid in the SDK but has no AuthorizedFunctionType constant", i)
			uncovered++
		}
	}
	if uncovered > 0 {
		t.Logf("add constants for the %d uncovered function type(s) above", uncovered)
	}
}
