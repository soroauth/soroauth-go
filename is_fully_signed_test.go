package soroauth

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// signedScVal returns a ScVal that isSigned considers signed: a non-void,
// non-empty value. We use a bytes value as the simplest stand-in for a
// real signature in structural tests that do not verify cryptography.
func signedScVal() xdr.ScVal {
	b := xdr.ScBytes([]byte{0x01})
	return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &b}
}

func TestIsFullySignedSourceAccount(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if !got {
		t.Error("source-account entry should be reported as fully signed (no signature required)")
	}
}

func TestIsFullySignedLegacyUnsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if got {
		t.Error("unsigned legacy entry should not be fully signed")
	}
}

func TestIsFullySignedLegacySigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	entry.Credentials.Address.Signature = signedScVal()
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if !got {
		t.Error("signed legacy entry should be fully signed")
	}
}

func TestIsFullySignedAddressV2Unsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if got {
		t.Error("unsigned address_v2 entry should not be fully signed")
	}
}

func TestIsFullySignedAddressV2Signed(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.Credentials.AddressV2.Signature = signedScVal()
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if !got {
		t.Error("signed address_v2 entry should be fully signed")
	}
}

func TestIsFullySignedDelegatesTopUnsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)
	// top-level unsigned, delegate unsigned → not fully signed
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if got {
		t.Error("delegates entry with unsigned top-level should not be fully signed")
	}
}

func TestIsFullySignedDelegatesPartiallySignedTopOnly(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)
	// sign the top-level but leave the delegate unsigned
	entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = signedScVal()
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if got {
		t.Error("delegates entry with unsigned delegate should not be fully signed")
	}
}

func TestIsFullySignedDelegatesFullySigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)
	entry.Credentials.AddressWithDelegates.AddressCredentials.Signature = signedScVal()
	for i := range entry.Credentials.AddressWithDelegates.Delegates {
		entry.Credentials.AddressWithDelegates.Delegates[i].Signature = signedScVal()
	}
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if !got {
		t.Error("delegates entry with all nodes signed should be fully signed")
	}
}

func TestIsFullySignedEmptyVecCountsAsUnsigned(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	// An empty ScvVec must count as unsigned per isSigned's definition.
	empty := xdr.ScVec{}
	vecPtr := &empty
	entry.Credentials.AddressV2.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &vecPtr}
	got, err := IsFullySigned(entry)
	if err != nil {
		t.Fatalf("IsFullySigned error = %v", err)
	}
	if got {
		t.Error("an empty ScvVec should count as unsigned")
	}
}
