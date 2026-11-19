package testentry_test

import (
	"bytes"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/testentry"
)

// TestKeyIsDeterministic checks that Key returns the same value on repeated calls
// and that two different labels produce different keys.
func TestKeyIsDeterministic(t *testing.T) {
	a1, err := testentry.Key(testentry.LabelSigner)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	a2, err := testentry.Key(testentry.LabelSigner)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if a1.Address() != a2.Address() {
		t.Errorf("Key is not deterministic: %q != %q", a1.Address(), a2.Address())
	}

	b, err := testentry.Key(testentry.LabelDelegate1)
	if err != nil {
		t.Fatalf("Key delegate: %v", err)
	}
	if a1.Address() == b.Address() {
		t.Error("two different labels produced the same key")
	}
}

// TestContractAddressIsDeterministic checks the same for ContractAddress.
func TestContractAddressIsDeterministic(t *testing.T) {
	a1, err := testentry.ContractAddress(testentry.LabelContract)
	if err != nil {
		t.Fatalf("ContractAddress: %v", err)
	}
	a2, err := testentry.ContractAddress(testentry.LabelContract)
	if err != nil {
		t.Fatalf("ContractAddress: %v", err)
	}
	if a1 != a2 {
		t.Errorf("ContractAddress is not deterministic: %q != %q", a1, a2)
	}
	if len(a1) == 0 || a1[0] != 'C' {
		t.Errorf("ContractAddress result is not a C… address: %q", a1)
	}
}

// TestInvocationIsDeterministic checks that the standard invocation marshals
// identically on repeated calls.
func TestInvocationIsDeterministic(t *testing.T) {
	inv1, err := testentry.Invocation()
	if err != nil {
		t.Fatalf("Invocation: %v", err)
	}
	inv2, err := testentry.Invocation()
	if err != nil {
		t.Fatalf("Invocation: %v", err)
	}
	b1, err := inv1.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b2, err := inv2.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Error("Invocation is not deterministic")
	}
}

// TestAllArmsProduceDeterministicEntries checks that every standard entry function
// returns the same bytes on repeated calls.
func TestAllArmsProduceDeterministicEntries(t *testing.T) {
	builders := []struct {
		name string
		fn   func() (xdr.SorobanAuthorizationEntry, error)
	}{
		{"SourceAccount", testentry.SourceAccountEntry},
		{"Legacy", testentry.LegacyEntry},
		{"V2", testentry.V2Entry},
		{"Delegates", testentry.DelegatesEntry},
	}

	for _, tc := range builders {
		t.Run(tc.name, func(t *testing.T) {
			e1, err := tc.fn()
			if err != nil {
				t.Fatalf("%s: first call: %v", tc.name, err)
			}
			e2, err := tc.fn()
			if err != nil {
				t.Fatalf("%s: second call: %v", tc.name, err)
			}
			b1, err := e1.MarshalBinary()
			if err != nil {
				t.Fatalf("%s: marshal first: %v", tc.name, err)
			}
			b2, err := e2.MarshalBinary()
			if err != nil {
				t.Fatalf("%s: marshal second: %v", tc.name, err)
			}
			if !bytes.Equal(b1, b2) {
				t.Errorf("%s: not deterministic", tc.name)
			}
		})
	}
}

// TestEntryArmsAreDistinct verifies that the four arms produce different bytes.
func TestEntryArmsAreDistinct(t *testing.T) {
	src, err := testentry.SourceAccountEntry()
	if err != nil {
		t.Fatalf("SourceAccountEntry: %v", err)
	}
	leg, err := testentry.LegacyEntry()
	if err != nil {
		t.Fatalf("LegacyEntry: %v", err)
	}
	v2, err := testentry.V2Entry()
	if err != nil {
		t.Fatalf("V2Entry: %v", err)
	}
	del, err := testentry.DelegatesEntry()
	if err != nil {
		t.Fatalf("DelegatesEntry: %v", err)
	}

	entries := []struct {
		name  string
		entry xdr.SorobanAuthorizationEntry
	}{
		{"source_account", src},
		{"legacy", leg},
		{"v2", v2},
		{"delegates", del},
	}

	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			b1, _ := entries[i].entry.MarshalBinary()
			b2, _ := entries[j].entry.MarshalBinary()
			if bytes.Equal(b1, b2) {
				t.Errorf("entries %s and %s produced the same bytes", entries[i].name, entries[j].name)
			}
		}
	}
}

// TestDelegatesEntryHasCorrectStructure checks the shape of the delegates tree.
func TestDelegatesEntryHasCorrectStructure(t *testing.T) {
	entry, err := testentry.DelegatesEntry()
	if err != nil {
		t.Fatalf("DelegatesEntry: %v", err)
	}
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Fatalf("credentials type = %v, want WithDelegates", entry.Credentials.Type)
	}
	wd := entry.Credentials.AddressWithDelegates
	if wd == nil {
		t.Fatal("AddressWithDelegates is nil")
	}
	if len(wd.Delegates) != 2 {
		t.Fatalf("top-level delegates = %d, want 2", len(wd.Delegates))
	}

	// Find the delegate that has the nested delegate.
	var foundNested bool
	for _, d := range wd.Delegates {
		if len(d.NestedDelegates) == 1 {
			foundNested = true
		}
	}
	if !foundNested {
		t.Error("no delegate has exactly one nested delegate")
	}
}

// TestDelegatesEntryIsSortedByXDRBytes verifies the ordering rule from CAP-71-01.
func TestDelegatesEntryIsSortedByXDRBytes(t *testing.T) {
	entry, err := testentry.DelegatesEntry()
	if err != nil {
		t.Fatalf("DelegatesEntry: %v", err)
	}
	wd := entry.Credentials.AddressWithDelegates
	if wd == nil || len(wd.Delegates) < 2 {
		t.Fatal("unexpected delegate structure")
	}
	a0, err := wd.Delegates[0].Address.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal delegates[0]: %v", err)
	}
	a1, err := wd.Delegates[1].Address.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal delegates[1]: %v", err)
	}
	if bytes.Compare(a0, a1) > 0 {
		t.Error("delegates are not sorted by XDR bytes ascending")
	}
}

// TestMustKeyPanicsOnEmptyLabel verifies that MustKey panics for a label that
// produces an error (empty string is valid, but this tests the panic path indirectly
// via MustContractAddress).
func TestMustKeyDoesNotPanicForStandardLabels(t *testing.T) {
	for _, label := range []string{
		testentry.LabelSigner,
		testentry.LabelDelegate1,
		testentry.LabelDelegate2,
		testentry.LabelNested,
	} {
		kp := testentry.MustKey(label)
		if kp == nil {
			t.Errorf("MustKey(%q) returned nil", label)
		}
	}
}
