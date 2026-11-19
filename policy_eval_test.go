package soroauth

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestEvaluateAccountPolicySourceAccount verifies that a source-account entry
// satisfies any policy, since authentication comes from the transaction envelope.
func TestEvaluateAccountPolicySourceAccount(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	result := EvaluateAccountPolicy(entry, RequiredSigner("G...irrelevant"))
	if !result.Satisfied {
		t.Errorf("source-account entry: got Satisfied=false, want true; violations: %v", result.Violations)
	}
}

// TestEvaluateAccountPolicyRequiredSignerPasses verifies a RequiredSigner
// policy on an entry whose node is signed.
func TestEvaluateAccountPolicyRequiredSignerPasses(t *testing.T) {
	label := "soroauth-policy-eval-required-signed"
	entry := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	signer := NewEd25519Signer(testKeypair(t, label))
	signed, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry},
		[]Signer{signer}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}

	result := EvaluateAccountPolicy(signed[0], RequiredSigner(testKeypair(t, label).Address()))
	if !result.Satisfied {
		t.Errorf("signed entry: got Satisfied=false; violations: %v", result.Violations)
	}
}

// TestEvaluateAccountPolicyRequiredSignerFails verifies a RequiredSigner policy
// on an unsigned entry, and that the violation names the address and node.
func TestEvaluateAccountPolicyRequiredSignerFails(t *testing.T) {
	label := "soroauth-policy-eval-required-unsigned"
	entry := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)
	addr := testKeypair(t, label).Address()

	result := EvaluateAccountPolicy(entry, RequiredSigner(addr))
	if result.Satisfied {
		t.Fatal("unsigned entry: got Satisfied=true, want false")
	}
	if len(result.Violations) != 1 {
		t.Fatalf("want 1 violation, got %d: %v", len(result.Violations), result.Violations)
	}
	if result.Violations[0].Node != addr {
		t.Errorf("violation Node: got %q, want %q", result.Violations[0].Node, addr)
	}
}

// TestEvaluateAccountPolicyThresholdPasses verifies that a threshold policy
// is satisfied when enough addresses are signed.
func TestEvaluateAccountPolicyThresholdPasses(t *testing.T) {
	a := testKeypair(t, "soroauth-policy-eval-thr-a")
	b := testKeypair(t, "soroauth-policy-eval-thr-b")
	c := testKeypair(t, "soroauth-policy-eval-thr-c")

	base := entryForSigner(t, "soroauth-policy-eval-thr-a",
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 10)
	wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: b.Address()},
		{Address: c.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("WithDelegates: %v", err)
	}

	// Sign only a and b (2 of 3).
	signers := []Signer{
		NewEd25519Signer(a),
		NewEd25519Signer(b),
	}
	signed, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{wrapped},
		signers, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}

	policy := ThresholdOfSigners(2, a.Address(), b.Address(), c.Address())
	result := EvaluateAccountPolicy(signed[0], policy)
	if !result.Satisfied {
		t.Errorf("2-of-3 threshold with 2 signed: Satisfied=false; violations: %v", result.Violations)
	}
}

// TestEvaluateAccountPolicyThresholdFails verifies that a threshold policy
// reports a violation when too few addresses are signed, naming the requirement.
func TestEvaluateAccountPolicyThresholdFails(t *testing.T) {
	a := testKeypair(t, "soroauth-policy-eval-thrfail-a")
	b := testKeypair(t, "soroauth-policy-eval-thrfail-b")
	c := testKeypair(t, "soroauth-policy-eval-thrfail-c")

	base := entryForSigner(t, "soroauth-policy-eval-thrfail-a",
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 11)
	wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: b.Address()},
		{Address: c.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("WithDelegates: %v", err)
	}

	// Sign only a (1 of 3, but threshold is 2).
	signed, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{wrapped},
		[]Signer{NewEd25519Signer(a)}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}

	policy := ThresholdOfSigners(2, a.Address(), b.Address(), c.Address())
	result := EvaluateAccountPolicy(signed[0], policy)
	if result.Satisfied {
		t.Fatal("1-of-3 with threshold 2: got Satisfied=true, want false")
	}
	if len(result.Violations) == 0 {
		t.Fatal("expected at least one violation")
	}
}

// TestEvaluateAccountPolicyAllSignersFails verifies that AllSigners reports a
// violation for each unsigned address, so the caller knows which nodes are
// missing, not just that the policy failed.
func TestEvaluateAccountPolicyAllSignersFails(t *testing.T) {
	a := testKeypair(t, "soroauth-policy-eval-all-a")
	b := testKeypair(t, "soroauth-policy-eval-all-b")

	base := entryForSigner(t, "soroauth-policy-eval-all-a",
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 12)
	wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: b.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("WithDelegates: %v", err)
	}

	// Sign only a; b is left unsigned.
	signed, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{wrapped},
		[]Signer{NewEd25519Signer(a)}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}

	result := EvaluateAccountPolicy(signed[0], AllSigners(a.Address(), b.Address()))
	if result.Satisfied {
		t.Fatal("b unsigned: got Satisfied=true, want false")
	}
	found := false
	for _, v := range result.Violations {
		if v.Node == b.Address() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("violation for %s not found in %v", b.Address(), result.Violations)
	}
}

// TestEvaluateAccountPolicyDocComment verifies that the doc comment's honesty
// boundary holds: a source-account entry passes any policy, and nothing here
// is about the deployed contract.
func TestEvaluateAccountPolicyDocComment(t *testing.T) {
	src := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	// Even a policy that names addresses the source-account entry has no nodes
	// for must pass, because source-account auth is the envelope's concern.
	result := EvaluateAccountPolicy(src, AllSigners("GABCDEF", "GHIJKLM"))
	if !result.Satisfied {
		t.Error("source-account entry must satisfy any policy")
	}
}
