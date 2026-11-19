package soroauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestDefaultRegistryMatchesStandaloneVerifyEntry(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	standalone, err := VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}

	registry := DefaultShapeRegistry()
	fromRegistry, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}

	if standalone.Verified() != fromRegistry.Verified() {
		t.Errorf("standalone.Verified() = %v, registry.Verified() = %v",
			standalone.Verified(), fromRegistry.Verified())
	}
	if len(standalone.Nodes) != len(fromRegistry.Nodes) {
		t.Fatalf("standalone has %d nodes, registry has %d",
			len(standalone.Nodes), len(fromRegistry.Nodes))
	}
	for i := range standalone.Nodes {
		if standalone.Nodes[i].Verdict != fromRegistry.Nodes[i].Verdict {
			t.Errorf("node %d: standalone verdict %q, registry verdict %q",
				i, standalone.Nodes[i].Verdict, fromRegistry.Nodes[i].Verdict)
		}
	}
}

func TestRegistryCustomShapeVerifies(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		t.Fatalf("addressCredentials: %v", err)
	}
	publicKey, rawSig, err := parseAccountSignature(credentials.Signature)
	if err != nil {
		t.Fatalf("parseAccountSignature: %v", err)
	}

	customSig := scBytes(append(publicKey, rawSig...))
	credentials.Signature = customSig

	customShape := ShapeRegistration{
		Name: "custom-ed25519-concat",
		Match: func(sig xdr.ScVal) bool {
			if sig.Type != xdr.ScValTypeScvBytes || sig.Bytes == nil {
				return false
			}
			return len(*sig.Bytes) == ed25519.PublicKeySize+ed25519.SignatureSize
		},
		Verify: func(_ context.Context, sig xdr.ScVal, payload [32]byte) (bool, error) {
			raw := *sig.Bytes
			pk := raw[:ed25519.PublicKeySize]
			s := raw[ed25519.PublicKeySize:]
			return ed25519.Verify(ed25519.PublicKey(pk), payload[:], s), nil
		},
	}

	registry := NewShapeRegistry(customShape)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictVerified {
		t.Errorf("verdict = %q (%s), want %q", report.Nodes[0].Verdict, report.Nodes[0].Reason, VerdictVerified)
	}
	if !strings.Contains(report.Nodes[0].Reason, "custom-ed25519-concat") {
		t.Errorf("reason %q does not name the registered shape", report.Nodes[0].Reason)
	}
	if !strings.Contains(report.Nodes[0].Reason, "caller's claim") {
		t.Errorf("reason %q does not state the trust boundary", report.Nodes[0].Reason)
	}
}

func TestRegistryFailingVerifierReportsInvalidNotCannotCheck(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	alwaysMatchAlwaysFail := ShapeRegistration{
		Name:  "always-fail",
		Match: func(sig xdr.ScVal) bool { return true },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			return false, nil
		},
	}

	registry := NewShapeRegistry(alwaysMatchAlwaysFail)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictInvalid {
		t.Errorf("verdict = %q, want %q — a failing registered verifier must report invalid, not cannot_check",
			report.Nodes[0].Verdict, VerdictInvalid)
	}
}

func TestRegistryCannotProduceFalseVerified(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		t.Fatalf("addressCredentials: %v", err)
	}
	credentials.Signature = scBytes([]byte("wrong-sig-completely"))

	lyingVerifier := ShapeRegistration{
		Name:  "liar",
		Match: func(sig xdr.ScVal) bool { return true },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			return true, nil
		},
	}

	registry := NewShapeRegistry(lyingVerifier)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}

	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictVerified {
		t.Fatalf("verdict = %q, want verified (from the lying verifier)", report.Nodes[0].Verdict)
	}
	if !strings.Contains(report.Nodes[0].Reason, "caller's claim") {
		t.Errorf("reason %q does not state the trust boundary — the report must make clear this is the caller's claim, not the library's",
			report.Nodes[0].Reason)
	}
}

func TestRegistryNoMatchFallsToCannotCheck(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		t.Fatalf("addressCredentials: %v", err)
	}
	credentials.Signature = scBytes([]byte("opaque"))

	neverMatch := ShapeRegistration{
		Name:  "never",
		Match: func(sig xdr.ScVal) bool { return false },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			t.Fatal("Verify should not be called when Match returns false")
			return false, nil
		},
	}

	registry := NewShapeRegistry(neverMatch)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictCannotCheck {
		t.Errorf("verdict = %q, want %q", report.Nodes[0].Verdict, VerdictCannotCheck)
	}
}

func TestRegistryFirstMatchWins(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	first := ShapeRegistration{
		Name:  "first",
		Match: func(sig xdr.ScVal) bool { return true },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			return false, nil
		},
	}
	second := ShapeRegistration{
		Name:  "second",
		Match: func(sig xdr.ScVal) bool { return true },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			return true, nil
		},
	}

	registry := NewShapeRegistry(first, second)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if report.Nodes[0].Verdict != VerdictInvalid {
		t.Errorf("verdict = %q, want %q — first match should win", report.Nodes[0].Verdict, VerdictInvalid)
	}
	if !strings.Contains(report.Nodes[0].Reason, "first") {
		t.Errorf("reason %q does not name the winning shape", report.Nodes[0].Reason)
	}
}

func TestRegistryVerifierErrorReportsCannotCheck(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	erroring := ShapeRegistration{
		Name:  "erroring",
		Match: func(sig xdr.ScVal) bool { return true },
		Verify: func(_ context.Context, _ xdr.ScVal, _ [32]byte) (bool, error) {
			return false, errors.New("device timeout")
		},
	}

	registry := NewShapeRegistry(erroring)
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if report.Nodes[0].Verdict != VerdictCannotCheck {
		t.Errorf("verdict = %q, want %q for a verifier error", report.Nodes[0].Verdict, VerdictCannotCheck)
	}
	if !strings.Contains(report.Nodes[0].Reason, "device timeout") {
		t.Errorf("reason %q does not surface the verifier's error", report.Nodes[0].Reason)
	}
}

func TestRegistryConcurrentUseSafe(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	registry := DefaultShapeRegistry()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
			if err != nil {
				errs <- err
				return
			}
			if !report.Verified() {
				errs <- errors.New("concurrent verify returned not-verified")
				return
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestRegistrySourceAccountEntryPassesThrough(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)

	registry := DefaultShapeRegistry()
	report, err := registry.VerifyEntry(entry, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	if report.CredentialType != CredentialTypeSourceAccount {
		t.Errorf("credential type = %q, want %q", report.CredentialType, CredentialTypeSourceAccount)
	}
	if len(report.Nodes) != 0 {
		t.Errorf("got %d nodes for source-account, want 0", len(report.Nodes))
	}
}

func TestRegistryBuiltinEd25519RegisteredThroughSameMechanism(t *testing.T) {
	reg := Ed25519ShapeRegistration()
	if reg.Name != "ed25519" {
		t.Errorf("name = %q, want %q", reg.Name, "ed25519")
	}
	if reg.Match == nil {
		t.Fatal("Match is nil")
	}
	if reg.Verify == nil {
		t.Fatal("Verify is nil")
	}

	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}
	creds, err := addressCredentials(signed.Credentials)
	if err != nil {
		t.Fatalf("addressCredentials: %v", err)
	}

	if !reg.Match(creds.Signature) {
		t.Error("built-in ed25519 shape did not match a classic account signature")
	}
}

func TestRegistryContextCancellation(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	registry := DefaultShapeRegistry()
	_, err = registry.VerifyEntryContext(ctx, signed, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestRegistryUnsupportedCredentialsArm(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
	}

	registry := DefaultShapeRegistry()
	_, err := registry.VerifyEntry(entry, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrUnsupportedCredentials) {
		t.Errorf("error = %v, want ErrUnsupportedCredentials", err)
	}
}

func TestRegistryEmptyRegistryAllCannotCheck(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	registry := NewShapeRegistry()
	report, err := registry.VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("registry.VerifyEntry: %v", err)
	}
	for i, node := range report.Nodes {
		if node.Verdict != VerdictCannotCheck {
			t.Errorf("node %d: verdict = %q, want %q for an empty registry",
				i, node.Verdict, VerdictCannotCheck)
		}
	}
}
