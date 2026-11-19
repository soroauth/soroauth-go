package soroauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestMergeEntriesTwoSignersV2 merges two copies of a V2 entry, each signed by
// a different signer on different nodes. The result must be byte-identical to
// the same signatures applied sequentially.
func TestMergeEntriesTwoSignersV2(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	signer := signerForLabel(t, v.Steps[0].SignerLabel)

	// Make an "unsigned" copy that has the same expiration (payload) but a
	// void signature.
	unsignedWithExp := bumpExpiration(t, diffEntry(t, v.UnsignedEntryXDR), v.ValidUntilLedger)

	// Sign the unsigned copy.
	signedCopy, err := AuthorizeEntry(
		context.Background(), unsignedWithExp, signer,
		v.ValidUntilLedger, v.NetworkPassphrase,
	)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Merge the unsigned (with correct expiration) and signed copies.
	merged, err := MergeEntries(unsignedWithExp, signedCopy)
	if err != nil {
		t.Fatalf("merging: %v", err)
	}

	same, err := xdrEqual(merged, signedCopy)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	if !same {
		t.Error("merged entry is not byte-identical to the sequentially signed entry")
	}

	// Also check: merging signed + signed should give the same result.
	merged2, err := MergeEntries(signedCopy, signedCopy)
	if err != nil {
		t.Fatalf("merging identical: %v", err)
	}
	same2, err := xdrEqual(merged2, signedCopy)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	if !same2 {
		t.Error("merging two identical signed copies is not byte-identical to either")
	}
}

// TestMergeEntriesRefusesPayloadMismatch checks that entries with different
// expirations are refused.
func TestMergeEntriesRefusesPayloadMismatch(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)

	bumped := bumpExpiration(t, unsigned, v.ValidUntilLedger+100)

	_, err := MergeEntries(unsigned, bumped)
	if err == nil {
		t.Fatal("expected an error for mismatched expirations")
	}
	if !errors.Is(err, ErrMergePayloadMismatch) {
		t.Errorf("error %q does not match ErrMergePayloadMismatch", err)
	}
	if !strings.Contains(err.Error(), "signatureExpirationLedger") {
		t.Errorf("error %q does not name the differing field", err)
	}
}

// TestMergeEntriesRefusesSignatureConflict checks that two different signatures
// on the same node are refused.
func TestMergeEntriesRefusesSignatureConflict(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)

	signerA := signerForLabel(t, v.Steps[0].SignerLabel)
	signerB := signerForLabel(t, "conflict-signer")

	signedA, err := AuthorizeEntry(
		context.Background(), unsigned, signerA,
		v.ValidUntilLedger, v.NetworkPassphrase,
	)
	if err != nil {
		t.Fatalf("signing A: %v", err)
	}

	signedB, err := AuthorizeEntry(
		context.Background(), unsigned, signerB,
		v.ValidUntilLedger, v.NetworkPassphrase,
		ForAddress(signerA.Address()),
	)
	if err != nil {
		t.Fatalf("signing B: %v", err)
	}

	_, err = MergeEntries(signedA, signedB)
	if err == nil {
		t.Fatal("expected an error for conflicting signatures")
	}
	if !errors.Is(err, ErrMergeSignatureConflict) {
		t.Errorf("error %q does not match ErrMergeSignatureConflict", err)
	}
}

// TestMergeEntriesIdenticalSignatures checks that merging two identically
// signed copies succeeds (same signature on the same node is not a conflict).
func TestMergeEntriesIdenticalSignatures(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	signed := diffEntry(t, v.SignedEntryXDR)

	merged, err := MergeEntries(signed, signed)
	if err != nil {
		t.Fatalf("merging identical copies: %v", err)
	}

	same, err := xdrEqual(merged, signed)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	if !same {
		t.Error("merged entry is not byte-identical to either input")
	}
}

// TestMergeEntriesRefusesSourceAccount checks that source-account entries are
// refused.
func TestMergeEntriesRefusesSourceAccount(t *testing.T) {
	a := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}
	_, err := MergeEntries(a, a)
	if err == nil {
		t.Fatal("expected an error for source-account entries")
	}
	if !errors.Is(err, ErrSourceAccountCredentials) {
		t.Errorf("error %q does not match ErrSourceAccountCredentials", err)
	}
}

// TestMergeEntriesRefusesTooFew checks that fewer than 2 entries is refused.
func TestMergeEntriesRefusesTooFew(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)

	_, err := MergeEntries(unsigned)
	if err == nil {
		t.Fatal("expected an error for a single entry")
	}
	if !strings.Contains(err.Error(), "at least 2") {
		t.Errorf("error %q does not say at least 2", err)
	}
}

// TestMergeEntriesThreeCopies merges three copies: one unsigned (with matching
// expiration) and two identically signed. Should succeed.
func TestMergeEntriesThreeCopies(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	signer := signerForLabel(t, v.Steps[0].SignerLabel)

	unsignedWithExp := bumpExpiration(t, diffEntry(t, v.UnsignedEntryXDR), v.ValidUntilLedger)

	signed, err := AuthorizeEntry(
		context.Background(), unsignedWithExp, signer,
		v.ValidUntilLedger, v.NetworkPassphrase,
	)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	merged, err := MergeEntries(unsignedWithExp, signed, signed)
	if err != nil {
		t.Fatalf("merging three copies: %v", err)
	}

	same, err := xdrEqual(merged, signed)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	if !same {
		t.Error("merged entry is not byte-identical to the signed entry")
	}
}

// TestMergeEntriesDelegates merges two copies of a delegates entry, each signed
// by a different delegate. The result must carry both signatures.
func TestMergeEntriesDelegates(t *testing.T) {
	v := findVector(t, "delegates_from_legacy")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)

	if len(v.Steps) < 2 {
		t.Skip("delegates_from_legacy vector needs at least 2 signing steps")
	}

	// Sign with the first step only.
	step0 := v.Steps[0]
	signer0 := signerForStep(t, step0)
	opts0 := mergeStepOptions(step0)
	copy0, err := AuthorizeEntry(
		context.Background(), unsigned, signer0,
		v.ValidUntilLedger, v.NetworkPassphrase, opts0...,
	)
	if err != nil {
		t.Fatalf("signing step 0: %v", err)
	}

	// Sign with the second step only.
	step1 := v.Steps[1]
	signer1 := signerForStep(t, step1)
	opts1 := mergeStepOptions(step1)
	copy1, err := AuthorizeEntry(
		context.Background(), unsigned, signer1,
		v.ValidUntilLedger, v.NetworkPassphrase, opts1...,
	)
	if err != nil {
		t.Fatalf("signing step 1: %v", err)
	}

	// Sequential baseline: sign step 0 then step 1 on the same copy.
	sequential, err := AuthorizeEntry(
		context.Background(), copy0, signer1,
		v.ValidUntilLedger, v.NetworkPassphrase, opts1...,
	)
	if err != nil {
		t.Fatalf("sequential signing: %v", err)
	}

	merged, err := MergeEntries(copy0, copy1)
	if err != nil {
		t.Fatalf("merging: %v", err)
	}

	same, err := xdrEqual(merged, sequential)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}
	if !same {
		t.Error("merged entry is not byte-identical to the sequentially signed entry")
	}
}

// mergeStepOptions builds the AuthorizeOption slice a golden vector step calls for.
func mergeStepOptions(step vectorStep) []AuthorizeOption {
	var opts []AuthorizeOption
	if step.ForAddress != nil && *step.ForAddress != "" {
		opts = append(opts, ForAddress(*step.ForAddress))
	}
	return opts
}

// TestMergeEntriesRefusesDifferentNonce checks that entries with different
// nonces are refused.
func TestMergeEntriesRefusesDifferentNonce(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	a := diffEntry(t, v.UnsignedEntryXDR)

	b, err := xdrcopyEntry(t, a)
	if err != nil {
		t.Fatalf("copying: %v", err)
	}
	creds, err := addressCredentials(b.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	creds.Nonce = creds.Nonce + 1

	_, err = MergeEntries(a, b)
	if err == nil {
		t.Fatal("expected an error for mismatched nonces")
	}
	if !errors.Is(err, ErrMergePayloadMismatch) {
		t.Errorf("error %q does not match ErrMergePayloadMismatch", err)
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error %q does not name the differing field", err)
	}
}
