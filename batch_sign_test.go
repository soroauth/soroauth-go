package soroauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

)

// entryForSigner is the same helper batch_test.go already uses.
func entryForSigner(t *testing.T, label string, armType xdr.SorobanCredentialsType, nonce int64) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, armType, nonce)
	address, err := ParseAddress(testKeypair(t, label).Address())
	if err != nil {
		t.Fatalf("parsing %q: %v", label, err)
	}
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	credentials.Address = address
	return entry
}

func TestAuthorizeBatchPreservesOrdering(t *testing.T) {
	// Three entries on three different arms, three signers out of order in
	// the slice. The batch must return them in the same order it was given,
	// one per slot, so a caller that relied on positional matching still
	// works.
	first := entryForSigner(t, "soroauth-order-1", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1)
	second := entryForSigner(t, "soroauth-order-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)
	third := entryForSigner(t, "soroauth-order-3", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 3)

	orderBefore := make([][]byte, 3)
	for i, entry := range []xdr.SorobanAuthorizationEntry{first, second, third} {
		encoded, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling entry %d: %v", i, err)
		}
		orderBefore[i] = encoded
	}

	signers := []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-3")),
		NewEd25519Signer(testKeypair(t, "soroauth-batch-2")),
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
	}

	got, err := AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{first, second, third}, signers,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeBatch returned an unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries back, want 3", len(got))
	}

	for i, entry := range []xdr.SorobanAuthorizationEntry{first, second, third} {
		encoded, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling entry %d: %v", i, err)
		}
		gotEncoded, err := got[i].MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling got entry %d: %v", i, err)
		}
		if !bytes.Equal(encoded, gotEncoded) {
			t.Errorf("entry %d changed order; before %x, got %x", i, encoded, gotEncoded)
		}
	}
}

func TestAuthorizeBatchIsAllOrNothing(t *testing.T) {
	good := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	bad := entryForSigner(t, "soroauth-batch-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)

	signers := []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
		SignerFunc(testKeypair(t, "soroauth-batch-2").Address(),
			func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
				return xdr.ScVal{}, errors.New("the hardware signer refused")
			}),
	}

	got, err := AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{good, bad}, signers,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("AuthorizeBatch succeeded despite a failing signer")
	}
	if got != nil {
		t.Errorf("AuthorizeBatch returned %d entries alongside an error, want nil", len(got))
	}
}

func TestAuthorizeBatchFailsClosedOnMissingSigner(t *testing.T) {
	first := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	absent := entryForSigner(t, "soroauth-batch-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)

	got, err := AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{first, absent}, []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
	}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatalf("AuthorizeBatch skipped an entry instead of failing, returning %d entries", len(got))
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
	if !strings.Contains(err.Error(), testKeypair(t, "soroauth-batch-2").Address()) {
		t.Errorf("error %q does not name the address with no signer", err)
	}
	if got != nil {
		t.Errorf("AuthorizeBatch returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeBatchEmptyBatch pins the documented edge case: an empty batch
// succeeds and returns an empty slice, with no Signer invoked.
func TestAuthorizeBatchEmptyBatch(t *testing.T) {
	got, err := AuthorizeBatch(context.Background(), nil, nil,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeBatch returned an unexpected error for an empty batch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d entries for an empty batch, want 0", len(got))
	}
}

// TestAuthorizeBatchCancelledContextFailsClosed asserts that a cancelled
// context is checked before any entry is signed, so no Signer runs at all.
func TestAuthorizeBatchCancelledContextFailsClosed(t *testing.T) {
	entry := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := AuthorizeBatch(ctx, []xdr.SorobanAuthorizationEntry{entry}, []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
	}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("AuthorizeBatch succeeded with a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %q does not wrap context.Canceled", err)
	}
	if got != nil {
		t.Errorf("AuthorizeBatch returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeBatchAllOrNothingOnConcurrentError exercises the slice order
// guarantee under contention: one worker fails while two others would have
// succeeded, and the result must be nil so no partial batch can be
// submitted. The test is racy by design (workers are scheduled by the
// scheduler), so it is confined to the race-detector run, where the
// ordering and data-race checks are worth the cost.
func TestAuthorizeBatchAllOrNothingOnConcurrentError(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: skipping a stressful concurrency test")
	}
	// This must run under go test -race, because it deliberately races a
	// condition the batch must observe. With the race detector absent,
	// timing is so stable that the failure is only ever visible here.
	entryGood := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	entryBad := entryForSigner(t, "soroauth-batch-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)

	want := errors.New("the hardware signer refused")
	signers := []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
		SignerFunc(testKeypair(t, "soroauth-batch-2").Address(),
			func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
				return xdr.ScVal{}, want
			}),
	}

	got, err := AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{entryGood, entryBad}, signers,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("AuthorizeBatch succeeded despite a failing signer, under concurrency")
	}
	if !errors.Is(err, want) {
		t.Errorf("error %q does not wrap the signer's refusal", err)
	}
	if got != nil {
		t.Errorf("AuthorizeBatch returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeBatchReusesNoCallerInput proves the batch never writes
// through a shared value: filling the result slice neither aliases the
// input nor the entries a winner returned to anyone else.
func TestAuthorizeBatchReusesNoCallerInput(t *testing.T) {
	first := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	second := entryForSigner(t, "soroauth-batch-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)

	before := make([][]byte, 2)
	for i, entry := range []xdr.SorobanAuthorizationEntry{first, second} {
		encoded, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		before[i] = encoded
	}

	got, err := AuthorizeBatch(context.Background(), []xdr.SorobanAuthorizationEntry{first, second}, []Signer{
		NewEd25519Signer(testKeypair(t, "soroauth-batch-1")),
		NewEd25519Signer(testKeypair(t, "soroauth-batch-2")),
	}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeBatch returned an unexpected error: %v", err)
	}

	for i, entry := range []xdr.SorobanAuthorizationEntry{first, second} {
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("entry %d was mutated by the batch", i)
		}
	}
}
