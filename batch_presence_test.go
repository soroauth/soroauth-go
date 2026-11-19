package soroauth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// fakeBatcher is a PresenceBatcher that calls Sign once per entry, so the
// bytes it produces are identical to the per-entry path. This lets
// TestPresenceBatcherByteIdenticalToIndividualSigning prove byte equivalence
// without requiring a real hardware device.
type fakeBatcher struct {
	kp Signer
	// calls tracks how many times BatchSign was invoked, so tests can assert
	// that one confirmation covers the whole batch.
	calls int
}

func (f *fakeBatcher) Address() string { return f.kp.Address() }

func (f *fakeBatcher) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	return f.kp.Sign(ctx, preimage, payload)
}

func (f *fakeBatcher) BatchSign(ctx context.Context, entries []BatchSignEntry) ([]xdr.ScVal, error) {
	f.calls++
	out := make([]xdr.ScVal, len(entries))
	for i, e := range entries {
		sig, err := f.kp.Sign(ctx, e.Preimage, e.Payload)
		if err != nil {
			return nil, err
		}
		out[i] = sig
	}
	return out, nil
}

// TestPresenceBatcherByteIdenticalToIndividualSigning proves that signing via
// WithPresenceBatcher produces the exact same bytes as signing each entry
// individually, satisfying the acceptance criterion in issue #327.
func TestPresenceBatcherByteIdenticalToIndividualSigning(t *testing.T) {
	kp := testKeypair(t, "soroauth-presence-batcher-1")
	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-presence-batcher-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, "soroauth-presence-batcher-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
		entryForSigner(t, "soroauth-presence-batcher-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 3),
	}

	// Individual path: sign each entry one at a time.
	individual, err := AuthorizeBatch(
		context.Background(), entries,
		[]Signer{NewEd25519Signer(kp)},
		testValidUntilLedger, network.TestNetworkPassphrase,
	)
	if err != nil {
		t.Fatalf("individual AuthorizeBatch: %v", err)
	}

	// Batched path: sign with WithPresenceBatcher.
	batcher := &fakeBatcher{kp: NewEd25519Signer(kp)}
	batched, err := AuthorizeBatch(
		context.Background(), entries,
		[]Signer{batcher},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithPresenceBatcher(),
	)
	if err != nil {
		t.Fatalf("batched AuthorizeBatch: %v", err)
	}

	if batcher.calls != 1 {
		t.Fatalf("BatchSign was called %d times, want 1 (all entries in one confirmation)", batcher.calls)
	}

	if len(batched) != len(individual) {
		t.Fatalf("batched result length %d, want %d", len(batched), len(individual))
	}
	for i := range individual {
		want, err := individual[i].MarshalBinary()
		if err != nil {
			t.Fatalf("marshal individual[%d]: %v", i, err)
		}
		got, err := batched[i].MarshalBinary()
		if err != nil {
			t.Fatalf("marshal batched[%d]: %v", i, err)
		}
		if string(want) != string(got) {
			t.Errorf("entry %d: batched bytes differ from individual bytes", i)
		}
	}
}

// TestPresenceBatcherFallsBackForNonBatcherSigner proves that when a signer
// does not implement PresenceBatcher, AuthorizeBatch falls back to the
// per-entry path without error, even with WithPresenceBatcher set.
func TestPresenceBatcherFallsBackForNonBatcherSigner(t *testing.T) {
	kp := testKeypair(t, "soroauth-presence-fallback")
	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-presence-fallback", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
	}

	// A plain Ed25519Signer does not implement PresenceBatcher.
	got, err := AuthorizeBatch(
		context.Background(), entries,
		[]Signer{NewEd25519Signer(kp)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithPresenceBatcher(),
	)
	if err != nil {
		t.Fatalf("AuthorizeBatch with fallback: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
}

// TestPresenceBatcherMixedSigners proves that entries for a PresenceBatcher
// and entries for a plain signer are both signed correctly in the same batch.
func TestPresenceBatcherMixedSigners(t *testing.T) {
	batcherKP := testKeypair(t, "soroauth-presence-mixed-batcher")
	plainKP := testKeypair(t, "soroauth-presence-mixed-plain")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-presence-mixed-batcher", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, "soroauth-presence-mixed-plain", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	batcher := &fakeBatcher{kp: NewEd25519Signer(batcherKP)}
	got, err := AuthorizeBatch(
		context.Background(), entries,
		[]Signer{batcher, NewEd25519Signer(plainKP)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithPresenceBatcher(),
	)
	if err != nil {
		t.Fatalf("AuthorizeBatch mixed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if batcher.calls != 1 {
		t.Fatalf("BatchSign called %d times, want 1", batcher.calls)
	}
}

// TestPresenceBatcherPropagatesBatchSignError checks that an error from
// BatchSign is surfaced to the caller.
func TestPresenceBatcherPropagatesBatchSignError(t *testing.T) {
	kp := testKeypair(t, "soroauth-presence-batcherr")
	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-presence-batcherr", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
	}

	boom := errors.New("device rejected")
	errBatcher := &errPresenceBatcher{
		Signer: NewEd25519Signer(kp),
		err:    boom,
	}
	_, err := AuthorizeBatch(
		context.Background(), entries,
		[]Signer{errBatcher},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithPresenceBatcher(),
	)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want boom wrapped", err)
	}
}

type errPresenceBatcher struct {
	Signer
	err error
}

func (e *errPresenceBatcher) BatchSign(_ context.Context, _ []BatchSignEntry) ([]xdr.ScVal, error) {
	return nil, e.err
}
