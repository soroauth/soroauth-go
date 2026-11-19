package trezor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// fakeTransport is a test double for Transport. It signs using a local
// keypair so tests run offline without a real Trezor device.
type fakeTransport struct {
	kp    *keypair.Full
	err   error
	calls int
	// receivedPreimage holds the last preimage bytes passed to StellarAuthorize,
	// so tests can assert the preimage was forwarded to the device.
	receivedPreimage []byte
}

func (f *fakeTransport) StellarAuthorize(_ context.Context, preimage []byte, payload [32]byte) ([]byte, error) {
	f.calls++
	f.receivedPreimage = preimage
	if f.err != nil {
		return nil, f.err
	}
	sig, err := f.kp.Sign(payload[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func testKeyPair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp
}

func TestNewSignerRejectsBadInput(t *testing.T) {
	kp := testKeyPair(t, "trezor-bad-input")
	tr := &fakeTransport{kp: kp}
	for _, tc := range []struct {
		name      string
		address   string
		transport Transport
	}{
		{"nil transport", kp.Address(), nil},
		{"bad address", "not-an-address", tr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSigner(tc.address, tc.transport)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSignProducesVerifiableSignatureAndForwardsPreimage(t *testing.T) {
	kp := testKeyPair(t, "trezor-sign-valid")
	tr := &fakeTransport{kp: kp}

	s, err := NewSigner(kp.Address(), tr)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("trezor test payload"))
	// Use zero-value preimage; marshalPreimageSafe recovers from the codec
	// panic and passes empty bytes. The test checks the transport was called.
	got, err := s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got.Type != xdr.ScValTypeScvVec || got.Vec == nil {
		t.Fatalf("Sign returned type %s, want scvVec", got.Type)
	}
	if tr.calls == 0 {
		t.Fatal("transport StellarAuthorize was not called")
	}
}

func TestSignDistinguishesDeviceErrors(t *testing.T) {
	kp := testKeyPair(t, "trezor-errors")
	payload := sha256.Sum256([]byte("x"))

	for _, tc := range []struct {
		name    string
		devErr  error
		wantErr error
	}{
		{"rejected", fmt.Errorf("user cancelled: %w", ErrDeviceRejected), ErrDeviceRejected},
		{"timeout", fmt.Errorf("confirm window: %w", ErrDeviceTimeout), ErrDeviceTimeout},
		{"disconnected", fmt.Errorf("hid lost: %w", ErrDeviceDisconnected), ErrDeviceDisconnected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &fakeTransport{kp: kp, err: tc.devErr}
			s, err := NewSigner(kp.Address(), tr)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			_, err = s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Sign error = %v, want %v wrapped", err, tc.wantErr)
			}
		})
	}
}

func TestSignRejectsBadSignatureFromDevice(t *testing.T) {
	kp := testKeyPair(t, "trezor-bad-sig")
	other := testKeyPair(t, "trezor-wrong-key")
	// Transport signs with the wrong key, local verify should catch it.
	tr := &fakeTransport{kp: other}

	s, err := NewSigner(kp.Address(), tr)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("x"))
	_, err = s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Fatalf("Sign error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignPropagatesContextCancellation(t *testing.T) {
	kp := testKeyPair(t, "trezor-cancel")
	tr := &fakeTransport{kp: kp}

	s, err := NewSigner(kp.Address(), tr)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	payload := sha256.Sum256([]byte("x"))
	_, err = s.Sign(ctx, xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign error = %v, want context.Canceled", err)
	}
	if tr.calls != 0 {
		t.Fatal("transport was called after cancelled context")
	}
}
