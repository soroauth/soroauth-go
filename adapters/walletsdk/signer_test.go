package walletsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	okxkeypair "github.com/okx/go-wallet-sdk/coins/stellar/keypair"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// The adapter's contract with the rest of soroauth, and the SDK's contract with
// the adapter, both stated where a compile failure would point at them.
var (
	_ soroauth.Signer = (*walletSigner)(nil)
	_ Keypair         = (*okxkeypair.Full)(nil)
)

// TestSignerMatchesNewEd25519Signer is the assertion that makes this package's
// second copy of the account-signature encoding acceptable rather than a drift
// risk.
//
// The adapter writes the same {public_key, signature} map, in the same key
// order, that soroauth.NewEd25519Signer writes. This signs one payload twice -
// once through a wallet SDK keypair and the adapter, once through soroauth's
// own signer — and asserts the two ScVals are byte-identical. If the host ever
// changes the shape it decodes, both copies move together.
func TestSignerMatchesNewEd25519Signer(t *testing.T) {
	seed := sha256.Sum256([]byte("walletsdk-equivalence"))

	stellarKeypair, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving a Stellar keypair: %v", err)
	}
	walletKeypair, err := okxkeypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving an OKX keypair: %v", err)
	}
	if walletKeypair.Address() != stellarKeypair.Address() {
		t.Fatalf("the two SDKs derive different addresses from one seed: %s and %s",
			walletKeypair.Address(), stellarKeypair.Address())
	}

	adapter, err := NewSigner(walletKeypair)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if adapter.Address() != stellarKeypair.Address() {
		t.Errorf("the adapter reports %s, want %s", adapter.Address(), stellarKeypair.Address())
	}

	payload := sha256.Sum256([]byte("walletsdk-equivalence-payload"))

	got, err := adapter.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("signing through the adapter: %v", err)
	}
	want, err := soroauth.NewEd25519Signer(stellarKeypair).
		Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("signing through soroauth: %v", err)
	}

	gotXDR, err := xdr.MarshalBase64(got)
	if err != nil {
		t.Fatalf("encoding the adapter's signature: %v", err)
	}
	wantXDR, err := xdr.MarshalBase64(want)
	if err != nil {
		t.Fatalf("encoding soroauth's signature: %v", err)
	}
	if gotXDR != wantXDR {
		t.Errorf("the adapter produced %s, soroauth.NewEd25519Signer produced %s", gotXDR, wantXDR)
	}
}

// TestSignerProducesAGenuineEd25519Signature checks the bytes rather than the
// shape: the signature the adapter stores must be a real ed25519 signature over
// the payload, verifiable by the standard library with the key the G… address
// carries. A shape that matched soroauth byte for byte could still hold a
// signature no host would accept; this is the check that it does not.
func TestSignerProducesAGenuineEd25519Signature(t *testing.T) {
	kp := testKeypair(t, "walletsdk-genuine-signature")

	signer, err := NewSigner(kp)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("walletsdk-genuine-payload"))
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	publicKey, signature, err := parseAccountSignature(value)
	if err != nil {
		t.Fatalf("reading back the stored signature: %v", err)
	}
	if !ed25519.Verify(publicKey, payload[:], signature) {
		t.Error("the stored signature does not verify against the payload with the stored public key")
	}
	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("decoding %s: %v", kp.Address(), err)
	}
	if !bytes.Equal(publicKey, raw) {
		t.Error("the stored public key is not the one the address carries")
	}
}

// TestNewSignerRefusals covers the keypairs that cannot be adapted. The typed
// nils matter: a nil pointer inside a non-nil interface is not caught by a
// plain nil check, and every method on it would panic.
func TestNewSignerRefusals(t *testing.T) {
	var nilStellarKeypair *keypair.Full
	var nilWalletKeypair *okxkeypair.Full

	tests := []struct {
		name string
		kp   Keypair
	}{
		{name: "nil interface", kp: nil},
		{name: "typed nil *keypair.Full", kp: nilStellarKeypair},
		{name: "typed nil *okxkeypair.Full", kp: nilWalletKeypair},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.kp)
			if !errors.Is(err, soroauth.ErrMissingSigner) {
				t.Fatalf("got %v, want it to wrap %v", err, soroauth.ErrMissingSigner)
			}
			if signer != nil {
				t.Error("a refused keypair produced a signer")
			}
		})
	}
}

func TestNewSignerRefusesANonAccountAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "contract address", address: testContractAddress(t, "walletsdk-not-an-account")},
		{name: "not an address at all", address: "not-an-address"},
		{name: "empty", address: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(stubKeypair{address: tt.address})
			if err == nil {
				t.Fatalf("%q was accepted as a signing address", tt.address)
			}
			if !strings.Contains(err.Error(), "not an account") {
				t.Errorf("the error %q does not say the address is not a G… account", err)
			}
			if signer != nil {
				t.Error("a refused address produced a signer")
			}
		})
	}
}

// cancelledContext is a context that is already cancelled, so a test can prove
// a function fails closed before it does any work.
func cancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancelledContext: ctx.Err() is not context.Canceled")
	}
	return ctx
}

func TestSignRefusals(t *testing.T) {
	address := testKeypair(t, "walletsdk-sign-refusals").Address()

	tests := []struct {
		name      string
		kp        Keypair
		wantIs    error
		wantInErr string
	}{
		{
			name: "the keypair fails to sign",
			kp: stubKeypair{address: address, sign: func([]byte) ([]byte, error) {
				return nil, errors.New("the HSM is offline")
			}},
			wantInErr: "the HSM is offline",
		},
		{
			name: "the signature is too short",
			kp: stubKeypair{address: address, sign: func([]byte) ([]byte, error) {
				return make([]byte, 10), nil
			}},
			wantIs:    soroauth.ErrSignatureMismatch,
			wantInErr: "10-byte signature",
		},
		{
			name: "the signature is too long",
			kp: stubKeypair{address: address, sign: func([]byte) ([]byte, error) {
				return make([]byte, ed25519.SignatureSize+1), nil
			}},
			wantIs:    soroauth.ErrSignatureMismatch,
			wantInErr: "65-byte signature",
		},
		{
			name: "the keypair cannot verify its own signature",
			kp: stubKeypair{
				address: address,
				sign: func([]byte) ([]byte, error) {
					return make([]byte, ed25519.SignatureSize), nil
				},
				verify: func([]byte, []byte) error { return errors.New("no") },
			},
			wantIs: soroauth.ErrSignatureMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.kp)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}

			_, err = signer.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
			if err == nil {
				t.Fatal("Sign returned a signature it should have refused")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("got %v, want it to wrap %v", err, tt.wantIs)
			}
			if tt.wantInErr != "" && !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("the error %q does not mention %q", err, tt.wantInErr)
			}
		})
	}
}

// TestSignHonoursContextCancellation proves the keypair is not touched once the
// context is done, which is the whole reason the check is there: a cancelled
// request must not ask a hardware wallet to sign.
func TestWalletSignerHonoursContextCancellation(t *testing.T) {
	kp := testKeypair(t, "walletsdk-cancelled")
	probe := stubKeypair{
		address: kp.Address(),
		sign: func([]byte) ([]byte, error) {
			t.Error("the keypair was asked to sign despite a cancelled context")
			return nil, errors.New("must not sign")
		},
	}

	signer, err := NewSigner(probe)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, err = signer.Sign(cancelledContext(t), xdr.HashIdPreimage{}, [32]byte{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want it to wrap %v", err, context.Canceled)
	}
}
