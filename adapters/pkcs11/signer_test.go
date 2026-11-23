package pkcs11

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// fakeP11Ctx is an in-process PKCS#11 implementation used by tests. It never
// requires a real HSM or SoftHSM2. The signer's private key is stored in full
// only in this fake; production code only holds the public key.
type fakeP11Ctx struct {
	kp         *keypair.Full
	loginErr   error
	signErr    error
	loginCalls int
}

func (f *fakeP11Ctx) OpenSession(_ uint, _ uint) (SessionHandle, error) {
	return SessionHandle(1), nil
}

func (f *fakeP11Ctx) CloseSession(_ SessionHandle) error { return nil }

func (f *fakeP11Ctx) Login(_ SessionHandle, _ uint, _ string) error {
	f.loginCalls++
	return f.loginErr
}

func (f *fakeP11Ctx) Logout(_ SessionHandle) error { return nil }

func (f *fakeP11Ctx) FindObjectsInit(_ SessionHandle, _ []Attribute) error { return nil }

func (f *fakeP11Ctx) FindObjects(_ SessionHandle, _ int) ([]ObjectHandle, bool, error) {
	return []ObjectHandle{ObjectHandle(1)}, false, nil
}

func (f *fakeP11Ctx) FindObjectsFinal(_ SessionHandle) error { return nil }

func (f *fakeP11Ctx) SignInit(_ SessionHandle, _ uint, _ ObjectHandle) error { return nil }

func (f *fakeP11Ctx) Sign(_ SessionHandle, msg []byte) ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig, err := f.kp.Sign(msg)
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

const testKeyLabel = "soroauth-test-ed25519"

func TestNewSignerRejectsBadInput(t *testing.T) {
	kp := testKeyPair(t, "pkcs11-bad-input")
	ctx := &fakeP11Ctx{kp: kp}
	pin := func() ([]byte, error) { return []byte("pin"), nil }
	for _, tc := range []struct {
		name     string
		address  string
		keyLabel string
		ctx      P11Ctx
		pin      PINFunc
	}{
		{"nil ctx", kp.Address(), testKeyLabel, nil, pin},
		{"empty label", kp.Address(), "", ctx, pin},
		{"nil pin", kp.Address(), testKeyLabel, ctx, nil},
		{"bad address", "not-an-address", testKeyLabel, ctx, pin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSigner(tc.address, 0, tc.keyLabel, tc.ctx, tc.pin)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSignProducesVerifiableAccountSignature(t *testing.T) {
	kp := testKeyPair(t, "pkcs11-sign-valid")
	fake := &fakeP11Ctx{kp: kp}
	pin := func() ([]byte, error) { return []byte("correct-pin"), nil }

	s, err := NewSigner(kp.Address(), 0, testKeyLabel, fake, pin)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("soroauth test payload"))
	got, err := s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got.Type != xdr.ScValTypeScvVec || got.Vec == nil {
		t.Fatalf("Sign returned type %s, want scvVec", got.Type)
	}
}

func TestSignRejectsBadSignature(t *testing.T) {
	kp := testKeyPair(t, "pkcs11-bad-sig")
	other := testKeyPair(t, "pkcs11-wrong-key")
	// fake signs with the wrong key, so the local verify should fail
	fake := &fakeP11Ctx{kp: other}
	pin := func() ([]byte, error) { return []byte("pin"), nil }

	s, err := NewSigner(kp.Address(), 0, testKeyLabel, fake, pin)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("bad payload"))
	_, err = s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Fatalf("Sign error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignPropagatesLoginFailure(t *testing.T) {
	kp := testKeyPair(t, "pkcs11-login-fail")
	loginErr := errors.New("CKR_PIN_INCORRECT")
	fake := &fakeP11Ctx{kp: kp, loginErr: loginErr}
	pin := func() ([]byte, error) { return []byte("wrong-pin"), nil }

	s, err := NewSigner(kp.Address(), 0, testKeyLabel, fake, pin)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := sha256.Sum256([]byte("x"))
	_, err = s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, loginErr) {
		t.Fatalf("Sign error = %v, want loginErr wrapped", err)
	}
}

func TestSignPropagatesContextCancellation(t *testing.T) {
	kp := testKeyPair(t, "pkcs11-cancel")
	fake := &fakeP11Ctx{kp: kp}
	pin := func() ([]byte, error) { return []byte("pin"), nil }

	s, err := NewSigner(kp.Address(), 0, testKeyLabel, fake, pin)
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
	if fake.loginCalls != 0 {
		t.Fatalf("Login was called after cancelled context")
	}
}

// TestSignErrorsNeverContainPIN is the security property asserted by the
// package doc: no error message produced during a Sign call ever contains
// the PIN value, even when the underlying P11Ctx returns errors.
func TestSignErrorsNeverContainPIN(t *testing.T) {
	const secretPIN = "SUPER_SECRET_PIN_XYZ_42"

	kp := testKeyPair(t, "pkcs11-pin-safety")
	pin := func() ([]byte, error) { return []byte(secretPIN), nil }

	for _, tc := range []struct {
		name     string
		loginErr error
		signErr  error
	}{
		{"login failure", errors.New("CKR_DEVICE_ERROR"), nil},
		{"sign failure", nil, errors.New("CKR_GENERAL_ERROR")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeP11Ctx{kp: kp, loginErr: tc.loginErr, signErr: tc.signErr}
			s, err := NewSigner(kp.Address(), 0, testKeyLabel, fake, pin)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}

			payload := sha256.Sum256([]byte("x"))
			_, err = s.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if strings.Contains(err.Error(), secretPIN) {
				t.Fatalf("error message contains PIN: %q", err.Error())
			}
		})
	}
}
