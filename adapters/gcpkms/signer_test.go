package gcpkms

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const testKeyVersion = "projects/test/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

// testKeypair derives a deterministic keypair from a public label, matching the
// rest of the repository's test keys. These are public test keys and are never
// funded.
func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving the test keypair: %v", err)
	}
	return kp
}

// fakeKMS is the test double: it records the request and returns whatever
// response the test prepared, so the signing path is exercised without live GCP.
type fakeKMS struct {
	signature []byte
	err       error

	calls    int
	lastName string
	lastData []byte
}

func (f *fakeKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.calls++
	f.lastName = req.GetName()
	f.lastData = append([]byte(nil), req.GetData()...)
	if f.err != nil {
		return nil, f.err
	}
	return &kmspb.AsymmetricSignResponse{Signature: f.signature}, nil
}

func TestNewSignerRejectsBadInput(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-bad-input")
	good := &fakeKMS{}

	tests := []struct {
		name    string
		address string
		version string
		client  AsymmetricSigner
		is      error
	}{
		{"nil client", kp.Address(), testKeyVersion, nil, soroauth.ErrMissingSigner},
		{"empty key version", kp.Address(), "", good, soroauth.ErrMissingSigner},
		{"not an account address", "CCYAMWWHKZWXCP2OF3WUEJZ4BS6G5Q6Y4W3P7P5F2JX6KKVWZ4Q5Z2QM", testKeyVersion, good, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSigner(tt.address, tt.version, tt.client)
			if err == nil {
				t.Fatal("NewSigner returned nil error, want a refusal")
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tt.is)
			}
		})
	}
}

func TestSignProducesVerifiedAccountSignature(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-valid")
	payload := sha256.Sum256([]byte("gcpkms payload"))

	signature, err := kp.Sign(payload[:])
	if err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	client := &fakeKMS{signature: signature}

	signer, err := NewSigner(kp.Address(), testKeyVersion, client)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Address() != kp.Address() {
		t.Errorf("Address() = %q, want %q", signer.Address(), kp.Address())
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	want, err := soroauth.Ed25519SignatureScVal(mustRawKey(t, kp.Address()), signature)
	if err != nil {
		t.Fatalf("Ed25519SignatureScVal: %v", err)
	}
	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the signed ScVal: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the expected ScVal: %v", err)
	}
	if string(gotBytes) != string(wantBytes) {
		t.Error("Sign output does not match the expected classic account signature ScVal")
	}

	if client.calls != 1 {
		t.Errorf("KMS calls = %d, want 1", client.calls)
	}
	if client.lastName != testKeyVersion {
		t.Errorf("KMS key name = %q, want %q", client.lastName, testKeyVersion)
	}
	if string(client.lastData) != string(payload[:]) {
		t.Error("KMS was not given the payload as the message to sign")
	}
}

func TestSignRejectsSignatureThatDoesNotVerify(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-bad-signature")
	payload := sha256.Sum256([]byte("gcpkms payload"))

	valid, err := kp.Sign(payload[:])
	if err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	corrupted := append([]byte(nil), valid...)
	corrupted[0] ^= 0xff

	signer, err := NewSigner(kp.Address(), testKeyVersion, &fakeKMS{signature: corrupted})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Errorf("Sign error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignRejectsWrongLengthSignature(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-wrong-length")
	payload := sha256.Sum256([]byte("gcpkms payload"))

	signer, err := NewSigner(kp.Address(), testKeyVersion, &fakeKMS{signature: []byte{1, 2, 3}})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Errorf("Sign error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignPropagatesKMSFailure(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-failure")
	payload := sha256.Sum256([]byte("gcpkms payload"))

	boom := errors.New("permission denied")
	signer, err := NewSigner(kp.Address(), testKeyVersion, &fakeKMS{err: boom})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	_, err = signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, boom) {
		t.Errorf("Sign error = %v, want it to wrap %v", err, boom)
	}
}

func TestSignChecksContextBeforeCallingKMS(t *testing.T) {
	kp := testKeypair(t, "soroauth-gcpkms-cancel")
	payload := sha256.Sum256([]byte("gcpkms payload"))
	client := &fakeKMS{}

	signer, err := NewSigner(kp.Address(), testKeyVersion, client)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, xdr.HashIdPreimage{}, payload)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Sign error = %v, want context.Canceled", err)
	}
	if client.calls != 0 {
		t.Errorf("KMS was called %d times with a cancelled context, want 0", client.calls)
	}
}

// mustRawKey decodes the 32-byte public key behind a G… address.
func mustRawKey(t *testing.T, address string) []byte {
	t.Helper()
	parsed, err := soroauth.ParseAddress(address)
	if err != nil {
		t.Fatalf("ParseAddress(%q): %v", address, err)
	}
	if parsed.Type != xdr.ScAddressTypeScAddressTypeAccount || parsed.AccountId == nil {
		t.Fatalf("%q is not an account address", address)
	}
	return parsed.AccountId.Ed25519[:]
}
