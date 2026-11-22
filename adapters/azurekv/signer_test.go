package azurekv

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const testKeyName = "soroauth-test-ed25519"
const testKeyVersion = "9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c"

type fakeAzure struct {
	signature []byte
	err       error
	calls     int
	lastAlgo  azkeys.SignatureAlgorithm
	lastValue []byte
}

func (f *fakeAzure) Sign(_ context.Context, _, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.calls++
	if params.Algorithm != nil {
		f.lastAlgo = *params.Algorithm
	}
	f.lastValue = params.Value
	if f.err != nil {
		return azkeys.SignResponse{}, f.err
	}
	resp := azkeys.SignResponse{}
	resp.Result = f.signature
	return resp, nil
}

func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving test keypair: %v", err)
	}
	return kp
}

func TestNewSignerRejectsBadInput(t *testing.T) {
	kp := testKeypair(t, "azurekv-bad-input")
	client := &fakeAzure{}
	for _, tc := range []struct {
		name       string
		address    string
		keyName    string
		keyVersion string
		client     SignerClient
	}{
		{"nil client", kp.Address(), testKeyName, testKeyVersion, nil},
		{"empty key name", kp.Address(), "", testKeyVersion, client},
		{"invalid address", "not-an-account", testKeyName, testKeyVersion, client},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSigner(tc.address, tc.keyName, tc.keyVersion, tc.client)
			if err == nil {
				t.Fatal("NewSigner: want error, got nil")
			}
			if tc.name != "invalid address" && !errors.Is(err, soroauth.ErrMissingSigner) {
				t.Fatalf("NewSigner error = %v, want ErrMissingSigner", err)
			}
		})
	}
}

func TestSignUsesEdDSAAndBuildsVerifiedAccountSignature(t *testing.T) {
	kp := testKeypair(t, "azurekv-valid")
	payload := sha256.Sum256([]byte("soroauth-azurekv-payload"))
	signature, err := kp.Sign(payload[:])
	if err != nil {
		t.Fatal(err)
	}

	client := &fakeAzure{signature: signature}
	signer, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, client)
	if err != nil {
		t.Fatal(err)
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != xdr.ScValTypeScvVec || got.Vec == nil {
		t.Fatalf("Sign type = %s, want ScvVec", got.Type)
	}
	if client.calls != 1 {
		t.Fatalf("Key Vault calls = %d, want 1", client.calls)
	}
	if client.lastAlgo != azkeys.SignatureAlgorithm("EdDSA") {
		t.Errorf("algorithm = %q, want EdDSA", client.lastAlgo)
	}
	if string(client.lastValue) != string(payload[:]) {
		t.Error("Key Vault did not receive the exact payload")
	}
}

func TestSignRejectsWrongLengthAndCorruptedSignature(t *testing.T) {
	kp := testKeypair(t, "azurekv-invalid")
	payload := sha256.Sum256([]byte("bad-sig-payload"))

	for _, sig := range [][]byte{{1, 2, 3}, make([]byte, 70)} {
		s, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, &fakeAzure{signature: sig})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, soroauth.ErrSignatureMismatch) {
			t.Errorf("Sign(%d bytes) error = %v, want ErrSignatureMismatch", len(sig), err)
		}
	}

	// Valid length but wrong key — verify fails.
	otherKP := testKeypair(t, "azurekv-other-key")
	realPayload := sha256.Sum256([]byte("other-payload"))
	otherSig, err := otherKP.Sign(realPayload[:])
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, &fakeAzure{signature: otherSig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, soroauth.ErrSignatureMismatch) {
		t.Errorf("corrupted signature error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSignPropagatesKeyVaultFailure(t *testing.T) {
	kp := testKeypair(t, "azurekv-errors")
	payload := sha256.Sum256([]byte("failure-payload"))
	boom := errors.New("key vault unavailable")

	s, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, &fakeAzure{err: boom})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, boom) {
		t.Errorf("Sign error = %v, want %v", err, boom)
	}
}

func TestSignRespectsContextCancellation(t *testing.T) {
	kp := testKeypair(t, "azurekv-cancel")
	payload := sha256.Sum256([]byte("cancel-payload"))
	client := &fakeAzure{}

	s, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, client)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sign(ctx, xdr.HashIdPreimage{}, payload); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Sign error = %v, want context.Canceled", err)
	}
	if client.calls != 0 {
		t.Errorf("Key Vault calls after cancellation = %d, want 0", client.calls)
	}
}

func TestNewSignerRejectsTypedNilClient(t *testing.T) {
	kp := testKeypair(t, "azurekv-typed-nil")
	var nilClient *azkeys.Client
	if _, err := NewSigner(kp.Address(), testKeyName, testKeyVersion, nilClient); !errors.Is(err, soroauth.ErrMissingSigner) {
		t.Errorf("typed-nil client error = %v, want ErrMissingSigner", err)
	}
}

func TestNewSignerAcceptsEmptyKeyVersion(t *testing.T) {
	kp := testKeypair(t, "azurekv-empty-version")
	client := &fakeAzure{}
	s, err := NewSigner(kp.Address(), testKeyName, "", client)
	if err != nil {
		t.Fatalf("NewSigner with empty keyVersion: %v", err)
	}
	if s.Address() != kp.Address() {
		t.Errorf("Address() = %q, want %q", s.Address(), kp.Address())
	}
}
