package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// vaultTestSeed is a public, deterministic seed. It exists only to make these
// tests reproducible; it is never funded and never used outside tests.
var vaultTestSeed = sha256.Sum256([]byte("soroauth-vault-test-key"))

func vaultTestKeypair(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(vaultTestSeed)
	if err != nil {
		t.Fatalf("deriving the Vault test keypair: %v", err)
	}
	return kp
}

// vaultTestPreimage builds a minimal preimage and its payload hash.
func vaultTestPreimage(t *testing.T) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	contract, err := ParseAddress(testContractAddress(t, "soroauth-vault-test-contract"))
	if err != nil {
		t.Fatalf("parsing the test contract address: %v", err)
	}
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			Nonce:                     xdr.Int64(1),
			SignatureExpirationLedger: 100,
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: contract,
						FunctionName:    xdr.ScSymbol("noop"),
						Args:            []xdr.ScVal{},
					},
				},
			},
		},
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the test preimage: %v", err)
	}
	return preimage, payload
}

// vaultServer is a stand-in for Vault's transit engine. It serves the two
// endpoints the signer uses and signs exactly as Vault's ed25519 key would.
type vaultServer struct {
	keyType     string
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	keysBody    string // when non-empty, returned by the read-key endpoint
	signStatus  int    // when non-zero, the sign endpoint returns this status
	signature   string // when non-empty, the signature value returned
	rejectToken bool
	lastInput   []byte
}

func (v *vaultServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if v.rejectToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		if r.Header.Get("X-Vault-Token") == "" {
			t.Errorf("request had no X-Vault-Token header")
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/alice":
			if v.keysBody != "" {
				_, _ = w.Write([]byte(v.keysBody))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"type": v.keyType,
					"keys": map[string]any{
						"1": base64.StdEncoding.EncodeToString(v.publicKey),
					},
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/alice":
			if v.signStatus != 0 {
				w.WriteHeader(v.signStatus)
				return
			}
			var request struct {
				Input string `json:"input"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decoding the sign request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			input, err := base64.StdEncoding.DecodeString(request.Input)
			if err != nil {
				t.Errorf("decoding the sign input: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			v.lastInput = input

			signature := ed25519.Sign(v.privateKey, input)
			value := v.signature
			if value == "" {
				value = "vault:v1:" + base64.StdEncoding.EncodeToString(signature)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"signature": value},
			})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func newVaultServer(t *testing.T, v *vaultServer) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(v.handler(t))
	t.Cleanup(server.Close)
	return server
}

func TestVaultSignerProducesTheAccountShape(t *testing.T) {
	kp := vaultTestKeypair(t)
	vault := &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	}
	server := newVaultServer(t, vault)

	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL,
		Token:   "test-token",
		KeyName: "alice",
		Address: kp.Address(),
	})
	if err != nil {
		t.Fatalf("NewVaultSigner returned an unexpected error: %v", err)
	}
	if got := signer.Address(); got != kp.Address() {
		t.Errorf("Address is %q, want %q", got, kp.Address())
	}

	preimage, payload := vaultTestPreimage(t)
	got, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	// Vault's transit ed25519 key is an ordinary Stellar key, so the signer must
	// produce byte-for-byte what the in-memory ed25519 signer produces for the
	// same key and payload.
	want, err := NewEd25519Signer(kp).Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("the reference ed25519 signer failed: %v", err)
	}
	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the Vault signature: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the reference signature: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("Vault signature shape differs from the account shape\n want %x\n  got %x", wantBytes, gotBytes)
	}

	// Vault must have received exactly the 32-byte payload.
	if !bytes.Equal(vault.lastInput, payload[:]) {
		t.Errorf("Vault signed %x, want the payload %x", vault.lastInput, payload)
	}
}

func TestVaultSignerRejectsUnauthorizedToken(t *testing.T) {
	kp := vaultTestKeypair(t)
	server := newVaultServer(t, &vaultServer{rejectToken: true})

	_, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "expired", KeyName: "alice", Address: kp.Address(),
	})
	if !errors.Is(err, ErrVaultUnauthorized) {
		t.Fatalf("error %v does not match ErrVaultUnauthorized", err)
	}
}

func TestVaultSignerRejectsMissingKey(t *testing.T) {
	kp := vaultTestKeypair(t)
	server := newVaultServer(t, &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	})

	// A different key name hits the handler's 404 branch.
	_, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "bob", Address: kp.Address(),
	})
	if !errors.Is(err, ErrVaultKeyNotFound) {
		t.Fatalf("error %v does not match ErrVaultKeyNotFound", err)
	}
}

func TestVaultSignerRejectsWrongKeyType(t *testing.T) {
	kp := vaultTestKeypair(t)
	vault := &vaultServer{
		keyType:    "aes256-gcm96",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	}
	server := newVaultServer(t, vault)

	_, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: kp.Address(),
	})
	if !errors.Is(err, ErrVaultKeyType) {
		t.Fatalf("error %v does not match ErrVaultKeyType", err)
	}
}

func TestVaultSignerRejectsAddressMismatch(t *testing.T) {
	other := testKeypair(t, "soroauth-vault-other-account")
	vault := &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	}
	server := newVaultServer(t, vault)

	_, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: other.Address(),
	})
	if !errors.Is(err, ErrSignerAddressMismatch) {
		t.Fatalf("error %v does not match ErrSignerAddressMismatch", err)
	}
}

func TestVaultSignerRejectsASignatureThatDoesNotVerify(t *testing.T) {
	kp := vaultTestKeypair(t)
	vault := &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
		signature:  "vault:v1:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	server := newVaultServer(t, vault)

	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: kp.Address(),
	})
	if err != nil {
		t.Fatalf("NewVaultSigner returned an unexpected error: %v", err)
	}

	preimage, payload := vaultTestPreimage(t)
	if _, err := signer.Sign(context.Background(), preimage, payload); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error %v does not match ErrSignatureMismatch", err)
	}
}

func TestVaultSignerRejectsAMismatchedPayload(t *testing.T) {
	kp := vaultTestKeypair(t)
	vault := &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	}
	server := newVaultServer(t, vault)

	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: kp.Address(),
	})
	if err != nil {
		t.Fatalf("NewVaultSigner returned an unexpected error: %v", err)
	}

	preimage, _ := vaultTestPreimage(t)
	if _, err := signer.Sign(context.Background(), preimage, testPayload("not-the-preimage")); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error %v does not match ErrSignatureMismatch", err)
	}
}

func TestVaultSignerHonorsContextCancellation(t *testing.T) {
	kp := vaultTestKeypair(t)
	vault := &vaultServer{
		keyType:    "ed25519",
		privateKey: ed25519.NewKeyFromSeed(vaultTestSeed[:]),
		publicKey:  ed25519.NewKeyFromSeed(vaultTestSeed[:]).Public().(ed25519.PublicKey),
	}
	server := newVaultServer(t, vault)

	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: kp.Address(),
	})
	if err != nil {
		t.Fatalf("NewVaultSigner returned an unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	preimage, payload := vaultTestPreimage(t)
	if _, err := signer.Sign(ctx, preimage, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not match context.Canceled", err)
	}
}

func TestVaultSignerValidatesConfig(t *testing.T) {
	kp := vaultTestKeypair(t)
	valid := func() VaultConfig {
		return VaultConfig{BaseURL: "https://vault.example:8200", Token: "t", KeyName: "alice", Address: kp.Address()}
	}

	cases := []struct {
		name string
		cfg  VaultConfig
	}{
		{name: "no base url", cfg: func() VaultConfig { c := valid(); c.BaseURL = ""; return c }()},
		{name: "relative base url", cfg: func() VaultConfig { c := valid(); c.BaseURL = "vault.example"; return c }()},
		{name: "no token", cfg: func() VaultConfig { c := valid(); c.Token = ""; return c }()},
		{name: "no key name", cfg: func() VaultConfig { c := valid(); c.KeyName = ""; return c }()},
		{name: "bad address", cfg: func() VaultConfig { c := valid(); c.Address = "M..."; return c }()},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewVaultSigner(context.Background(), testCase.cfg); err == nil {
				t.Fatal("NewVaultSigner accepted an invalid config")
			}
		})
	}
}

func TestVaultSignatureDecoderRejectsGarbage(t *testing.T) {
	for _, encoded := range []string{"", "no-prefix", "vault:v1:not base64!"} {
		if _, err := decodeVaultSignature(encoded); err == nil {
			t.Errorf("decodeVaultSignature accepted %q", encoded)
		}
	}
}

// TestVaultSignerDerivesTheAccountFromTheKey pins the address derivation: the
// Stellar address is the strkey encoding of the Vault key's raw public bytes.
func TestVaultSignerDerivesTheAccountFromTheKey(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(vaultTestSeed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	want, err := strkey.Encode(strkey.VersionByteAccountID, publicKey)
	if err != nil {
		t.Fatalf("encoding the expected address: %v", err)
	}

	server := newVaultServer(t, &vaultServer{
		keyType:    "ed25519",
		privateKey: privateKey,
		publicKey:  publicKey,
	})
	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		BaseURL: server.URL, Token: "t", KeyName: "alice", Address: want,
	})
	if err != nil {
		t.Fatalf("NewVaultSigner returned an unexpected error: %v", err)
	}
	if signer.Address() != want {
		t.Errorf("Address is %q, want %q", signer.Address(), want)
	}
}

func TestLatestPublicKeySelectsTheNewestVersion(t *testing.T) {
	first := make([]byte, ed25519.PublicKeySize)
	second := make([]byte, ed25519.PublicKeySize)
	second[0] = 1
	keys := map[string]any{
		"1": base64.StdEncoding.EncodeToString(first),
		"2": base64.StdEncoding.EncodeToString(second),
	}
	got, err := latestPublicKey(keys, 0)
	if err != nil {
		t.Fatalf("latestPublicKey returned an unexpected error: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Errorf("latestPublicKey picked %x, want the newest version %x", got, second)
	}
}
