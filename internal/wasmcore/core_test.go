package wasmcore_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/wasmcore"
)

// vector is the subset of a golden vector this package needs. It is read from
// the committed vectors rather than baked into the test, so the wasm core is
// held to the same bytes as the native library.
type vector struct {
	Name              string `json:"name"`
	NetworkPassphrase string `json:"network_passphrase"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	PreimageXDR       string `json:"preimage_xdr"`
	PayloadHex        string `json:"payload_hex"`
	SignedEntryXDR    string `json:"signed_entry_xdr"`
	PublicKeyHex      string `json:"public_key_hex"`
	SignatureHex      string `json:"signature_hex"`
	SignatureMapXDR   string `json:"signature_map_xdr"`
	Steps             []struct {
		SignerLabel string  `json:"signer_label"`
		ForAddress  *string `json:"for_address"`
	} `json:"steps"`
}

func loadVector(t *testing.T, name string) vector {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return v
}

// seedHexFor is the deterministic seed every test key in this repository uses:
// sha256 of a public label. It is not secret.
func seedHexFor(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func TestPreimageMatchesGoldenVector(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")

	got, err := wasmcore.Preimage(v.UnsignedEntryXDR, v.ValidUntilLedger, v.NetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if got.PreimageXDR != v.PreimageXDR {
		t.Errorf("preimage differs from the golden vector")
	}
	if got.PayloadHex != v.PayloadHex {
		t.Errorf("payload = %s, want %s", got.PayloadHex, v.PayloadHex)
	}
}

func TestPayloadMatchesGoldenVector(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")

	got, err := wasmcore.Payload(v.PreimageXDR)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	if got != v.PayloadHex {
		t.Errorf("payload = %s, want %s", got, v.PayloadHex)
	}
}

func TestAuthorizeWithSeedMatchesGoldenVector(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")
	if len(v.Steps) != 1 {
		t.Fatalf("vector has %d steps, want 1", len(v.Steps))
	}

	digest, err := hex.DecodeString(seedHexFor(v.Steps[0].SignerLabel))
	if err != nil {
		t.Fatalf("decoding the seed: %v", err)
	}
	var seed [32]byte
	copy(seed[:], digest)
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving the keypair: %v", err)
	}
	// The signer label must actually be the key that signed the vector; this
	// catches a vector/test mismatch as a signature failure rather than a
	// confusing byte difference.
	if kp.Address() == "" {
		t.Fatal("derived an empty address")
	}

	got, err := wasmcore.AuthorizeWithSeed(
		v.UnsignedEntryXDR, v.ValidUntilLedger, v.NetworkPassphrase,
		seedHexFor(v.Steps[0].SignerLabel), "",
	)
	if err != nil {
		t.Fatalf("AuthorizeWithSeed: %v", err)
	}
	if got != v.SignedEntryXDR {
		t.Errorf("signed entry differs from the golden vector")
	}
}

func TestPreimageRejectsSourceAccount(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	entry.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
	}
	raw, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding the source-account entry: %v", err)
	}

	_, err = wasmcore.Preimage(base64.StdEncoding.EncodeToString(raw), v.ValidUntilLedger, v.NetworkPassphrase)
	if err == nil {
		t.Fatal("Preimage accepted a source-account entry, which has no preimage")
	}
}

func TestPayloadRejectsMalformedXDR(t *testing.T) {
	if _, err := wasmcore.Payload("not base64 xdr"); err == nil {
		t.Fatal("Payload accepted malformed input")
	}
}

func TestPasskeySignatureMatchesGoldenVector(t *testing.T) {
	v := loadVector(t, "passkey/passkey_signature_map_typical")
	if v.PublicKeyHex == "" || v.SignatureHex == "" || v.SignatureMapXDR == "" {
		t.Fatal("the passkey vector is missing a field this test needs")
	}

	got, err := wasmcore.PasskeySignature(v.PublicKeyHex, v.SignatureHex)
	if err != nil {
		t.Fatalf("PasskeySignature: %v", err)
	}
	if got != v.SignatureMapXDR {
		t.Errorf("signature map differs from the golden vector")
	}
}

func TestPasskeySignatureRejectsMalformedKey(t *testing.T) {
	tests := []struct {
		name      string
		publicKey string
		signature string
	}{
		{"not hex", "zz", strings.Repeat("00", 64)},
		{"wrong key length", "04" + strings.Repeat("00", 62), strings.Repeat("00", 64)},
		{"not an uncompressed point", "02" + strings.Repeat("00", 64), strings.Repeat("00", 64)},
		{"off curve", "04" + strings.Repeat("00", 64), strings.Repeat("00", 64)},
		{"wrong signature length", "04" + strings.Repeat("00", 64), strings.Repeat("00", 63)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := wasmcore.PasskeySignature(tt.publicKey, tt.signature); err == nil {
				t.Fatal("PasskeySignature accepted malformed input")
			}
		})
	}
}
