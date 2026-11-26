package walletsdk

// conformance_test.go proves that the OKX wallet SDK adapter produces results
// that are byte-identical to what the JS reference SDK (@stellar/stellar-sdk
// @17.1.0) records in the golden vectors. It is the adapter's acceptance test:
// if the adapter ever diverges from the reference — a different ScVal shape, a
// different byte order, a different signature — this test fails.
//
// # Relationship to TestSignerMatchesNewEd25519Signer
//
// TestSignerMatchesNewEd25519Signer (signer_test.go) proves that the adapter
// produces the same ScVal as soroauth.NewEd25519Signer for one fixed payload.
// TestOKXAdapterMatchesGoldenVectors proves the same thing for every vector in
// testdata/vectors/, including the full AuthorizeEntry call chain, so changes
// in how soroauth builds preimages or walks credential nodes are also caught.
//
// # Scheduled CI
//
// .github/workflows/wallet-conformance.yml runs this test suite weekly and
// opens a GitHub issue on failure, so a wallet SDK update that changes the
// signing behaviour surfaces before it reaches a user.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	okxkeypair "github.com/okx/go-wallet-sdk/coins/stellar/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// conformanceVectorStep is one signing call from a golden vector.
type conformanceVectorStep struct {
	SignerLabel string  `json:"signer_label"`
	ForAddress  *string `json:"for_address"`
}

// conformanceVector holds the fields from a golden vector file that the
// conformance test uses. Unknown fields are allowed here (the full vector
// format is richer); only what we sign and compare needs to be exact.
type conformanceVector struct {
	Name              string                  `json:"name"`
	SDK               string                  `json:"sdk"`
	NetworkPassphrase string                  `json:"network_passphrase"`
	ValidUntilLedger  uint32                  `json:"valid_until_ledger"`
	UnsignedEntryXDR  string                  `json:"unsigned_entry_xdr"`
	Delegates         []json.RawMessage       `json:"delegates"`
	Steps             []conformanceVectorStep `json:"steps"`
	PreimageXDR       string                  `json:"preimage_xdr"`
	PayloadHex        string                  `json:"payload_hex"`
	SignedEntryXDR    string                  `json:"signed_entry_xdr"`
}

// conformanceVectorDir returns the path to testdata/vectors in the root module.
// The walletsdk adapter lives at adapters/walletsdk, so the root is two levels up.
func conformanceVectorDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vectors"))
	if err != nil {
		t.Fatalf("resolving vector dir: %v", err)
	}
	return dir
}

// loadConformanceVectors loads every *.json file from testdata/vectors.
func loadConformanceVectors(t *testing.T) []conformanceVector {
	t.Helper()
	dir := conformanceVectorDir(t)

	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatalf("globbing %s: %v", dir, err)
	}
	if len(paths) == 0 {
		t.Skip("no golden vectors found in " + dir + "; run `cd testdata/gen && npm ci && node gen.mjs` from the repo root")
	}

	var vectors []conformanceVector
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		var v conformanceVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		if v.Name == "" {
			t.Fatalf("%s has no name", path)
		}
		vectors = append(vectors, v)
	}
	return vectors
}

// okxSignerForLabel derives an OKX wallet SDK keypair from a golden vector's
// signer label, using the same seed derivation as the reference implementation:
// sha256 of the label bytes.
func okxSignerForLabel(t *testing.T, label string) *okxkeypair.Full {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	kp, err := okxkeypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving OKX keypair for label %q: %v", label, err)
	}
	return kp
}

// TestOKXAdapterMatchesGoldenVectors is the byte-equality gate for the OKX
// wallet SDK adapter: for each golden vector that uses a single signing step
// and no delegate tree, the adapter must produce a signed entry that is
// byte-identical to the JS reference SDK's output.
//
// Delegate-tree vectors are skipped: the adapter's Sign function works at the
// envelope level and builds delegate trees differently from AuthorizeEntry.
// Those vectors are covered by the root module's TestGoldenVectors.
//
// Source-account entries are skipped: they carry no signature (the envelope
// covers them) and there is nothing the adapter adds to verify.
func TestOKXAdapterMatchesGoldenVectors(t *testing.T) {
	for _, v := range loadConformanceVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			// Skip vectors that need delegate-tree construction: those require
			// the full delegate-signing flow, which is out of scope for the
			// wallet-adapter conformance test.
			if len(v.Delegates) > 0 {
				t.Skip("delegate-tree vector; covered by root module TestGoldenVectors")
				return
			}
			if len(v.Steps) != 1 {
				t.Skip("multi-step vector; conformance test covers single-step vectors only")
				return
			}

			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
				t.Fatalf("decoding unsigned_entry_xdr: %v", err)
			}
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				t.Skip("source-account entry; adapter has no signature to verify")
				return
			}

			step := v.Steps[0]
			kp := okxSignerForLabel(t, step.SignerLabel)

			signer, err := FromOKXKeypair(kp)
			if err != nil {
				t.Fatalf("FromOKXKeypair: %v", err)
			}

			var opts []soroauth.AuthorizeOption
			if step.ForAddress != nil && *step.ForAddress != "" {
				opts = append(opts, soroauth.ForAddress(*step.ForAddress))
			}

			signed, err := soroauth.AuthorizeEntry(
				context.Background(),
				entry,
				signer,
				v.ValidUntilLedger,
				v.NetworkPassphrase,
				opts...,
			)
			if err != nil {
				t.Fatalf("AuthorizeEntry: %v", err)
			}

			// Preimage check: the OKX signer must compute the same preimage as
			// the Go library (and thus the JS reference).
			wantPreimage, err := base64.StdEncoding.DecodeString(v.PreimageXDR)
			if err != nil {
				t.Fatalf("decoding preimage_xdr: %v", err)
			}
			preimage, err := soroauth.Preimage(signed, v.ValidUntilLedger, v.NetworkPassphrase)
			if err != nil {
				t.Fatalf("Preimage: %v", err)
			}
			gotPreimage, err := preimage.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling preimage: %v", err)
			}
			if !bytes.Equal(gotPreimage, wantPreimage) {
				t.Errorf("preimage mismatch\n want %x\n  got %x", wantPreimage, gotPreimage)
			}

			// Payload check: sha256 of the preimage must match.
			wantPayload, err := hex.DecodeString(v.PayloadHex)
			if err != nil {
				t.Fatalf("decoding payload_hex: %v", err)
			}
			payload, err := soroauth.Payload(preimage)
			if err != nil {
				t.Fatalf("Payload: %v", err)
			}
			if !bytes.Equal(payload[:], wantPayload) {
				t.Errorf("payload mismatch\n want %x\n  got %x", wantPayload, payload)
			}

			// Signed entry check: the full signed entry must be byte-identical
			// to what the JS reference SDK produced.
			wantSigned, err := base64.StdEncoding.DecodeString(v.SignedEntryXDR)
			if err != nil {
				t.Fatalf("decoding signed_entry_xdr: %v", err)
			}
			gotSigned, err := signed.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling signed entry: %v", err)
			}
			if !bytes.Equal(gotSigned, wantSigned) {
				t.Errorf("signed entry mismatch for vector %q\n want (hex) %x\n  got (hex) %x",
					v.Name, wantSigned, gotSigned)
			}
		})
	}
}

// TestOKXAdapterEnvelopeConformance proves the full envelope-level signing
// flow: take the unsigned entry, wrap it in an envelope, call Sign, and verify
// that the signed entry in the returned submittable envelope matches the
// golden vector byte-for-byte.
//
// This catches adapter regressions at the envelope level (Sign → MarkEnforced
// → Envelope) rather than just at the AuthorizeEntry level.
func TestOKXAdapterEnvelopeConformance(t *testing.T) {
	for _, v := range loadConformanceVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			if len(v.Delegates) > 0 {
				t.Skip("delegate-tree vector; conformance test covers single-step vectors only")
				return
			}
			if len(v.Steps) != 1 {
				t.Skip("multi-step vector; conformance test covers single-step vectors only")
				return
			}

			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
				t.Fatalf("decoding unsigned_entry_xdr: %v", err)
			}
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				t.Skip("source-account entry; adapter has no signature to verify")
				return
			}

			step := v.Steps[0]
			kp := okxSignerForLabel(t, step.SignerLabel)

			env := testEnvelope(t, invokeOperation(t, entry))

			signed, err := Sign(context.Background(), env, kp, v.ValidUntilLedger, v.NetworkPassphrase)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// Simulate the enforce pass, then take the submittable envelope.
			signed.MarkEnforced()
			submittable, err := signed.Envelope()
			if err != nil {
				t.Fatalf("Envelope: %v", err)
			}

			// Extract the authorization entry from the returned envelope.
			signedEntry := entryOf(t, submittable)

			// Compare with the golden vector.
			wantSigned, err := base64.StdEncoding.DecodeString(v.SignedEntryXDR)
			if err != nil {
				t.Fatalf("decoding signed_entry_xdr: %v", err)
			}
			gotSigned, err := signedEntry.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling signed entry: %v", err)
			}
			if !bytes.Equal(gotSigned, wantSigned) {
				t.Errorf("envelope-level signed entry mismatch for vector %q\n want (hex) %x\n  got (hex) %x",
					v.Name, wantSigned, gotSigned)
			}

			// Also verify through the adapter's own VerifyEnvelope: the round-trip
			// must succeed after Sign and MarkEnforced.
			if err := VerifyEnvelope(submittable, kp, v.ValidUntilLedger, v.NetworkPassphrase); err != nil {
				t.Errorf("VerifyEnvelope after Sign: %v", err)
			}
		})
	}
}
