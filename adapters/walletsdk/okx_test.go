package walletsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	okxkeypair "github.com/okx/go-wallet-sdk/coins/stellar/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/soroauth/soroauth-go"
)

// TestOKXKeypairEndToEnd is the worked integration: a keypair from
// github.com/okx/go-wallet-sdk taken through the whole adapter, from "what does
// this envelope want from me?" to a signature the standard library confirms is
// a genuine ed25519 signature over the entry's payload.
//
// The key comes from the SDK's own Random rather than a fixed seed, so the path
// a wallet actually walks — generate a key, get its address, sign, verify — is
// the path under test.
func TestOKXKeypairEndToEnd(t *testing.T) {
	kp, err := okxkeypair.Random()
	if err != nil {
		t.Fatalf("okxkeypair.Random: %v", err)
	}

	signer, err := FromOKXKeypair(kp)
	if err != nil {
		t.Fatalf("FromOKXKeypair: %v", err)
	}
	if signer.Address() != kp.Address() {
		t.Fatalf("the signer reports %s, the keypair says %s", signer.Address(), kp.Address())
	}
	if _, err := strkey.Decode(strkey.VersionByteAccountID, kp.Address()); err != nil {
		t.Fatalf("the SDK produced an address that is not an account address: %v", err)
	}

	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 7)))

	// What does this envelope want from me?
	requirements, err := Requirements(env, kp.Address())
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if len(requirements) != 1 {
		t.Fatalf("Requirements reported %d entries, want 1", len(requirements))
	}
	if !requirements[0].Wanted || requirements[0].Signed {
		t.Fatalf("Requirements reported wanted=%v signed=%v, want an entry this key is wanted for and has not signed",
			requirements[0].Wanted, requirements[0].Signed)
	}

	// Sign it, and record the enforce pass before taking the envelope. A wallet
	// that skips the second simulation pass gets a fee error, not a signature
	// error, so the adapter will not produce the envelope without being told.
	signed, err := Sign(context.Background(), env, kp, testValidUntilLedger, testPassphrase)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := signed.Envelope(); !errors.Is(err, ErrEnforcePassMissing) {
		t.Fatalf("the envelope was handed out before the enforce pass: got %v", err)
	}
	signed.MarkEnforced()
	submittable, err := signed.Envelope()
	if err != nil {
		t.Fatalf("Envelope: %v", err)
	}

	// Verify what was written, twice over: through the adapter, and against the
	// standard library. The second check is the one that says the bytes are a
	// real signature rather than a shape the adapter agrees with itself about.
	if err := VerifyEnvelope(submittable, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}

	entry := entryOf(t, submittable)
	preimage, err := soroauth.Preimage(entry, testValidUntilLedger, testPassphrase)
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}

	nodes, err := signatureNodes(entry, kp.Address())
	if err != nil {
		t.Fatalf("signatureNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("the signed entry carries %d nodes for this address, want 1", len(nodes))
	}
	publicKey, signature, err := parseAccountSignature(nodes[0])
	if err != nil {
		t.Fatalf("parseAccountSignature: %v", err)
	}

	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	if !bytes.Equal(publicKey, raw) {
		t.Error("the stored public key is not the one the address carries")
	}
	if !ed25519.Verify(publicKey, payload[:], signature) {
		t.Error("the stored signature is not a valid ed25519 signature over the entry's payload")
	}

	// And the to-do list is now empty for this key.
	after, err := Requirements(submittable, kp.Address())
	if err != nil {
		t.Fatalf("Requirements after signing: %v", err)
	}
	if !after[0].Signed {
		t.Error("the signed entry is still reported as unsigned")
	}
}

func TestFromOKXKeypairRefusesNil(t *testing.T) {
	if signer, err := FromOKXKeypair(nil); !errors.Is(err, soroauth.ErrMissingSigner) {
		t.Fatalf("got %v, want it to wrap %v", err, soroauth.ErrMissingSigner)
	} else if signer != nil {
		t.Error("a nil keypair produced a signer")
	}
}

// TestRootModuleStaysFreeOfWalletSDKs is an acceptance criterion as a test
// rather than a promise: the adapter must not pull a wallet SDK into the root
// module. The adapter lives in its own module precisely so that importing
// soroauth never drags one along, and this reads the root module's own files to
// say that the boundary is still there.
func TestRootModuleStaysFreeOfWalletSDKs(t *testing.T) {
	forbidden := []string{"okx", "wallet"}

	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("reading the root go.mod: %v", err)
	}
	for _, line := range strings.Split(string(mod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := strings.ToLower(fields[0])
		for _, bad := range forbidden {
			if strings.Contains(path, bad) {
				t.Errorf("the root go.mod requires %q, which looks like a wallet SDK; the root module must stay free of one",
					fields[0])
			}
		}
	}

	sum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatalf("reading the root go.sum: %v", err)
	}
	if strings.Contains(strings.ToLower(string(sum)), "okx") {
		t.Error("the root go.sum records the OKX wallet SDK; the root module must stay free of one")
	}
}
