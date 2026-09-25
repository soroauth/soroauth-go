package walletsdk

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// verifyFixture signs one entry for kp through the ordinary flow and returns
// the stored entry and the envelope it lives in, so the verification tests
// check signatures that were produced the way a wallet produces them.
func verifyFixture(t *testing.T, kp Keypair) (xdr.SorobanAuthorizationEntry, xdr.TransactionEnvelope) {
	t.Helper()
	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 5)))
	_, submittable := signOnce(t, env, kp)
	return entryOf(t, submittable), submittable
}

// tamperSignature flips a byte of the signature stored on an entry, leaving the
// public key alone. That is the shape of a damaged signature: still in the
// built-in account signature form, still naming the right key, and no longer a
// signature over the entry.
func tamperSignature(t *testing.T, entry xdr.SorobanAuthorizationEntry) xdr.SorobanAuthorizationEntry {
	t.Helper()

	damaged := reencode(t, entry)
	credentials := damaged.Credentials.AddressV2
	if credentials == nil {
		t.Fatal("the entry is not on the address_v2 arm")
	}

	values := **credentials.Signature.Vec
	if len(values) != 1 {
		t.Fatalf("the stored signature holds %d entries, want 1", len(values))
	}
	for _, field := range **values[0].Map {
		if field.Key.Sym != nil && string(*field.Key.Sym) == "signature" {
			(*field.Val.Bytes)[0] ^= 0xff
			return damaged
		}
	}

	t.Fatal("the stored signature has no signature field")
	return xdr.SorobanAuthorizationEntry{}
}

func TestVerifyEntryAcceptsItsOwnSignature(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-ok")
	entry, _ := verifyFixture(t, kp)

	if err := VerifyEntry(entry, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}

	// A key the entry never names has nothing to verify here: the entry is not
	// refusing it, it simply is not one of the signers it asks for.
	stranger := testKeypair(t, "walletsdk-verify-ok-stranger")
	err := VerifyEntry(entry, stranger, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, ErrSignatureNotFound) {
		t.Errorf("got %v, want it to wrap %v", err, ErrSignatureNotFound)
	}
}

// TestVerifyEntryCommitsToTheExpiration pins the reading that matters most for
// a wallet: the expiration ledger is inside the payload the signature covers,
// so verifying against a different ledger is not a laxer check, it is a
// different question. This is the host's clock, and it is a different one from
// any window a contract enforces for itself.
func TestVerifyEntryCommitsToTheExpiration(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-expiration")
	entry, _ := verifyFixture(t, kp)

	err := VerifyEntry(entry, kp, testValidUntilLedger+1, testPassphrase)
	if !errors.Is(err, ErrSignatureNotByKey) {
		t.Fatalf("verifying against another expiration: got %v, want it to wrap %v", err, ErrSignatureNotByKey)
	}
}

func TestVerifyEntryRefusesADamagedSignature(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-damaged")
	entry, _ := verifyFixture(t, kp)

	err := VerifyEntry(tamperSignature(t, entry), kp, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, ErrSignatureNotByKey) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrSignatureNotByKey)
	}

	// The untouched entry still verifies, so the tampering is what was caught.
	if err := VerifyEntry(entry, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("the untampered entry does not verify: %v", err)
	}
}

// TestVerifyEntryRefusesASignatureFromAnotherKey covers the check that makes
// verification independent of soroauth. ForAddress legitimately lets one key
// sign onto another address's node — that is how the delegates arm works — so a
// node naming an address is not evidence that the address signed it. The stored
// public key has to be compared, and this proves it is.
func TestVerifyEntryRefusesASignatureFromAnotherKey(t *testing.T) {
	target := testKeypair(t, "walletsdk-verify-target")
	writer := testKeypair(t, "walletsdk-verify-writer")

	forged, err := soroauth.AuthorizeEntry(context.Background(),
		testEntry(t, target.Address(), 9),
		soroauth.NewEd25519Signer(writer), testValidUntilLedger, testPassphrase,
		soroauth.ForAddress(target.Address()))
	if err != nil {
		t.Fatalf("AuthorizeEntry with ForAddress: %v", err)
	}

	err = VerifyEntry(forged, target, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, ErrSignatureNotByKey) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrSignatureNotByKey)
	}
}

func TestVerifyEntryRefusals(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-refusals")
	entry, _ := verifyFixture(t, kp)

	tests := []struct {
		name      string
		entry     xdr.SorobanAuthorizationEntry
		kp        Keypair
		wantIs    error
		wantInErr string
	}{
		{
			name:      "an unsigned entry",
			entry:     testEntry(t, kp.Address(), 4),
			kp:        kp,
			wantIs:    ErrUnreadableSignature,
			wantInErr: "ScValTypeScvVoid",
		},
		{
			name:   "a source-account entry",
			entry:  testSourceAccountEntry(t),
			kp:     kp,
			wantIs: soroauth.ErrSourceAccountCredentials,
		},
		{
			name:   "no keypair at all",
			entry:  entry,
			kp:     nil,
			wantIs: soroauth.ErrMissingSigner,
		},
		{
			name:   "a keypair whose address is not an account",
			entry:  entry,
			kp:     stubKeypair{address: testContractAddress(t, "walletsdk-verify-not-an-account")},
			wantIs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyEntry(tt.entry, tt.kp, testValidUntilLedger, testPassphrase)
			if err == nil {
				t.Fatal("VerifyEntry accepted something it should have refused")
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

// TestVerifyEnvelopeSkipsWhatItCannotCheck covers the two arms VerifyEnvelope
// deliberately passes over: a source-account entry, which the envelope's own
// signature covers and which has no payload of its own, and an entry naming no
// node for the key, which is somebody else's to sign.
func TestVerifyEnvelopeSkipsWhatItCannotCheck(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-skip")
	other := testKeypair(t, "walletsdk-verify-skip-other")

	env := testEnvelope(t, invokeOperation(t,
		testSourceAccountEntry(t),
		testEntry(t, other.Address(), 1),
	))

	if err := VerifyEnvelope(env, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("VerifyEnvelope over entries that are not this key's: %v", err)
	}
}

// TestVerifyEnvelopeFailsClosedOnAnUnsignedEntry is the case a wallet actually
// needs to catch: an entry it is supposed to have signed, submitted without the
// signature. It must not be mistaken for somebody else's entry.
func TestVerifyEnvelopeFailsClosedOnAnUnsignedEntry(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-unsigned-envelope")
	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 1)))

	err := VerifyEnvelope(env, kp, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, ErrUnreadableSignature) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrUnreadableSignature)
	}
}

// TestVerifyEnvelopeNamesWhereAFailureIs checks the message, because it is what
// a wallet has to put in front of a user.
func TestVerifyEnvelopeNamesWhereAFailureIs(t *testing.T) {
	kp := testKeypair(t, "walletsdk-verify-damaged-envelope")
	entry, _ := verifyFixture(t, kp)
	env := testEnvelope(t, paymentOperation(t), invokeOperation(t, tamperSignature(t, entry)))

	err := VerifyEnvelope(env, kp, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, ErrSignatureNotByKey) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrSignatureNotByKey)
	}
	if !strings.Contains(err.Error(), "operation 1 entry 0") {
		t.Errorf("the error %q does not say which entry the damaged signature is on", err)
	}
}
