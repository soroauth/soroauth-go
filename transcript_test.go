package soroauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// transcriptEntry builds a delegates-arm entry with a top-level account and two
// nested credential nodes.
func transcriptEntry(t *testing.T, top, first, second *keypair.Full) xdr.SorobanAuthorizationEntry {
	t.Helper()
	topAddress, err := ParseAddress(top.Address())
	if err != nil {
		t.Fatalf("ParseAddress(top): %v", err)
	}
	firstAddress, err := ParseAddress(first.Address())
	if err != nil {
		t.Fatalf("ParseAddress(first): %v", err)
	}
	secondAddress, err := ParseAddress(second.Address())
	if err != nil {
		t.Fatalf("ParseAddress(second): %v", err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   topAddress,
					Nonce:                     7,
					SignatureExpirationLedger: 1234,
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: []xdr.SorobanDelegateSignature{
					{
						Address:   firstAddress,
						Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
						NestedDelegates: []xdr.SorobanDelegateSignature{{
							Address:   secondAddress,
							Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
						}},
					},
				},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &xdr.ContractId{9},
					},
					FunctionName: xdr.ScSymbol("transfer"),
					Args:         []xdr.ScVal{},
				},
			},
		},
	}
}

func TestCoordinatorProducesSignedTranscript(t *testing.T) {
	top := testKeypair(t, "transcript-top")
	first := testKeypair(t, "transcript-first")
	second := testKeypair(t, "transcript-second")
	coordinator := testKeypair(t, "transcript-coordinator")

	entry := transcriptEntry(t, top, first, second)
	coord, err := NewCoordinator(entry, 1234, network.TestNetworkPassphrase,
		WithSessionTranscript(coordinator))
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	ctx := context.Background()
	for _, step := range []struct {
		address string
		signer  *keypair.Full
	}{
		{top.Address(), top},
		{first.Address(), first},
		{second.Address(), second},
	} {
		if err := coord.Record(ctx, step.address, NewEd25519Signer(step.signer)); err != nil {
			t.Fatalf("Record(%s): %v", step.address, err)
		}
	}

	transcript, ok := coord.FinalizedTranscript()
	if !ok {
		t.Fatal("the completed session produced no transcript")
	}
	if transcript.Outcome != SessionOutcomeComplete {
		t.Fatalf("outcome = %q, want complete", transcript.Outcome)
	}
	if transcript.FailureReason != "" {
		t.Fatalf("a complete transcript carries a reason: %q", transcript.FailureReason)
	}
	if len(transcript.Rounds) != 3 {
		t.Fatalf("rounds = %d, want 3", len(transcript.Rounds))
	}
	for i, round := range transcript.Rounds {
		if round.Round != i+1 {
			t.Errorf("round %d is numbered %d", i, round.Round)
		}
	}
	if len(transcript.Participants) != 3 {
		t.Fatalf("participants = %v, want the three credential nodes", transcript.Participants)
	}
	if len(transcript.PayloadHash) != 64 {
		t.Fatalf("payload hash = %q, want 32 bytes of hex", transcript.PayloadHash)
	}
	if len(transcript.AuditRecords) != 3 {
		t.Fatalf("audit records = %d, want one per round", len(transcript.AuditRecords))
	}
	if transcript.CoordinatorPublicKey == "" || transcript.Signature == "" {
		t.Fatal("the transcript is not signed")
	}

	// Verification needs only the transcript.
	if err := VerifyTranscript(transcript); err != nil {
		t.Fatalf("VerifyTranscript: %v", err)
	}
}

func TestTranscriptVerificationCatchesTampering(t *testing.T) {
	top := testKeypair(t, "transcript-tamper-top")
	coordinator := testKeypair(t, "transcript-tamper-coordinator")
	entry := transcriptEntry(t, top, testKeypair(t, "transcript-tamper-a"), testKeypair(t, "transcript-tamper-b"))

	recorder, err := NewTranscriptRecorder(TranscriptConfig{
		Entry:             entry,
		ValidUntilLedger:  1234,
		NetworkPassphrase: network.TestNetworkPassphrase,
		Coordinator:       coordinator,
	})
	if err != nil {
		t.Fatalf("NewTranscriptRecorder: %v", err)
	}
	if err := recorder.RecordRound([]string{top.Address()}, 1, 3); err != nil {
		t.Fatalf("RecordRound: %v", err)
	}
	transcript, err := recorder.Abort("operator cancelled the ceremony")
	if err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := VerifyTranscript(transcript); err != nil {
		t.Fatalf("VerifyTranscript (honest): %v", err)
	}

	tampered := transcript
	tampered.PayloadHash = strings.Repeat("0", 64)
	if err := VerifyTranscript(tampered); !errors.Is(err, ErrTranscriptVerification) {
		t.Fatalf("tampered payload hash = %v, want ErrTranscriptVerification", err)
	}

	tampered = transcript
	tampered.Rounds[0].Signers = []string{"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"}
	if err := VerifyTranscript(tampered); !errors.Is(err, ErrTranscriptVerification) {
		t.Fatalf("tampered round = %v, want ErrTranscriptVerification", err)
	}

	tampered = transcript
	tampered.CoordinatorPublicKey = strings.Repeat("00", 32)
	if err := VerifyTranscript(tampered); !errors.Is(err, ErrTranscriptVerification) {
		t.Fatalf("tampered public key = %v, want ErrTranscriptVerification", err)
	}

	if _, err := recorder.Abort("again"); err != nil {
		t.Fatalf("second Abort returned an error instead of the signed transcript: %v", err)
	}
}

func TestCoordinatorFailedSessionProducesTranscript(t *testing.T) {
	top := testKeypair(t, "transcript-fail-top")
	coordinator := testKeypair(t, "transcript-fail-coordinator")
	entry := transcriptEntry(t, top, testKeypair(t, "transcript-fail-a"), testKeypair(t, "transcript-fail-b"))
	outsider := testKeypair(t, "transcript-fail-outsider")

	coord, err := NewCoordinator(entry, 1234, network.TestNetworkPassphrase,
		WithSessionTranscript(coordinator))
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	err = coord.Record(context.Background(), outsider.Address(), NewEd25519Signer(outsider))
	if err == nil {
		t.Fatal("a target outside the tree was accepted")
	}
	transcript, ok := coord.FinalizedTranscript()
	if !ok {
		t.Fatal("the failed session produced no transcript")
	}
	if transcript.Outcome != SessionOutcomeFailed {
		t.Fatalf("outcome = %q, want failed", transcript.Outcome)
	}
	if !strings.Contains(transcript.FailureReason, "no credential node matches") {
		t.Fatalf("failure reason = %q", transcript.FailureReason)
	}
	if err := VerifyTranscript(transcript); err != nil {
		t.Fatalf("VerifyTranscript (failed session): %v", err)
	}
}

func TestCoordinatorAbortTranscript(t *testing.T) {
	top := testKeypair(t, "transcript-abort-top")
	coordinator := testKeypair(t, "transcript-abort-coordinator")
	entry := transcriptEntry(t, top, testKeypair(t, "transcript-abort-a"), testKeypair(t, "transcript-abort-b"))

	coord, err := NewCoordinator(entry, 1234, network.TestNetworkPassphrase,
		WithSessionTranscript(coordinator))
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	if err := coord.AbortTranscript(""); err == nil {
		t.Fatal("an abort with no reason was accepted")
	}
	if err := coord.AbortTranscript("operator cancelled"); err != nil {
		t.Fatalf("AbortTranscript: %v", err)
	}
	transcript, ok := coord.FinalizedTranscript()
	if !ok {
		t.Fatal("no transcript after abort")
	}
	if transcript.Outcome != SessionOutcomeAborted || transcript.FailureReason != "operator cancelled" {
		t.Fatalf("transcript = %+v", transcript)
	}
	if err := VerifyTranscript(transcript); err != nil {
		t.Fatalf("VerifyTranscript: %v", err)
	}

	// A coordinator without a recorder refuses rather than fabricating one.
	bare, err := NewCoordinator(entry, 1234, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	if err := bare.AbortTranscript("no recorder"); err == nil {
		t.Fatal("AbortTranscript succeeded without a transcript recorder")
	}
}

func TestTranscriptContainsNoSecretMaterial(t *testing.T) {
	top := testKeypair(t, "transcript-secret-top")
	first := testKeypair(t, "transcript-secret-first")
	second := testKeypair(t, "transcript-secret-second")
	coordinator := testKeypair(t, "transcript-secret-coordinator")

	entry := transcriptEntry(t, top, first, second)
	coord, err := NewCoordinator(entry, 1234, network.TestNetworkPassphrase,
		WithSessionTranscript(coordinator))
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	ctx := context.Background()
	for _, step := range []struct {
		address string
		signer  *keypair.Full
	}{
		{top.Address(), top},
		{first.Address(), first},
		{second.Address(), second},
	} {
		if err := coord.Record(ctx, step.address, NewEd25519Signer(step.signer)); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	transcript, ok := coord.FinalizedTranscript()
	if !ok {
		t.Fatal("no transcript")
	}

	encoded, err := json.Marshal(transcript)
	if err != nil {
		t.Fatalf("marshalling the transcript: %v", err)
	}
	for _, secret := range []string{top.Seed(), first.Seed(), second.Seed(), coordinator.Seed()} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("a secret seed appears in the transcript")
		}
	}

	// The transcript must also not smuggle a signature share or a raw entry.
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}
	if strings.Contains(string(encoded), string(entryBytes)) {
		t.Fatal("the transcript contains the entry bytes")
	}
	if transcript.EntryHash == "" || transcript.EntryHash == transcript.PayloadHash {
		t.Fatal("the entry hash is missing or duplicated the payload hash")
	}

	// Timestamps are real, ordered UTC values rather than zero values.
	if transcript.StartedAt.IsZero() || transcript.FinishedAt.IsZero() {
		t.Fatal("the transcript has no timestamps")
	}
	if transcript.FinishedAt.Before(transcript.StartedAt) || transcript.StartedAt.Location() != time.UTC {
		t.Fatal("the transcript timestamps are not ordered UTC values")
	}
}
