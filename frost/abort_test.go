package frost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/frost"
)

// abortTestGroup builds a group and its participants in identifier order.
func abortTestGroup(t *testing.T, threshold, maxSigners int) (*FROSTCoordinator, []byte, [][]byte, []*FROSTParticipant) {
	t.Helper()

	secretShares, verificationKey, publicKeyShares, err := TrustedDealerKeygen(threshold, maxSigners)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}
	coord, err := NewFROSTCoordinator(verificationKey, publicKeyShares, threshold, maxSigners,
		testAddress(t, "policy-test-abort"))
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participants := make([]*FROSTParticipant, maxSigners)
	for i := range participants {
		participants[i], err = NewFROSTParticipant(secretShares[i], publicKeyShares[i], uint16(i+1), coord)
		if err != nil {
			t.Fatalf("NewFROSTParticipant %d: %v", i+1, err)
		}
	}
	return coord, verificationKey, publicKeyShares, participants
}

func abortBeginRound(t *testing.T, coord *FROSTCoordinator, payload [32]byte) int64 {
	t.Helper()
	round, err := coord.Begin(context.Background(), payload)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return round
}

func abortCommitAll(t *testing.T, participants []*FROSTParticipant, round int64) {
	t.Helper()
	for _, p := range participants {
		if _, err := p.Commit(context.Background(), round); err != nil {
			t.Fatalf("participant %d Commit: %v", p.ID(), err)
		}
	}
}

// abortMutateShare flips one scalar bit so the share no longer satisfies the
// verification equation while remaining a decodable scalar.
func abortMutateShare(t *testing.T, coord *FROSTCoordinator, share *frost.SignatureShare) *frost.SignatureShare {
	t.Helper()
	encoded := share.SignatureShare.Encode()
	encoded[0] ^= 0x01
	scalar := coord.cfg.Ciphersuite.Group().NewScalar()
	if err := scalar.Decode(encoded); err != nil {
		t.Fatalf("decoding the mutated scalar: %v", err)
	}
	return &frost.SignatureShare{
		SignatureShare:   scalar,
		SignerIdentifier: share.SignerIdentifier,
		Group:            share.Group,
	}
}

func abortErrorsAsContribution(t *testing.T, err error) *ContributionError {
	t.Helper()
	var contributionErr *ContributionError
	if !errors.As(err, &contributionErr) {
		t.Fatalf("errors.As(*ContributionError) = false for %v", err)
	}
	if contributionErr.Evidence == nil {
		t.Fatal("ContributionError carries no evidence")
	}
	return contributionErr
}

// TestInvalidSignatureShareNamesTheSender proves a failing share produces an
// accusation against its authenticated sender, that the evidence re-checks
// without the coordinator, and that the round cannot go on to produce a
// signature after an attributable failure.
func TestInvalidSignatureShareNamesTheSender(t *testing.T) {
	coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0xab, 0xcd}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)

	commitments, err := coord.GetCommitments(round)
	if err != nil {
		t.Fatalf("GetCommitments: %v", err)
	}
	validShare, err := participants[1].signer.Sign(payload[:], commitments)
	if err != nil {
		t.Fatalf("producing participant 2's share: %v", err)
	}
	badShare := abortMutateShare(t, coord, validShare)

	_, err = coord.AddSignatureShare(context.Background(), round, 2, badShare)
	if err == nil {
		t.Fatal("expected the invalid share to be rejected")
	}
	if !errors.Is(err, ErrContributionInvalid) {
		t.Fatalf("errors.Is(err, ErrContributionInvalid) = false: %v", err)
	}
	if errors.Is(err, ErrParticipantUnavailable) {
		t.Fatalf("an invalid share must not be reported as unavailable: %v", err)
	}
	contributionErr := abortErrorsAsContribution(t, err)
	if contributionErr.Participant != 2 {
		t.Errorf("accused participant = %d, want 2", contributionErr.Participant)
	}
	if contributionErr.Reason != AbortReasonSignatureShareInvalid {
		t.Errorf("reason = %q, want %q", contributionErr.Reason, AbortReasonSignatureShareInvalid)
	}
	if !strings.Contains(err.Error(), "participant 2") {
		t.Errorf("error %q does not name participant 2", err)
	}

	// A third party with only public group data reproduces the verdict.
	if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
		t.Fatalf("VerifyAbortEvidence: %v", err)
	}

	// Swapping in the valid share makes the accusation false: the verifier
	// must refuse it rather than repeat it.
	falseEvidence := *contributionErr.Evidence
	falseEvidence.Contribution = validShare.Encode()
	if err := VerifyAbortEvidence(&falseEvidence, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("false accusation: errors.Is(err, ErrInvalidAbortEvidence) = false: %v", err)
	}

	// The round is poisoned: GetSignature returns the same accusation, and
	// IsComplete stays false even if enough other shares were collected.
	if _, err := coord.GetSignature(round); !errors.Is(err, ErrContributionInvalid) {
		t.Errorf("GetSignature after abort = %v, want ErrContributionInvalid", err)
	}
	if coord.IsComplete(round) {
		t.Error("IsComplete = true after an attributable failure")
	}
}

// TestCraftedIdentifierCannotFrameAnotherParticipant is the anti-framing test.
// Participant 2 sends contributions whose embedded identifier is participant
// 1's. The accusation must name participant 2 every time, and participant 1
// must still be able to complete a fresh round.
func TestCraftedIdentifierCannotFrameAnotherParticipant(t *testing.T) {
	t.Run("commitment", func(t *testing.T) {
		coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
		payload := [32]byte{0x11}
		round := abortBeginRound(t, coord, payload)

		sender := participants[1] // ID 2
		victim := participants[0] // ID 1
		crafted := sender.signer.Commit()
		crafted.SignerID = victim.ID()

		err := coord.AddCommitment(context.Background(), round, sender.ID(), crafted)
		if err == nil {
			t.Fatal("expected the mislabelled commitment to be rejected")
		}
		contributionErr := abortErrorsAsContribution(t, err)
		if contributionErr.Participant != sender.ID() {
			t.Errorf("accused participant = %d, want the sender %d", contributionErr.Participant, sender.ID())
		}
		if contributionErr.Participant == victim.ID() {
			t.Error("the sender framed the victim: the accusation names participant 1")
		}
		if contributionErr.Evidence.ClaimedParticipant != victim.ID() {
			t.Errorf("claimed participant = %d, want %d", contributionErr.Evidence.ClaimedParticipant, victim.ID())
		}
		if contributionErr.Reason != AbortReasonIdentifierMismatch {
			t.Errorf("reason = %q, want %q", contributionErr.Reason, AbortReasonIdentifierMismatch)
		}
		if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
			t.Fatalf("VerifyAbortEvidence: %v", err)
		}

		// The victim is unharmed: a fresh round excluding the sender
		// completes with participants 1 and 3.
		round = abortBeginRound(t, coord, payload)
		if _, err := victim.Commit(context.Background(), round); err != nil {
			t.Fatalf("victim Commit: %v", err)
		}
		if _, err := participants[2].Commit(context.Background(), round); err != nil {
			t.Fatalf("participant 3 Commit: %v", err)
		}
		if _, err := victim.Sign(context.Background(), round); err != nil {
			t.Fatalf("victim Sign: %v", err)
		}
		if _, err := participants[2].Sign(context.Background(), round); err != nil {
			t.Fatalf("participant 3 Sign: %v", err)
		}
		sig, err := coord.GetSignature(round)
		if err != nil {
			t.Fatalf("GetSignature: %v", err)
		}
		if err := VerifySignature(verificationKey, payload[:], sig); err != nil {
			t.Fatalf("the victim's signature does not verify: %v", err)
		}
	})

	t.Run("signature share", func(t *testing.T) {
		coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
		payload := [32]byte{0x22}
		round := abortBeginRound(t, coord, payload)
		abortCommitAll(t, participants, round)

		commitments, err := coord.GetCommitments(round)
		if err != nil {
			t.Fatalf("GetCommitments: %v", err)
		}
		sender := participants[1] // ID 2
		victim := participants[0] // ID 1
		validShare, err := sender.signer.Sign(payload[:], commitments)
		if err != nil {
			t.Fatalf("producing the sender's share: %v", err)
		}
		validShare.SignerIdentifier = victim.ID()

		_, err = coord.AddSignatureShare(context.Background(), round, sender.ID(), validShare)
		if err == nil {
			t.Fatal("expected the mislabelled share to be rejected")
		}
		contributionErr := abortErrorsAsContribution(t, err)
		if contributionErr.Participant != sender.ID() {
			t.Errorf("accused participant = %d, want the sender %d", contributionErr.Participant, sender.ID())
		}
		if contributionErr.Participant == victim.ID() {
			t.Error("the sender framed the victim: the accusation names participant 1")
		}
		if contributionErr.Reason != AbortReasonIdentifierMismatch {
			t.Errorf("reason = %q, want %q", contributionErr.Reason, AbortReasonIdentifierMismatch)
		}
		if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
			t.Fatalf("VerifyAbortEvidence: %v", err)
		}
	})
}

// TestCommitmentShareMismatchBlamesOnlyItsSender proves a participant whose
// commitment does not match the share it sends is identified alone: an honest
// participant's share in the same round still verifies and is accepted.
func TestCommitmentShareMismatchBlamesOnlyItsSender(t *testing.T) {
	coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0x33}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)

	honestCommitments, err := coord.GetCommitments(round)
	if err != nil {
		t.Fatalf("GetCommitments: %v", err)
	}
	// The sender's real share, computed against its real commitment.
	senderShare, err := participants[1].signer.Sign(payload[:], honestCommitments)
	if err != nil {
		t.Fatalf("producing participant 2's share: %v", err)
	}

	// Replace participant 2's committed nonce points with participant 1's,
	// which the FROST encoding and ValidateCommitment both accept. The round's
	// group commitment now disagrees with participant 2's share.
	coord.mu.Lock()
	senderCommitment := coord.sessions[round].commitmentByID[2]
	senderCommitment.HidingNonceCommitment = honestCommitments.Get(1).HidingNonceCommitment.Copy()
	senderCommitment.BindingNonceCommitment = honestCommitments.Get(1).BindingNonceCommitment.Copy()
	coord.mu.Unlock()

	// The honest participant's share still verifies and is accepted.
	if _, err := participants[0].Sign(context.Background(), round); err != nil {
		t.Fatalf("honest participant 1 was rejected: %v", err)
	}

	_, err = coord.AddSignatureShare(context.Background(), round, 2, senderShare)
	if err == nil {
		t.Fatal("expected the mismatched share to be rejected")
	}
	contributionErr := abortErrorsAsContribution(t, err)
	if contributionErr.Participant != 2 {
		t.Errorf("accused participant = %d, want 2", contributionErr.Participant)
	}
	if contributionErr.Reason != AbortReasonSignatureShareInvalid {
		t.Errorf("reason = %q, want %q", contributionErr.Reason, AbortReasonSignatureShareInvalid)
	}
	if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
		t.Fatalf("VerifyAbortEvidence: %v", err)
	}
}

// TestEvidenceRefusesAnUnprovenAccusation covers the verifier's fail-closed
// cases: an honest share, a substituted key, a substituted payload, and
// malformed evidence all fail verification rather than confirming an
// accusation.
func TestEvidenceRefusesAnUnprovenAccusation(t *testing.T) {
	coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0x44}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)

	commitments, err := coord.GetCommitments(round)
	if err != nil {
		t.Fatalf("GetCommitments: %v", err)
	}
	honestShare, err := participants[0].signer.Sign(payload[:], commitments)
	if err != nil {
		t.Fatalf("producing participant 1's share: %v", err)
	}

	encodedCommitments := make([][]byte, 0, len(commitments))
	for _, commitment := range commitments {
		encodedCommitments = append(encodedCommitments, commitment.Encode())
	}
	honestEvidence := &AbortEvidence{
		Version:        AbortEvidenceVersion,
		Round:          round,
		Participant:    1,
		Reason:         AbortReasonSignatureShareInvalid,
		Payload:        append([]byte(nil), payload[:]...),
		Contribution:   honestShare.Encode(),
		Commitments:    encodedCommitments,
		PublicKeyShare: append([]byte(nil), publicKeyShares[0]...),
	}

	if err := VerifyAbortEvidence(honestEvidence, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("honest share accepted as evidence: errors.Is(err, ErrInvalidAbortEvidence) = false: %v", err)
	}

	substitutedKey := *honestEvidence
	substitutedKey.PublicKeyShare = append([]byte(nil), publicKeyShares[1]...)
	if err := VerifyAbortEvidence(&substitutedKey, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("substituted key accepted: %v", err)
	}

	wrongPayload := *honestEvidence
	if err := VerifyAbortEvidence(&wrongPayload, bytes.Repeat([]byte{0xff}, 32), verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("evidence about another payload accepted: %v", err)
	}

	// A coordinator that substitutes the payload inside the evidence and then
	// verifies against its own substituted value still gets rejected when the
	// real payload is supplied, which is the verifier's job.
	wrongPayload.Payload = bytes.Repeat([]byte{0xff}, 32)
	if err := VerifyAbortEvidence(&wrongPayload, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("substituted payload accepted: %v", err)
	}

	wrongRoster := [][]byte{publicKeyShares[1], publicKeyShares[0], publicKeyShares[2]}
	if err := VerifyAbortEvidence(honestEvidence, payload[:], verificationKey, wrongRoster, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("evidence verified against a different roster: %v", err)
	}

	if err := VerifyAbortEvidence(nil, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("nil evidence accepted: %v", err)
	}

	unknownVersion := *honestEvidence
	unknownVersion.Version = AbortEvidenceVersion + 1
	if err := VerifyAbortEvidence(&unknownVersion, payload[:], verificationKey, publicKeyShares, 2); !errors.Is(err, ErrInvalidAbortEvidence) {
		t.Errorf("unknown version accepted: %v", err)
	}
}

// TestUnavailableIsNeverAnAccusation proves missing contributions and
// cancelled contexts produce the unavailable sentinel (or the context error),
// not an accusation.
func TestUnavailableIsNeverAnAccusation(t *testing.T) {
	coord, _, _, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0x55}
	round := abortBeginRound(t, coord, payload)

	_, err := coord.GetCommitments(round)
	if !errors.Is(err, ErrParticipantUnavailable) {
		t.Fatalf("GetCommitments on an empty round = %v, want ErrParticipantUnavailable", err)
	}
	if errors.Is(err, ErrContributionInvalid) {
		t.Fatalf("an incomplete round was reported as an accusation: %v", err)
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("errors.As(*UnavailableError) = false for %v", err)
	}
	if unavailable.Need != 2 || unavailable.Have != 0 {
		t.Errorf("UnavailableError = %+v, want Need 2, Have 0", unavailable)
	}
	if len(unavailable.Missing) == 0 {
		t.Error("UnavailableError names no missing participants")
	}

	// One participant committed: still unavailable, and nobody is accused.
	if _, err := participants[0].Commit(context.Background(), round); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := coord.GetCommitments(round); !errors.Is(err, ErrParticipantUnavailable) {
		t.Fatalf("GetCommitments with one commitment = %v, want ErrParticipantUnavailable", err)
	}

	// A cancelled context is a transport/interruption outcome.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coord.AddCommitment(cancelled, round, 2, participants[1].signer.Commit()); !errors.Is(err, context.Canceled) {
		t.Fatalf("AddCommitment with a cancelled context = %v, want context.Canceled", err)
	} else if errors.Is(err, ErrContributionInvalid) {
		t.Fatalf("a cancelled context was reported as an accusation: %v", err)
	}

	// A deadline is also not an accusation.
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	_, err = coord.AddSignatureShare(expired, round, 1, &frost.SignatureShare{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AddSignatureShare past its deadline = %v, want context.DeadlineExceeded", err)
	}
	var contributionErr *ContributionError
	if errors.As(err, &contributionErr) {
		t.Fatalf("a deadline produced an accusation: %v", err)
	}
}

// TestProtocolViolationsAreAttributed covers the two remaining attributable
// failures: a share sent without a commitment, and a conflicting duplicate.
func TestProtocolViolationsAreAttributed(t *testing.T) {
	t.Run("share without commitment", func(t *testing.T) {
		coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
		payload := [32]byte{0x66}
		round := abortBeginRound(t, coord, payload)

		if _, err := participants[0].Commit(context.Background(), round); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		// A syntactically valid scalar and identifier from the sender, but no
		// commitment for that sender in the round.
		scalar := coord.cfg.Ciphersuite.Group().NewScalar().SetUInt64(7)
		share := &frost.SignatureShare{
			SignatureShare:   scalar,
			SignerIdentifier: 2,
			Group:            coord.cfg.Ciphersuite.Group(),
		}
		_, err := coord.AddSignatureShare(context.Background(), round, 2, share)
		if err == nil {
			t.Fatal("expected a share without a commitment to be rejected")
		}
		contributionErr := abortErrorsAsContribution(t, err)
		if contributionErr.Participant != 2 || contributionErr.Reason != AbortReasonCommitmentMissing {
			t.Errorf("accusation = participant %d, reason %q; want participant 2, %q",
				contributionErr.Participant, contributionErr.Reason, AbortReasonCommitmentMissing)
		}
		if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
			t.Fatalf("VerifyAbortEvidence: %v", err)
		}
	})

	t.Run("conflicting duplicate commitment", func(t *testing.T) {
		coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
		payload := [32]byte{0x77}
		round := abortBeginRound(t, coord, payload)

		sender := participants[1]
		first := sender.signer.Commit()
		if err := coord.AddCommitment(context.Background(), round, sender.ID(), first); err != nil {
			t.Fatalf("first AddCommitment: %v", err)
		}
		second := sender.signer.Commit()
		err := coord.AddCommitment(context.Background(), round, sender.ID(), second)
		if err == nil {
			t.Fatal("expected the conflicting duplicate to be rejected")
		}
		contributionErr := abortErrorsAsContribution(t, err)
		if contributionErr.Participant != sender.ID() || contributionErr.Reason != AbortReasonDuplicateContribution {
			t.Errorf("accusation = participant %d, reason %q; want participant 2, %q",
				contributionErr.Participant, contributionErr.Reason, AbortReasonDuplicateContribution)
		}
		if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 2); err != nil {
			t.Fatalf("VerifyAbortEvidence: %v", err)
		}
	})

	t.Run("identical retransmission is acknowledged", func(t *testing.T) {
		coord, _, _, participants := abortTestGroup(t, 2, 3)
		payload := [32]byte{0x78}
		round := abortBeginRound(t, coord, payload)

		sender := participants[1]
		commitment := sender.signer.Commit()
		if err := coord.AddCommitment(context.Background(), round, sender.ID(), commitment); err != nil {
			t.Fatalf("first AddCommitment: %v", err)
		}
		if err := coord.AddCommitment(context.Background(), round, sender.ID(), commitment.Copy()); err != nil {
			t.Fatalf("identical retransmission was rejected: %v", err)
		}
	})

	t.Run("conflicting duplicate share", func(t *testing.T) {
		coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 3, 3)
		payload := [32]byte{0x88}
		round := abortBeginRound(t, coord, payload)
		abortCommitAll(t, participants, round)

		commitments, err := coord.GetCommitments(round)
		if err != nil {
			t.Fatalf("GetCommitments: %v", err)
		}
		shareA, err := participants[0].signer.Sign(payload[:], commitments)
		if err != nil {
			t.Fatalf("participant 1 share: %v", err)
		}
		shareB, err := participants[1].signer.Sign(payload[:], commitments)
		if err != nil {
			t.Fatalf("participant 2 share: %v", err)
		}
		if _, err := coord.AddSignatureShare(context.Background(), round, 1, shareA); err != nil {
			t.Fatalf("participant 1 AddSignatureShare: %v", err)
		}
		if _, err := coord.AddSignatureShare(context.Background(), round, 2, shareB); err != nil {
			t.Fatalf("participant 2 AddSignatureShare: %v", err)
		}

		conflicting := abortMutateShare(t, coord, shareA)
		_, err = coord.AddSignatureShare(context.Background(), round, 1, conflicting)
		if err == nil {
			t.Fatal("expected the conflicting duplicate share to be rejected")
		}
		contributionErr := abortErrorsAsContribution(t, err)
		if contributionErr.Participant != 1 || contributionErr.Reason != AbortReasonDuplicateContribution {
			t.Errorf("accusation = participant %d, reason %q; want participant 1, %q",
				contributionErr.Participant, contributionErr.Reason, AbortReasonDuplicateContribution)
		}
		if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 3); err != nil {
			t.Fatalf("VerifyAbortEvidence: %v", err)
		}
	})
}

// TestAbortEvidenceFitsAnAuditRecord bounds the evidence size for a
// five-participant round: it has to be small enough to store alongside the
// session it describes.
func TestAbortEvidenceFitsAnAuditRecord(t *testing.T) {
	coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 5, 5)
	payload := [32]byte{0x99}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)

	commitments, err := coord.GetCommitments(round)
	if err != nil {
		t.Fatalf("GetCommitments: %v", err)
	}
	validShare, err := participants[3].signer.Sign(payload[:], commitments)
	if err != nil {
		t.Fatalf("producing participant 4's share: %v", err)
	}
	badShare := abortMutateShare(t, coord, validShare)

	_, err = coord.AddSignatureShare(context.Background(), round, 4, badShare)
	if err == nil {
		t.Fatal("expected the invalid share to be rejected")
	}
	contributionErr := abortErrorsAsContribution(t, err)
	if err := VerifyAbortEvidence(contributionErr.Evidence, payload[:], verificationKey, publicKeyShares, 5); err != nil {
		t.Fatalf("VerifyAbortEvidence: %v", err)
	}

	encoded, err := json.Marshal(contributionErr.Evidence)
	if err != nil {
		t.Fatalf("json.Marshal(evidence): %v", err)
	}
	if len(encoded) >= 1024 {
		t.Errorf("evidence is %d bytes; it must stay under 1024 to fit an audit record", len(encoded))
	}
}

// TestGetSignatureListsMissingShares proves an incomplete signature phase is
// reported as unavailable, with the participants that have not contributed.
func TestGetSignatureListsMissingShares(t *testing.T) {
	coord, _, _, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0xaa}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)

	if _, err := participants[0].Sign(context.Background(), round); err != nil {
		t.Fatalf("participant 1 Sign: %v", err)
	}

	_, err := coord.GetSignature(round)
	if !errors.Is(err, ErrParticipantUnavailable) {
		t.Fatalf("GetSignature with one share = %v, want ErrParticipantUnavailable", err)
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("errors.As(*UnavailableError) = false for %v", err)
	}
	if unavailable.Need != 2 || unavailable.Have != 1 {
		t.Errorf("UnavailableError = %+v, want Need 2, Have 1", unavailable)
	}
	wantMissing := []uint16{2, 3}
	if len(unavailable.Missing) != len(wantMissing) {
		t.Fatalf("missing participants = %v, want %v", unavailable.Missing, wantMissing)
	}
	for i, id := range wantMissing {
		if unavailable.Missing[i] != id {
			t.Errorf("missing participants = %v, want %v", unavailable.Missing, wantMissing)
			break
		}
	}
}

// TestAbortReasonText covers the fixed vocabulary and the two error texts a
// caller or an audit log may render.
func TestAbortReasonText(t *testing.T) {
	reasons := []AbortReason{
		AbortReasonCommitmentInvalid,
		AbortReasonIdentifierMismatch,
		AbortReasonDuplicateContribution,
		AbortReasonSignatureShareInvalid,
		AbortReasonCommitmentMissing,
	}
	for _, reason := range reasons {
		if reason.Description() == "" || reason.Description() == "unknown contribution failure" {
			t.Errorf("reason %q has no specific description", reason)
		}
	}
	if got := AbortReason("unexpected").Description(); got != "unknown contribution failure" {
		t.Errorf("unknown reason description = %q", got)
	}

	contributionErr := &ContributionError{Participant: 3, Reason: AbortReasonSignatureShareInvalid}
	if !errors.Is(contributionErr, ErrContributionInvalid) {
		t.Error("ContributionError does not wrap ErrContributionInvalid")
	}
	if !strings.Contains(contributionErr.Error(), "participant 3") {
		t.Errorf("ContributionError text %q does not name the participant", contributionErr.Error())
	}

	withMissing := &UnavailableError{Need: 2, Have: 0, Missing: []uint16{1, 2}}
	if !strings.Contains(withMissing.Error(), "missing participants") {
		t.Errorf("UnavailableError text %q does not list the missing participants", withMissing.Error())
	}
	withoutMissing := &UnavailableError{Need: 2, Have: 1}
	if strings.Contains(withoutMissing.Error(), "missing participants") {
		t.Errorf("UnavailableError text %q mentions missing participants it did not record", withoutMissing.Error())
	}
	if !errors.Is(withoutMissing, ErrParticipantUnavailable) {
		t.Error("UnavailableError does not wrap ErrParticipantUnavailable")
	}
}

// TestVerifyAbortEvidenceRejectsMalformedAndFalseEvidence drives every
// rejection branch of the verifier, including a false accusation, a
// substituted payload, and a duplicate claim whose two values agree.
func TestVerifyAbortEvidenceRejectsMalformedAndFalseEvidence(t *testing.T) {
	coord, verificationKey, publicKeyShares, participants := abortTestGroup(t, 2, 3)
	payload := [32]byte{0xbb}
	round := abortBeginRound(t, coord, payload)
	abortCommitAll(t, participants, round)
	commitments, err := coord.GetCommitments(round)
	if err != nil {
		t.Fatalf("GetCommitments: %v", err)
	}

	encodedCommitments := make([][]byte, 0, len(commitments))
	for _, commitment := range commitments {
		encodedCommitments = append(encodedCommitments, commitment.Encode())
	}

	// A valid identifier-mismatch accusation: participant 1 sent a
	// contribution that asserted participant 2.
	base := func() *AbortEvidence {
		return &AbortEvidence{
			Version:            AbortEvidenceVersion,
			Round:              round,
			Participant:        1,
			ClaimedParticipant: 2,
			Reason:             AbortReasonIdentifierMismatch,
			Payload:            append([]byte(nil), payload[:]...),
			Contribution:       commitments.Get(2).Encode(),
			Commitments:        encodedCommitments,
			PublicKeyShare:     append([]byte(nil), publicKeyShares[0]...),
		}
	}

	if err := VerifyAbortEvidence(base(), payload[:], verificationKey, publicKeyShares, 2); err != nil {
		t.Fatalf("the base evidence does not verify: %v", err)
	}

	duplicateSenderCommitment := participants[1].signer.Commit()
	otherParticipantShare, err := participants[1].signer.Sign(payload[:], commitments)
	if err != nil {
		t.Fatalf("producing participant 2's share: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*AbortEvidence)
		want error
	}{
		{"participant outside roster", func(e *AbortEvidence) { e.Participant = 9 }, ErrInvalidAbortEvidence},
		{"substituted public key share", func(e *AbortEvidence) { e.PublicKeyShare = publicKeyShares[1] }, ErrInvalidAbortEvidence},
		{"short payload", func(e *AbortEvidence) { e.Payload = []byte{1} }, ErrInvalidAbortEvidence},
		{"claimed participant zero", func(e *AbortEvidence) { e.ClaimedParticipant = 0 }, ErrInvalidAbortEvidence},
		{"claimed participant is sender", func(e *AbortEvidence) { e.ClaimedParticipant = 1 }, ErrInvalidAbortEvidence},
		{"undecodable mismatch contribution", func(e *AbortEvidence) { e.Contribution = []byte{1, 2, 3} }, ErrInvalidAbortEvidence},
		{"contribution asserts another identifier", func(e *AbortEvidence) { e.ClaimedParticipant = 3 }, ErrInvalidAbortEvidence},
		{"duplicate without prior", func(e *AbortEvidence) {
			e.Reason = AbortReasonDuplicateContribution
			e.Participant, e.ClaimedParticipant = 2, 2
			e.Contribution = commitments.Get(2).Encode()
		}, ErrInvalidAbortEvidence},
		{"duplicate with identical values", func(e *AbortEvidence) {
			e.Reason = AbortReasonDuplicateContribution
			e.Participant, e.ClaimedParticipant = 2, 2
			e.Contribution = commitments.Get(2).Encode()
			e.PriorContribution = commitments.Get(2).Encode()
		}, ErrInvalidAbortEvidence},
		{"duplicate prior from another participant", func(e *AbortEvidence) {
			e.Reason = AbortReasonDuplicateContribution
			e.Participant, e.ClaimedParticipant = 2, 2
			e.Contribution = commitments.Get(2).Encode()
			e.PriorContribution = commitments.Get(3).Encode()
		}, ErrInvalidAbortEvidence},
		{"valid duplicate", func(e *AbortEvidence) {
			e.Reason = AbortReasonDuplicateContribution
			e.Participant, e.ClaimedParticipant = 2, 2
			e.PublicKeyShare = publicKeyShares[1]
			e.Contribution = duplicateSenderCommitment.Encode()
			e.PriorContribution = commitments.Get(2).Encode()
		}, nil},
		{"commitment missing with no list", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentMissing
			e.ClaimedParticipant = 0
			e.Contribution = nil
			e.Commitments = nil
		}, ErrInvalidAbortEvidence},
		{"commitment missing but present", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentMissing
			e.ClaimedParticipant = 0
			e.Contribution = nil
		}, ErrInvalidAbortEvidence},
		{"commitment missing and absent", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentMissing
			e.ClaimedParticipant = 0
			e.Contribution = nil
			e.Commitments = [][]byte{commitments.Get(2).Encode(), commitments.Get(3).Encode()}
		}, nil},
		{"commitment invalid without bytes", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentInvalid
			e.ClaimedParticipant = 0
			e.Contribution = nil
		}, ErrInvalidAbortEvidence},
		{"commitment invalid because undecodable", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentInvalid
			e.ClaimedParticipant = 0
			e.Contribution = []byte{1, 2, 3}
		}, nil},
		{"commitment invalid but actually verifies", func(e *AbortEvidence) {
			e.Reason = AbortReasonCommitmentInvalid
			e.ClaimedParticipant = 2
			e.Contribution = commitments.Get(1).Encode()
		}, ErrInvalidAbortEvidence},
		{"commitment invalid because identity point", func(e *AbortEvidence) {
			identity := coord.cfg.Ciphersuite.Group().NewElement().Identity()
			crafted := commitments.Get(1).Copy()
			crafted.BindingNonceCommitment = identity
			e.Reason = AbortReasonCommitmentInvalid
			e.ClaimedParticipant = 1
			e.Contribution = crafted.Encode()
		}, nil},
		{"signature share without bytes", func(e *AbortEvidence) {
			e.Reason = AbortReasonSignatureShareInvalid
			e.ClaimedParticipant = 1
			e.Contribution = nil
		}, ErrInvalidAbortEvidence},
		{"signature share undecodable", func(e *AbortEvidence) {
			e.Reason = AbortReasonSignatureShareInvalid
			e.ClaimedParticipant = 1
			e.Contribution = []byte{1, 2, 3}
		}, ErrInvalidAbortEvidence},
		{"signature share asserts another participant", func(e *AbortEvidence) {
			e.Reason = AbortReasonSignatureShareInvalid
			e.ClaimedParticipant = 1
			e.Contribution = otherParticipantShare.Encode()
		}, ErrInvalidAbortEvidence},
		{"unknown reason", func(e *AbortEvidence) { e.Reason = AbortReason("made up") }, ErrInvalidAbortEvidence},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := base()
			tt.mut(evidence)
			err := VerifyAbortEvidence(evidence, payload[:], verificationKey, publicKeyShares, 2)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("VerifyAbortEvidence = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyAbortEvidence = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestNewFROSTCoordinatorRejectsMalformedKeys covers the configuration
// validation shared with the evidence verifier.
func TestNewFROSTCoordinatorRejectsMalformedKeys(t *testing.T) {
	_, verificationKey, publicKeyShares, err := TrustedDealerKeygen(2, 3)
	if err != nil {
		t.Fatalf("TrustedDealerKeygen: %v", err)
	}
	address := testAddress(t, "policy-test-abort")

	shortKey := append([]byte(nil), verificationKey[:31]...)
	shortShare := append([]byte(nil), publicKeyShares[0][:31]...)

	tests := []struct {
		name string
		vk   []byte
		pks  [][]byte
	}{
		{"short verification key", shortKey, publicKeyShares},
		{"short public key share", verificationKey, [][]byte{publicKeyShares[0], shortShare, publicKeyShares[2]}},
		{"wrong share count", verificationKey, publicKeyShares[:2]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFROSTCoordinator(tt.vk, tt.pks, 2, 3, address); err == nil {
				t.Fatal("expected the malformed configuration to be rejected")
			}
		})
	}
}
