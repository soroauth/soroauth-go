package frost

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bytemare/frost"
)

// AbortEvidenceVersion is the schema version of AbortEvidence. A verifier
// refuses a version it does not know rather than guessing at the meaning of
// the fields, because evidence is what an accusation rests on.
const AbortEvidenceVersion = 1

// AbortReason names why a contribution was rejected. It is a small,
// fixed vocabulary so audit records stay comparable across sessions.
type AbortReason string

const (
	// AbortReasonCommitmentInvalid means the contribution was a commitment
	// this group's configuration rejects, such as an unregistered signer
	// identifier or a nonce commitment that is not a valid group element.
	AbortReasonCommitmentInvalid AbortReason = "commitment_invalid"

	// AbortReasonIdentifierMismatch means the contribution asserted a
	// participant identifier other than the one the authenticated sender
	// proved. This is the reason a participant cannot frame another: the
	// identifier inside a contribution is never trusted over the sender.
	AbortReasonIdentifierMismatch AbortReason = "identifier_mismatch"

	// AbortReasonDuplicateContribution means the same sender contributed two
	// different values for the same phase of one round.
	AbortReasonDuplicateContribution AbortReason = "duplicate_contribution"

	// AbortReasonSignatureShareInvalid means the signature share failed the
	// FROST share verification equation (RFC 9591 §5.3) against the round's
	// commitments and the sender's public key share.
	AbortReasonSignatureShareInvalid AbortReason = "signature_share_invalid"

	// AbortReasonCommitmentMissing means a sender submitted a signature share
	// for a round in which it never submitted a commitment.
	AbortReasonCommitmentMissing AbortReason = "commitment_missing"
)

// Description returns a short human-readable explanation of the reason.
func (r AbortReason) Description() string {
	switch r {
	case AbortReasonCommitmentInvalid:
		return "invalid commitment"
	case AbortReasonIdentifierMismatch:
		return "contribution identified a different participant than its sender"
	case AbortReasonDuplicateContribution:
		return "conflicting duplicate contribution"
	case AbortReasonSignatureShareInvalid:
		return "signature share failed verification"
	case AbortReasonCommitmentMissing:
		return "signature share submitted without a commitment"
	default:
		return "unknown contribution failure"
	}
}

// The errors a threshold round returns. They are deliberately three values
// rather than one, because the three call for different operational actions:
//
//   - ErrContributionInvalid is an accusation. It wraps a *ContributionError
//     naming one participant and carrying AbortEvidence that a third party can
//     re-check with VerifyAbortEvidence.
//   - ErrParticipantUnavailable is not an accusation. It means the round is
//     incomplete — a contribution has not arrived yet — and a timeout or an
//     offline participant must surface here, never as ErrContributionInvalid.
//   - ErrInvalidAbortEvidence means an accusation did not verify. It is the
//     verifier's fail-closed result: evidence that cannot be re-checked is not
//     evidence, so a third party rejects the accusation rather than repeating
//     it.
var (
	// ErrContributionInvalid is returned when a contribution is attributable
	// to a participant and is provably invalid. Use errors.As to recover the
	// *ContributionError and its evidence.
	ErrContributionInvalid = errors.New("threshold participant contributed an invalid value")

	// ErrParticipantUnavailable is returned when a round cannot proceed
	// because a contribution has not arrived. It never names a participant as
	// faulty.
	ErrParticipantUnavailable = errors.New("threshold participant is unavailable")

	// ErrInvalidAbortEvidence is returned by VerifyAbortEvidence when the
	// evidence does not demonstrate what it claims, including when it accuses
	// a participant whose contribution actually verifies.
	ErrInvalidAbortEvidence = errors.New("threshold abort evidence does not verify")
)

// ContributionError is an accusation: participant Participant sent a
// contribution the round rejected, and Evidence is the proof.
//
// It wraps ErrContributionInvalid so callers can branch with errors.Is, and
// its Evidence can be re-checked by any party holding the group's public
// configuration, with no access to the coordinator's state:
//
//	var contradiction *frost.ContributionError
//	if errors.As(err, &contradiction) {
//		if verifyErr := frost.VerifyAbortEvidence(contradiction.Evidence,
//			verificationKey, publicKeyShares, threshold); verifyErr != nil {
//			// The accusation itself is bad; do not act on it.
//		}
//	}
//
// The error text names the participant. It does not include the evidence,
// which keeps an error cheap to log; the Evidence field is what belongs in an
// audit record.
type ContributionError struct {
	// Participant is the authenticated sender of the invalid contribution.
	// It is never the identifier the contribution asserted: that is recorded
	// as AbortEvidence.ClaimedParticipant instead, so a crafted contribution
	// cannot move an accusation onto someone else.
	Participant uint16
	// Reason classifies the failure.
	Reason AbortReason
	// Evidence carries the bytes and public values a verifier needs. It is
	// small: a commitment list and one share, not the key material or the
	// whole entry.
	Evidence *AbortEvidence
}

// Error implements error.
func (e *ContributionError) Error() string {
	return fmt.Sprintf("frost: participant %d: %s: %v",
		e.Participant, e.Reason.Description(), ErrContributionInvalid)
}

// Unwrap returns ErrContributionInvalid so errors.Is keeps working.
func (e *ContributionError) Unwrap() error { return ErrContributionInvalid }

// UnavailableError reports that a round cannot proceed because contributions
// are missing. It is not an accusation, and it deliberately carries no
// evidence: a timeout or an unreachable host says nothing about whether the
// participant's contribution would have been valid.
type UnavailableError struct {
	// Need is the number of contributions the round requires.
	Need int
	// Have is the number of contributions the round has.
	Have int
	// Missing lists the participant identifiers whose contributions are
	// absent, in ascending order. It may be nil when the round is one
	// contribution short but every participant has already contributed to
	// that phase.
	Missing []uint16
}

// Error implements error.
func (e *UnavailableError) Error() string {
	if len(e.Missing) == 0 {
		return fmt.Sprintf("frost: %v: have %d of %d required contributions",
			ErrParticipantUnavailable, e.Have, e.Need)
	}
	return fmt.Sprintf("frost: %v: have %d of %d required contributions; missing participants %v",
		ErrParticipantUnavailable, e.Have, e.Need, e.Missing)
}

// Unwrap returns ErrParticipantUnavailable so errors.Is keeps working.
func (e *UnavailableError) Unwrap() error { return ErrParticipantUnavailable }

// AbortEvidence is the independently checkable record of an invalid
// contribution. It contains only public values: the accused participant's
// public key share, the contribution bytes, the commitments used for the
// round, and the 32-byte payload that was being signed.
//
// The JSON encoding is the audit-record form. For a five-participant group it
// is under a kilobyte, and a test asserts that bound.
type AbortEvidence struct {
	// Version is AbortEvidenceVersion. A verifier refuses any other value.
	Version int `json:"version"`
	// Round is the round the contribution belonged to.
	Round int64 `json:"round"`
	// Participant is the authenticated sender of the contribution.
	Participant uint16 `json:"participant"`
	// ClaimedParticipant is the identifier the contribution itself asserted,
	// when it carried one. It differs from Participant for an identifier
	// mismatch.
	ClaimedParticipant uint16 `json:"claimed_participant,omitempty"`
	// Reason classifies the failure and selects the check a verifier runs.
	Reason AbortReason `json:"reason"`
	// Payload is the 32-byte message hash the round was signing.
	Payload []byte `json:"payload"`
	// Contribution is the encoded contribution: a frost.Commitment encoding,
	// a frost.SignatureShare encoding, or empty when the value could not be
	// encoded at all. For a duplicate, this is the conflicting value.
	Contribution []byte `json:"contribution,omitempty"`
	// PriorContribution is the earlier contribution that makes a duplicate a
	// conflict. It is set only for AbortReasonDuplicateContribution, so a
	// verifier can see both values and confirm they disagree.
	PriorContribution []byte `json:"prior_contribution,omitempty"`
	// Commitments holds every commitment the round had collected when the
	// contribution was rejected, each in frost.Commitment encoding.
	Commitments [][]byte `json:"commitments,omitempty"`
	// PublicKeyShare is the accused participant's 32-byte public key share
	// from the group configuration.
	PublicKeyShare []byte `json:"public_key_share"`
}

// VerifyAbortEvidence checks an accusation using only public group data. A
// third party with the payload, the verification key and the roster can call
// it without the coordinator, the session, or any secret material.
//
// expectedPayload is the 32-byte signing payload the verifier independently
// knows the round was for — the payload rebuilt from the entry, not a value
// taken from the evidence. Requiring it is what keeps a coordinator from
// proving an honest share "invalid" by substituting a different message: a
// share that fails only because the message was swapped is not evidence of
// anything.
//
// It returns nil only when the evidence demonstrates the claimed failure. It
// returns ErrInvalidAbortEvidence when the evidence is malformed, names a
// participant or key outside the roster, or — importantly — when the accused
// contribution actually verifies. That last case is what stops a coordinator
// (or anyone else) from using this API to frame an honest participant.
//
// The threshold and roster must be the group's real values. Evidence checked
// against a different roster proves nothing about this group.
func VerifyAbortEvidence(ev *AbortEvidence, expectedPayload, verificationKey []byte, publicKeyShares [][]byte, threshold int) error {
	if ev == nil {
		return invalidEvidence("evidence is nil")
	}
	if ev.Version != AbortEvidenceVersion {
		return invalidEvidence(fmt.Sprintf("unsupported evidence version %d", ev.Version))
	}
	if len(ev.Payload) != 32 {
		return invalidEvidence(fmt.Sprintf("payload must be 32 bytes, got %d", len(ev.Payload)))
	}
	if len(expectedPayload) != 32 {
		return invalidEvidence(fmt.Sprintf("expected payload must be 32 bytes, got %d", len(expectedPayload)))
	}
	if !bytes.Equal(ev.Payload, expectedPayload) {
		return invalidEvidence("evidence is about a different payload than the one the verifier expects")
	}

	cfg, err := newFrostConfiguration(verificationKey, publicKeyShares, threshold, len(publicKeyShares))
	if err != nil {
		return invalidEvidence(fmt.Sprintf("group configuration is invalid: %v", err))
	}

	if ev.Participant == 0 || int(ev.Participant) > len(publicKeyShares) {
		return invalidEvidence(fmt.Sprintf("participant %d is not in the roster", ev.Participant))
	}
	rosterKey := publicKeyShares[ev.Participant-1]
	if !bytes.Equal(ev.PublicKeyShare, rosterKey) {
		return invalidEvidence(fmt.Sprintf("public key share for participant %d does not match the roster", ev.Participant))
	}

	switch ev.Reason {
	case AbortReasonIdentifierMismatch:
		return verifyIdentifierMismatch(ev)
	case AbortReasonDuplicateContribution:
		return verifyDuplicateContribution(ev)
	case AbortReasonCommitmentMissing:
		return verifyCommitmentMissing(ev, cfg)
	case AbortReasonCommitmentInvalid:
		return verifyCommitmentInvalid(ev, cfg)
	case AbortReasonSignatureShareInvalid:
		return verifySignatureShareInvalid(ev, cfg)
	default:
		return invalidEvidence(fmt.Sprintf("unknown reason %q", ev.Reason))
	}
}

// verifyIdentifierMismatch checks that the contribution really did assert a
// different identifier from the sender's. The binding of the contribution to
// the sender is the transport's job; what is checkable here is that the
// contribution's own identifier is not the participant's.
func verifyIdentifierMismatch(ev *AbortEvidence) error {
	if ev.ClaimedParticipant == 0 {
		return invalidEvidence("identifier mismatch evidence carries no claimed participant")
	}
	if ev.ClaimedParticipant == ev.Participant {
		return invalidEvidence("claimed participant equals the sender; there is no mismatch")
	}
	claimed, ok := contributionIdentifier(ev.Contribution)
	if !ok {
		return invalidEvidence("contribution cannot be decoded, so its identifier cannot be checked")
	}
	if claimed != ev.ClaimedParticipant {
		return invalidEvidence(fmt.Sprintf("contribution asserts participant %d, evidence says %d", claimed, ev.ClaimedParticipant))
	}
	return nil
}

func verifyDuplicateContribution(ev *AbortEvidence) error {
	current, ok := contributionIdentifier(ev.Contribution)
	if !ok {
		return invalidEvidence("duplicate contribution cannot be decoded")
	}
	prior, ok := contributionIdentifier(ev.PriorContribution)
	if !ok {
		return invalidEvidence("prior contribution cannot be decoded")
	}
	if current != ev.Participant || prior != ev.Participant {
		return invalidEvidence(fmt.Sprintf("duplicate evidence names participants %d and %d, not the sender %d",
			current, prior, ev.Participant))
	}
	if bytes.Equal(ev.Contribution, ev.PriorContribution) {
		return invalidEvidence("the two contributions are identical; an identical retransmission is not a conflict")
	}
	return nil
}

func verifyCommitmentMissing(ev *AbortEvidence, cfg *frost.Configuration) error {
	if len(ev.Commitments) == 0 {
		return invalidEvidence("no commitment list was included, so the absence of a commitment cannot be shown")
	}
	// This failure can legitimately happen before the round has a threshold
	// of commitments, so each entry is validated individually instead of
	// requiring a complete list.
	commitments, err := decodeCommitments(ev.Commitments)
	if err != nil {
		return invalidEvidence(err.Error())
	}
	for _, commitment := range commitments {
		if err := cfg.ValidateCommitment(commitment); err != nil {
			return invalidEvidence(fmt.Sprintf("commitment list is not valid: %v", err))
		}
	}
	if commitments.Get(ev.Participant) != nil {
		return invalidEvidence(fmt.Sprintf("participant %d did contribute a commitment", ev.Participant))
	}
	return nil
}

func verifyCommitmentInvalid(ev *AbortEvidence, cfg *frost.Configuration) error {
	if len(ev.Contribution) == 0 {
		return invalidEvidence("no contribution bytes were included to check")
	}
	commitment := &frost.Commitment{}
	if err := commitment.Decode(ev.Contribution); err != nil {
		// Bytes that do not even decode are themselves the evidence of an
		// invalid commitment.
		return nil
	}
	if commitment.SignerID != ev.Participant {
		return invalidEvidence(fmt.Sprintf("commitment asserts participant %d, not the sender %d", commitment.SignerID, ev.Participant))
	}
	if err := cfg.ValidateCommitment(commitment); err == nil {
		return invalidEvidence("commitment verifies; the accusation is false")
	}
	return nil
}

func verifySignatureShareInvalid(ev *AbortEvidence, cfg *frost.Configuration) error {
	if len(ev.Contribution) == 0 {
		return invalidEvidence("no signature share bytes were included to check")
	}
	share := &frost.SignatureShare{}
	if err := share.Decode(ev.Contribution); err != nil {
		return invalidEvidence(fmt.Sprintf("signature share does not decode: %v", err))
	}
	if share.SignerIdentifier != ev.Participant {
		return invalidEvidence(fmt.Sprintf("signature share asserts participant %d, not the sender %d", share.SignerIdentifier, ev.Participant))
	}
	commitments, err := decodeEvidenceCommitments(ev.Commitments, cfg)
	if err != nil {
		return invalidEvidence(err.Error())
	}
	if err := cfg.VerifySignatureShare(share, ev.Payload, commitments); err == nil {
		return invalidEvidence(fmt.Sprintf("the contribution from participant %d verifies; the accusation is false", ev.Participant))
	}
	return nil
}

// contributionIdentifier returns the participant identifier embedded in an
// encoded commitment or signature share.
func contributionIdentifier(raw []byte) (uint16, bool) {
	commitment := &frost.Commitment{}
	if err := commitment.Decode(raw); err == nil {
		return commitment.SignerID, true
	}
	share := &frost.SignatureShare{}
	if err := share.Decode(raw); err == nil {
		return share.SignerIdentifier, true
	}
	return 0, false
}

// decodeCommitments decodes a commitment list from evidence and sorts it,
// because the FROST verification API requires ascending identifiers
// (RFC 9591 §5.3).
func decodeCommitments(raw [][]byte) (frost.CommitmentList, error) {
	commitments := make(frost.CommitmentList, 0, len(raw))
	for i, encoded := range raw {
		commitment := &frost.Commitment{}
		if err := commitment.Decode(encoded); err != nil {
			return nil, fmt.Errorf("commitment %d does not decode: %w", i, err)
		}
		commitments = append(commitments, commitment)
	}
	commitments.Sort()
	return commitments, nil
}

// decodeEvidenceCommitments decodes and fully validates a commitment list
// from evidence.
func decodeEvidenceCommitments(raw [][]byte, cfg *frost.Configuration) (frost.CommitmentList, error) {
	commitments, err := decodeCommitments(raw)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateCommitmentList(commitments); err != nil {
		return nil, fmt.Errorf("commitment list is not valid: %w", err)
	}
	return commitments, nil
}

func invalidEvidence(detail string) error {
	return fmt.Errorf("frost: verify abort evidence: %s: %w", detail, ErrInvalidAbortEvidence)
}

// encodeCommitmentForEvidence returns the canonical encoding of a commitment,
// or nil when the value is too malformed to encode. It never panics on a
// caller-supplied struct.
func encodeCommitmentForEvidence(commitment *frost.Commitment) []byte {
	if commitment == nil ||
		commitment.HidingNonceCommitment == nil ||
		commitment.BindingNonceCommitment == nil {
		return nil
	}
	return commitment.Encode()
}

// encodeShareForEvidence returns the canonical encoding of a signature share,
// or nil when the share has no scalar to encode.
func encodeShareForEvidence(share *frost.SignatureShare) []byte {
	if share == nil || share.SignatureShare == nil {
		return nil
	}
	return share.Encode()
}
