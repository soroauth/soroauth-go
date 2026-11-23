package frost

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/bytemare/dkg"
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
)

// Errors returned by the distributed key generation ceremony. They are
// sentinels so a caller can tell a configuration mistake from a peer that
// contributed bad data: a ceremony that cannot be verified must produce no
// usable share (RFC 9591, Appendix C.2, "If vss_verify fails, the participant
// MUST abort the protocol").
var (
	// ErrDKGConfig reports a threshold, signer count or participant identifier
	// outside the supported range.
	ErrDKGConfig = errors.New("frost: invalid DKG configuration")
	// ErrDKGPhase reports a protocol call made out of order, such as Finalize
	// before Continue.
	ErrDKGPhase = errors.New("frost: DKG phase out of order")
	// ErrDKGIncomplete reports that a participant's round-one commitment or
	// round-two share never arrived. The ParticipantID on the DKGError names
	// the missing participant.
	ErrDKGIncomplete = errors.New("frost: DKG contribution missing")
	// ErrDKGInvalidContribution reports a contribution that failed
	// verification. The ParticipantID on the DKGError names the sender.
	ErrDKGInvalidContribution = errors.New("frost: invalid DKG contribution")
	// ErrDKGVerification reports a transcript whose verification key or public
	// key shares do not follow from its commitments.
	ErrDKGVerification = errors.New("frost: DKG transcript verification failed")
)

// DKGError attributes a DKG failure to one participant. ParticipantID is zero
// when the fault cannot be attributed to a sender (for example, a nil package).
type DKGError struct {
	ParticipantID uint16
	Err           error
}

// Error implements error.
func (e *DKGError) Error() string {
	if e.ParticipantID == 0 {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: participant %d", e.Err, e.ParticipantID)
}

// Unwrap returns the sentinel this error classifies as.
func (e *DKGError) Unwrap() error { return e.Err }

func dkgErrorf(id uint16, sentinel error) error {
	return &DKGError{ParticipantID: id, Err: sentinel}
}

// DKGConfig is the ceremony every participant must agree on. Threshold is the
// number of shares required to sign; MaxSigners is the number of participants,
// which is also the number of shares produced.
type DKGConfig struct {
	Threshold  uint16
	MaxSigners uint16
}

func (c DKGConfig) validate() error {
	if c.MaxSigners == 0 {
		return fmt.Errorf("%w: MaxSigners must be positive", ErrDKGConfig)
	}
	if c.Threshold == 0 {
		return fmt.Errorf("%w: Threshold must be positive", ErrDKGConfig)
	}
	if c.Threshold > c.MaxSigners {
		return fmt.Errorf("%w: Threshold %d exceeds MaxSigners %d", ErrDKGConfig, c.Threshold, c.MaxSigners)
	}
	if c.Threshold > maxAccountSignatures {
		return fmt.Errorf("%w: Threshold %d exceeds %d", ErrDKGConfig, c.Threshold, maxAccountSignatures)
	}
	return nil
}

// maxAccountSignatures mirrors the account signature cap the rest of soroauth
// enforces. It is repeated here because package frost does not import its
// parent, and a FROST group larger than the cap cannot back a classic account.
const maxAccountSignatures = 20

// DKGShare is one participant's finished key material. It is the exact shape
// TrustedDealerKeygen returns, so it can be handed to NewFROSTCoordinator and
// NewFROSTParticipant without conversion.
//
// SecretShare is private key material. Do not log it, serialise it, or send it
// anywhere except to the participant that owns it. The public fields
// (PublicKeyShare and VerificationKey) are safe to publish.
type DKGShare struct {
	// ParticipantID is the 1-indexed identifier of the participant holding
	// this share.
	ParticipantID uint16
	// Threshold and MaxSigners are the configuration the ceremony ran under.
	Threshold  uint16
	MaxSigners uint16
	// Epoch is the refresh epoch. A freshly generated group starts at zero and
	// a successful refresh increments it by one.
	Epoch uint32
	// SecretShare is the participant's 32-byte secret share. Private.
	SecretShare []byte
	// PublicKeyShare is the participant's 32-byte public key share.
	PublicKeyShare []byte
	// VerificationKey is the 32-byte group public key every participant
	// computed independently. It is the key a FROST signature verifies under.
	VerificationKey []byte
	// Commitment is the participant's public VSS commitment: one 32-byte
	// encoded curve element per polynomial coefficient. It is public and is
	// what a refresh adds to.
	Commitment [][]byte
}

// DKGTranscript is the public record of a ceremony: every participant's
// round-one VSS commitment and proof of knowledge, plus the group verification
// key every participant must agree on. It carries no secret and is safe to
// publish, which is what makes the ceremony independently verifiable.
//
// Verification follows RFC 9591 Appendix C.2: a commitment set determines the
// verification key and every public key share, and a participant whose share
// does not follow from the commitments has failed vss_verify and must abort.
type DKGTranscript struct {
	Threshold       uint16
	MaxSigners      uint16
	VerificationKey []byte
	Round1          []*dkg.Round1Data
}

// DKGParticipant is one party's local state in a distributed key generation
// ceremony. The state is deliberately stateful and single-use: Start, Continue
// and Finalize are one-shot phases, and the wrapped library erases the
// polynomial once Continue succeeds.
//
// No participant and no coordinator ever holds the full private key. The group
// secret exists only as Shamir shares; the verification key is the only group
// secret-derived value that is published.
type DKGParticipant struct {
	cfg  DKGConfig
	id   uint16
	core *dkg.Participant
}

// NewDKGParticipant creates participant id (1-indexed) for cfg. The same cfg
// must be used by every participant; the ceremony fails closed otherwise.
func NewDKGParticipant(cfg DKGConfig, id uint16) (*DKGParticipant, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if id == 0 || id > cfg.MaxSigners {
		return nil, fmt.Errorf("%w: participant ID %d outside [1, %d]", ErrDKGConfig, id, cfg.MaxSigners)
	}
	core, err := dkg.Edwards25519Sha512.NewParticipant(id, cfg.Threshold, cfg.MaxSigners)
	if err != nil {
		return nil, fmt.Errorf("frost: new DKG participant: %w", err)
	}
	return &DKGParticipant{cfg: cfg, id: id, core: core}, nil
}

// ID returns the participant's 1-indexed identifier.
func (p *DKGParticipant) ID() uint16 { return p.id }

// Start produces the round-one package to broadcast. It contains the
// participant's VSS commitment and a Schnorr proof of knowledge of the
// polynomial's constant term; it contains no secret share.
func (p *DKGParticipant) Start() (*dkg.Round1Data, error) {
	round1, err := p.core.Start()
	if err != nil {
		return nil, fmt.Errorf("frost: DKG start (participant %d): %w", p.id, err)
	}
	return round1, nil
}

// Continue consumes every participant's round-one package, including this
// participant's own, and returns one secret share per peer. Each returned
// Round2Data must be delivered only to its RecipientIdentifier over an
// authenticated, confidential channel; it is private key material.
//
// Every package is verified before it is accepted:
//
//   - identifiers are in range, unique, and the set is complete;
//   - the group and commitment length match the agreed configuration;
//   - the proof of knowledge verifies against the commitment (RFC 9591
//     Appendix C.2 defines the commitment; the proof is the DKG's
//     Schnorr proof, which the bytemare/dkg implementation specifies because
//     RFC 9591 leaves the DKG construction out of scope in Section 4).
//
// A failure names the participant that sent the bad package.
func (p *DKGParticipant) Continue(round1 []*dkg.Round1Data) (map[uint16]*dkg.Round2Data, error) {
	if _, err := NewDKGTranscript(p.cfg, round1); err != nil {
		return nil, err
	}
	shares, err := p.core.Continue(round1)
	if err != nil {
		return nil, fmt.Errorf("frost: DKG continue (participant %d): %w", p.id, err)
	}
	return shares, nil
}

// Finalize consumes the same round-one set accepted by Continue and the
// round-two shares addressed to this participant, verifies every share against
// its sender's commitment, and returns this participant's DKGShare.
//
// The share is verified against the transcript before it is returned
// (RFC 9591 Appendix C.2): this participant's public key share must follow from
// the commitments, and the verification key must equal the one every other
// participant computes. A mismatch is ErrDKGVerification and no share is
// returned.
func (p *DKGParticipant) Finalize(round1 []*dkg.Round1Data, round2 []*dkg.Round2Data) (DKGShare, error) {
	transcript, err := NewDKGTranscript(p.cfg, round1)
	if err != nil {
		return DKGShare{}, err
	}
	if err := p.verifyRound2(round1, round2); err != nil {
		return DKGShare{}, err
	}

	share, err := p.core.Finalize(round1, round2)
	if err != nil {
		return DKGShare{}, fmt.Errorf("frost: DKG finalize (participant %d): %w", p.id, err)
	}
	return p.toDKGShare(transcript, share)
}

// verifyRound2 checks the round-two set before the library consumes it, so a
// missing or malformed share is attributed to its sender. This is the
// fail-closed check the acceptance criteria require: a participant that aborts
// is named, and a share that does not verify against its sender's commitment is
// rejected rather than folded into the final share.
func (p *DKGParticipant) verifyRound2(round1 []*dkg.Round1Data, round2 []*dkg.Round2Data) error {
	byID := make(map[uint16]*dkg.Round1Data, len(round1))
	for _, r1 := range round1 {
		byID[r1.SenderIdentifier] = r1
	}

	received := make(map[uint16]bool, len(round2))
	for _, r2 := range round2 {
		if r2 == nil {
			return dkgErrorf(0, ErrDKGInvalidContribution)
		}
		sender := r2.SenderIdentifier
		if sender == 0 || sender > p.cfg.MaxSigners || sender == p.id {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}
		if received[sender] {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}
		received[sender] = true
		if r2.RecipientIdentifier != p.id {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}
		if r2.Group != dkg.Edwards25519Sha512.Group() {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}
		if r2.SecretShare == nil {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}

		commitment := byID[sender]
		if commitment == nil {
			return dkgErrorf(sender, ErrDKGIncomplete)
		}
		// vss_verify from RFC 9591 Appendix C.2: the share the sender issued to
		// this participant must lie on the polynomial it committed to.
		claimed := dkg.Edwards25519Sha512.Group().Base().Multiply(r2.SecretShare)
		if !secretsharing.Verify(dkg.Edwards25519Sha512.Group(), p.id, claimed, commitment.Commitment) {
			return dkgErrorf(sender, ErrDKGInvalidContribution)
		}
	}

	for i := uint16(1); i <= p.cfg.MaxSigners; i++ {
		if i == p.id {
			continue
		}
		if !received[i] {
			return dkgErrorf(i, ErrDKGIncomplete)
		}
	}
	return nil
}

// toDKGShare converts a verified library key share into the representation the
// FROST signer uses.
func (p *DKGParticipant) toDKGShare(transcript DKGTranscript, share *keys.KeyShare) (DKGShare, error) {
	if share.Identifier() != p.id {
		return DKGShare{}, fmt.Errorf("%w: share identifier %d does not match participant %d",
			ErrDKGVerification, share.Identifier(), p.id)
	}
	if err := transcript.Verify(); err != nil {
		return DKGShare{}, err
	}

	vk := share.VerificationKey().Encode()
	if !bytes.Equal(vk, transcript.VerificationKey) {
		return DKGShare{}, fmt.Errorf("%w: participant %d computed a different verification key",
			ErrDKGVerification, p.id)
	}

	commitments := make([][]*ecc.Element, 0, len(transcript.Round1))
	for _, r1 := range transcript.Round1 {
		commitments = append(commitments, r1.Commitment)
	}
	if err := dkg.VerifyPublicKey(dkg.Edwards25519Sha512, p.id, share.PublicKey(), commitments); err != nil {
		return DKGShare{}, fmt.Errorf("%w: participant %d public key share: %v",
			ErrDKGVerification, p.id, err)
	}

	commitment := share.Commitment()
	encodedCommitment := make([][]byte, len(commitment))
	for i, element := range commitment {
		encodedCommitment[i] = element.Encode()
	}

	return DKGShare{
		ParticipantID:   p.id,
		Threshold:       p.cfg.Threshold,
		MaxSigners:      p.cfg.MaxSigners,
		Epoch:           0,
		SecretShare:     share.SecretKey().Encode(),
		PublicKeyShare:  share.PublicKey().Encode(),
		VerificationKey: vk,
		Commitment:      encodedCommitment,
	}, nil
}

// NewDKGTranscript builds the public transcript from the round-one packages. It
// validates every package, copies it by encoding and decoding it (so later
// mutation of the caller's value cannot change the transcript), sorts by
// sender, and computes the group verification key.
func NewDKGTranscript(cfg DKGConfig, round1 []*dkg.Round1Data) (DKGTranscript, error) {
	if err := cfg.validate(); err != nil {
		return DKGTranscript{}, err
	}
	if len(round1) != int(cfg.MaxSigners) {
		present := make(map[uint16]bool, len(round1))
		for _, data := range round1 {
			if data != nil {
				present[data.SenderIdentifier] = true
			}
		}
		for id := uint16(1); id <= cfg.MaxSigners; id++ {
			if !present[id] {
				return DKGTranscript{}, dkgErrorf(id, ErrDKGIncomplete)
			}
		}
		return DKGTranscript{}, fmt.Errorf("%w: got %d round-one packages, want %d",
			ErrDKGIncomplete, len(round1), cfg.MaxSigners)
	}

	copied := make([]*dkg.Round1Data, 0, len(round1))
	seen := make(map[uint16]bool, len(round1))
	for _, data := range round1 {
		if data == nil {
			return DKGTranscript{}, dkgErrorf(0, ErrDKGInvalidContribution)
		}
		id := data.SenderIdentifier
		if id == 0 || id > cfg.MaxSigners {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		if seen[id] {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		seen[id] = true
		if data.Group != dkg.Edwards25519Sha512.Group() {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		if len(data.Commitment) != int(cfg.Threshold) {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		for _, c := range data.Commitment {
			if c == nil {
				return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
			}
		}
		// The proof of knowledge binds the sender to the constant term of its
		// commitment. RFC 9591 leaves the DKG construction out of scope
		// (Section 4); this is the Schnorr proof the bytemare/dkg protocol
		// defines, and a false result aborts the ceremony.
		ok, err := dkg.FrostVerifyZeroKnowledgeProof(dkg.Edwards25519Sha512, id, data.Commitment[0], data.ProofOfKnowledge)
		if err != nil {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		if !ok {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}

		encoded := data.Encode()
		if encoded == nil {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		clone := &dkg.Round1Data{}
		if err := clone.Decode(encoded); err != nil {
			return DKGTranscript{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		copied = append(copied, clone)
	}

	sort.Slice(copied, func(i, j int) bool {
		return copied[i].SenderIdentifier < copied[j].SenderIdentifier
	})

	commitments := make([][]*ecc.Element, 0, len(copied))
	for _, data := range copied {
		commitments = append(commitments, data.Commitment)
	}
	vk, err := dkg.VerificationKeyFromRound1(dkg.Edwards25519Sha512, copied)
	if err != nil {
		return DKGTranscript{}, fmt.Errorf("frost: DKG verification key: %w", err)
	}
	// VerificationKeyFromRound1 already validated the set; recomputing from
	// the commitments checks the two derivations agree before the key is
	// published as part of the transcript.
	fromCommitments, err := dkg.VerificationKeyFromCommitments(dkg.Edwards25519Sha512, commitments)
	if err != nil {
		return DKGTranscript{}, fmt.Errorf("frost: DKG verification key: %w", err)
	}
	if !vk.Equal(fromCommitments) {
		return DKGTranscript{}, fmt.Errorf("%w: verification key does not follow from the commitments",
			ErrDKGVerification)
	}

	return DKGTranscript{
		Threshold:       cfg.Threshold,
		MaxSigners:      cfg.MaxSigners,
		VerificationKey: vk.Encode(),
		Round1:          copied,
	}, nil
}

// Verify re-checks a transcript without any participant state. It is what a
// third party runs to confirm the ceremony completed correctly: every proof and
// commitment is validated, the verification key is recomputed, and every
// public key share is derived from the commitments.
func (t DKGTranscript) Verify() error {
	if t.Threshold == 0 || t.MaxSigners == 0 || t.Threshold > t.MaxSigners {
		return fmt.Errorf("%w: invalid threshold %d for %d signers",
			ErrDKGVerification, t.Threshold, t.MaxSigners)
	}
	if len(t.Round1) != int(t.MaxSigners) {
		return fmt.Errorf("%w: got %d commitments, want %d",
			ErrDKGVerification, len(t.Round1), t.MaxSigners)
	}
	if len(t.VerificationKey) == 0 {
		return fmt.Errorf("%w: missing verification key", ErrDKGVerification)
	}

	rebuilt, err := NewDKGTranscript(DKGConfig{Threshold: t.Threshold, MaxSigners: t.MaxSigners}, t.Round1)
	if err != nil {
		return err
	}
	if !bytes.Equal(rebuilt.VerificationKey, t.VerificationKey) {
		return fmt.Errorf("%w: verification key mismatch", ErrDKGVerification)
	}

	commitments := make([][]*ecc.Element, 0, len(t.Round1))
	for _, data := range t.Round1 {
		commitments = append(commitments, data.Commitment)
	}
	for _, data := range t.Round1 {
		want, err := dkg.ComputeParticipantPublicKey(dkg.Edwards25519Sha512, data.SenderIdentifier, commitments)
		if err != nil {
			return fmt.Errorf("%w: participant %d: %v", ErrDKGVerification, data.SenderIdentifier, err)
		}
		if want.IsIdentity() {
			return fmt.Errorf("%w: participant %d has the identity public key share",
				ErrDKGVerification, data.SenderIdentifier)
		}
	}
	return nil
}
