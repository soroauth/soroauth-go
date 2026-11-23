package frost

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bytemare/dkg"
	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing"
)

// ErrRefreshEpoch reports a refresh whose epoch is not exactly one more than
// the share it is applied to. Epochs make a replay of an old refresh visible
// instead of silently replacing a share with one from an earlier window.
var ErrRefreshEpoch = errors.New("frost: refresh epoch mismatch")

// RefreshConfig describes one refresh window. Every participant must use the
// same Threshold, MaxSigners and Epoch. Epoch is the window the refresh
// produces, so it must be one more than the epoch on the share it replaces.
//
// Operational procedure (all steps fail closed):
//
//  1. Every participant creates a RefreshParticipant and publishes its
//     Commitment. Commitments are public and carry no secret.
//  2. Every participant calls Shares with the complete commitment set and
//     sends each returned scalar only to the participant named by the map key,
//     over an authenticated and confidential channel.
//  3. Every participant calls Apply with its own current share, the scalars it
//     received, and the same commitment set. Apply verifies every scalar
//     against its sender's commitment before changing the share.
//  4. A participant that is missing from either set is named in a *DKGError
//     and no participant receives a new share, so a partially refreshed group
//     cannot silently keep signing.
//
// Refresh does not change the group verification key or the Stellar account
// address. It changes every secret share and every public key share, so an
// attacker who holds one old share must also compromise a threshold of shares
// from the same window.
type RefreshConfig struct {
	Threshold  uint16
	MaxSigners uint16
	Epoch      uint32
}

func (c RefreshConfig) validate() error {
	if err := (DKGConfig{Threshold: c.Threshold, MaxSigners: c.MaxSigners}).validate(); err != nil {
		return err
	}
	if c.Epoch == 0 {
		return fmt.Errorf("%w: Epoch must be at least 1", ErrRefreshEpoch)
	}
	return nil
}

// RefreshCommitment is one participant's public contribution to a refresh: a
// VSS commitment to a polynomial whose constant term is the identity. Because
// the constant term is zero, adding the contributions changes each share
// without changing the group secret (RFC 9591 Appendix C.2 defines the
// commitment; a zero constant term is what makes this a refresh rather than a
// new key generation).
//
// Commitment holds 32-byte encoded curve elements, one per polynomial
// coefficient. It is public data.
type RefreshCommitment struct {
	ParticipantID uint16   `json:"participant_id"`
	Epoch         uint32   `json:"epoch"`
	Commitment    [][]byte `json:"commitment"`
}

// RefreshParticipant is one participant's local refresh state. It generates a
// random polynomial of degree Threshold-1 with a zero constant term, and can
// evaluate it for its peers.
type RefreshParticipant struct {
	cfg        RefreshConfig
	id         uint16
	polynomial secretsharing.Polynomial
	commitment [][]byte
}

// NewRefreshParticipant creates the refresh state for participant id. A fresh
// polynomial is generated with a zero constant term; no participant learns
// another's coefficients.
func NewRefreshParticipant(cfg RefreshConfig, id uint16) (*RefreshParticipant, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if id == 0 || id > cfg.MaxSigners {
		return nil, fmt.Errorf("%w: participant ID %d outside [1, %d]", ErrDKGConfig, id, cfg.MaxSigners)
	}

	g := dkgGroup()
	polynomial := make(secretsharing.Polynomial, cfg.Threshold)
	polynomial[0] = g.NewScalar().Zero()
	for i := uint16(1); i < cfg.Threshold; i++ {
		polynomial[i] = g.NewScalar().Random()
	}
	if cfg.Threshold > 1 && polynomial[cfg.Threshold-1].IsZero() {
		// The highest coefficient must be non-zero for the polynomial to have
		// degree Threshold-1. Regenerate rather than publish a lower-degree
		// sharing that would give some subsets less security than promised.
		for polynomial[cfg.Threshold-1].IsZero() {
			polynomial[cfg.Threshold-1].Random()
		}
	}

	commitment, err := secretsharing.Commit(g, polynomial)
	if err != nil {
		return nil, fmt.Errorf("frost: refresh commitment: %w", err)
	}
	encoded := make([][]byte, len(commitment))
	for i, element := range commitment {
		encoded[i] = element.Encode()
	}

	return &RefreshParticipant{
		cfg:        cfg,
		id:         id,
		polynomial: polynomial,
		commitment: encoded,
	}, nil
}

// ID returns the participant's 1-indexed identifier.
func (p *RefreshParticipant) ID() uint16 { return p.id }

// Commitment returns a copy of this participant's public contribution.
func (p *RefreshParticipant) Commitment() RefreshCommitment {
	commitment := make([][]byte, len(p.commitment))
	for i, element := range p.commitment {
		commitment[i] = append([]byte(nil), element...)
	}
	return RefreshCommitment{
		ParticipantID: p.id,
		Epoch:         p.cfg.Epoch,
		Commitment:    commitment,
	}
}

// Shares validates the complete commitment set and returns the refresh scalar
// owed to every other participant, keyed by recipient identifier. Each value is
// private key material for its recipient and must not be broadcast.
//
// The first element of every commitment must be the identity. That is the check
// that proves the refresh preserves the group key: a non-zero constant term
// would change the secret the group signs with, so the ceremony fails closed
// and names the sender.
func (p *RefreshParticipant) Shares(commitments []RefreshCommitment) (map[uint16][]byte, error) {
	if _, err := p.verifyCommitments(commitments); err != nil {
		return nil, err
	}

	g := dkgGroup()
	shares := make(map[uint16][]byte, p.cfg.MaxSigners-1)
	for id := uint16(1); id <= p.cfg.MaxSigners; id++ {
		if id == p.id {
			continue
		}
		value := p.polynomial.Evaluate(g.NewScalar().SetUInt64(uint64(id)))
		shares[id] = value.Encode()
	}
	return shares, nil
}

// Apply verifies the refresh shares addressed to this participant and returns
// its share for the new epoch. current is the participant's share from the
// preceding epoch; commitments is the complete set published in step 1;
// received maps each sender to the scalar it sent this participant.
//
// Every received scalar is checked against its sender's VSS commitment
// (RFC 9591 Appendix C.2, vss_verify) before it is added. The resulting share
// is checked so that its public key share matches the aggregate commitment and
// the group verification key is unchanged. Any failure returns no share.
func (p *RefreshParticipant) Apply(current DKGShare, received map[uint16][]byte, commitments []RefreshCommitment) (DKGShare, error) {
	if err := p.verifyCurrentShare(current); err != nil {
		return DKGShare{}, err
	}
	decoded, err := p.verifyCommitments(commitments)
	if err != nil {
		return DKGShare{}, err
	}

	g := dkgGroup()
	secret := g.NewScalar()
	if err := secret.Decode(current.SecretShare); err != nil {
		return DKGShare{}, fmt.Errorf("frost: refresh current secret share: %w", err)
	}
	// A participant adds its own contribution too; the aggregate commitment
	// below includes it, so leaving it out would make the share fall off the
	// refreshed polynomial.
	secret.Add(p.polynomial.Evaluate(g.NewScalar().SetUInt64(uint64(p.id))))

	for id := uint16(1); id <= p.cfg.MaxSigners; id++ {
		if id == p.id {
			continue
		}
		encoded, ok := received[id]
		if !ok {
			return DKGShare{}, dkgErrorf(id, ErrDKGIncomplete)
		}
		share := g.NewScalar()
		if err := share.Decode(encoded); err != nil {
			return DKGShare{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		claimed := g.Base().Multiply(share)
		if !secretsharing.Verify(g, p.id, claimed, decoded[id]) {
			return DKGShare{}, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		secret.Add(share)
	}

	// Aggregate commitment: the old commitment plus every refresh commitment.
	aggregate, err := p.aggregateCommitment(current.Commitment, decoded)
	if err != nil {
		return DKGShare{}, err
	}
	publicKeyShare, err := secretsharing.PubKeyForCommitment(g, p.id, aggregate)
	if err != nil {
		return DKGShare{}, fmt.Errorf("frost: refresh public key share: %w", err)
	}
	if !g.Base().Multiply(secret).Equal(publicKeyShare) {
		return DKGShare{}, fmt.Errorf("%w: refreshed share does not match the aggregate commitment",
			ErrDKGVerification)
	}
	if !bytes.Equal(aggregate[0].Encode(), current.VerificationKey) {
		return DKGShare{}, fmt.Errorf("%w: refresh changed the group verification key",
			ErrDKGVerification)
	}

	encodedAggregate := make([][]byte, len(aggregate))
	for i, element := range aggregate {
		encodedAggregate[i] = element.Encode()
	}
	return DKGShare{
		ParticipantID:   p.id,
		Threshold:       p.cfg.Threshold,
		MaxSigners:      p.cfg.MaxSigners,
		Epoch:           p.cfg.Epoch,
		SecretShare:     secret.Encode(),
		PublicKeyShare:  publicKeyShare.Encode(),
		VerificationKey: append([]byte(nil), current.VerificationKey...),
		Commitment:      encodedAggregate,
	}, nil
}

// verifyCurrentShare checks that current belongs to the same group and is the
// epoch immediately before the one this refresh produces.
func (p *RefreshParticipant) verifyCurrentShare(current DKGShare) error {
	if current.Threshold != p.cfg.Threshold || current.MaxSigners != p.cfg.MaxSigners {
		return fmt.Errorf("%w: share configuration %d-of-%d does not match refresh %d-of-%d",
			ErrDKGConfig, current.Threshold, current.MaxSigners, p.cfg.Threshold, p.cfg.MaxSigners)
	}
	if current.ParticipantID != p.id {
		return fmt.Errorf("%w: share belongs to participant %d, not %d",
			ErrDKGConfig, current.ParticipantID, p.id)
	}
	if current.Epoch+1 != p.cfg.Epoch {
		return fmt.Errorf("%w: share is at epoch %d, refresh produces %d (expected %d)",
			ErrRefreshEpoch, current.Epoch, p.cfg.Epoch, current.Epoch+1)
	}
	if len(current.SecretShare) == 0 || len(current.PublicKeyShare) == 0 ||
		len(current.VerificationKey) == 0 || len(current.Commitment) != int(p.cfg.Threshold) {
		return fmt.Errorf("%w: share is missing key material", ErrDKGConfig)
	}
	return nil
}

// verifyCommitments validates the complete public contribution set and returns
// the decoded commitments by sender. It rejects duplicates, missing or
// out-of-range identifiers, wrong epochs, wrong lengths, malformed elements,
// and any non-zero constant term.
func (p *RefreshParticipant) verifyCommitments(commitments []RefreshCommitment) (map[uint16][]*ecc.Element, error) {
	if len(commitments) != int(p.cfg.MaxSigners) {
		present := make(map[uint16]bool, len(commitments))
		for _, c := range commitments {
			present[c.ParticipantID] = true
		}
		for id := uint16(1); id <= p.cfg.MaxSigners; id++ {
			if !present[id] {
				return nil, dkgErrorf(id, ErrDKGIncomplete)
			}
		}
		return nil, fmt.Errorf("%w: got %d commitments, want %d",
			ErrDKGIncomplete, len(commitments), p.cfg.MaxSigners)
	}

	g := dkgGroup()
	decoded := make(map[uint16][]*ecc.Element, len(commitments))
	for _, commitment := range commitments {
		id := commitment.ParticipantID
		if id == 0 || id > p.cfg.MaxSigners {
			return nil, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		if _, ok := decoded[id]; ok {
			return nil, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		if commitment.Epoch != p.cfg.Epoch {
			return nil, fmt.Errorf("%w: participant %d committed to epoch %d, want %d",
				ErrRefreshEpoch, id, commitment.Epoch, p.cfg.Epoch)
		}
		if len(commitment.Commitment) != int(p.cfg.Threshold) {
			return nil, dkgErrorf(id, ErrDKGInvalidContribution)
		}

		elements := make([]*ecc.Element, len(commitment.Commitment))
		for i, encoded := range commitment.Commitment {
			element, err := decodeCommitmentElement(g, encoded)
			if err != nil {
				return nil, dkgErrorf(id, ErrDKGInvalidContribution)
			}
			elements[i] = element
		}
		if !elements[0].IsIdentity() {
			return nil, dkgErrorf(id, ErrDKGInvalidContribution)
		}
		decoded[id] = elements
	}

	own := decoded[p.id]
	if own == nil {
		return nil, dkgErrorf(p.id, ErrDKGIncomplete)
	}
	for i, element := range own {
		if !bytes.Equal(element.Encode(), p.commitment[i]) {
			return nil, fmt.Errorf("%w: the published commitment for participant %d is not the one this participant generated",
				ErrDKGInvalidContribution, p.id)
		}
	}
	return decoded, nil
}

// aggregateCommitment adds the old commitment and every refresh commitment
// coefficient by coefficient.
func (p *RefreshParticipant) aggregateCommitment(previous [][]byte, decoded map[uint16][]*ecc.Element) ([]*ecc.Element, error) {
	g := dkgGroup()
	if len(previous) != int(p.cfg.Threshold) {
		return nil, fmt.Errorf("%w: previous commitment has %d coefficients, want %d",
			ErrDKGConfig, len(previous), p.cfg.Threshold)
	}
	aggregate := make([]*ecc.Element, len(previous))
	for i := range previous {
		element, err := decodeCommitmentElement(g, previous[i])
		if err != nil {
			return nil, fmt.Errorf("%w: previous commitment coefficient %d", ErrDKGConfig, i)
		}
		aggregate[i] = element
	}
	for id := uint16(1); id <= p.cfg.MaxSigners; id++ {
		commitment := decoded[id]
		if commitment == nil {
			return nil, dkgErrorf(id, ErrDKGIncomplete)
		}
		for i, element := range commitment {
			aggregate[i].Add(element)
		}
	}
	return aggregate, nil
}

// decodeCommitmentElement decodes one committed curve element. The identity is
// a valid commitment to a zero coefficient but the underlying decoder reports
// it as an error, because the identity is not a valid public key. A refresh's
// constant term is exactly that identity, so it is accepted explicitly and
// every other decode failure is still rejected.
func decodeCommitmentElement(g ecc.Group, encoded []byte) (*ecc.Element, error) {
	element := g.NewElement()
	if err := element.Decode(encoded); err != nil {
		if bytes.Equal(encoded, g.NewElement().Identity().Encode()) {
			return g.NewElement().Identity(), nil
		}
		return nil, err
	}
	return element, nil
}

// dkgGroup is the Edwards25519 group used by the FROST Ed25519 ciphersuite.
func dkgGroup() ecc.Group {
	return dkg.Edwards25519Sha512.Group()
}
