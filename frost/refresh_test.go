package frost

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// refreshAll runs one honest refresh across every participant and returns the
// new shares plus the public commitments.
func refreshAll(t *testing.T, current []DKGShare, epoch uint32) ([]DKGShare, []RefreshCommitment) {
	t.Helper()
	cfg := RefreshConfig{
		Threshold:  current[0].Threshold,
		MaxSigners: current[0].MaxSigners,
		Epoch:      epoch,
	}
	participants := make([]*RefreshParticipant, len(current))
	for i := range participants {
		p, err := NewRefreshParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewRefreshParticipant(%d): %v", i+1, err)
		}
		participants[i] = p
	}
	commitments := make([]RefreshCommitment, len(participants))
	for i, p := range participants {
		commitments[i] = p.Commitment()
	}

	received := make([]map[uint16][]byte, len(participants))
	for i := range received {
		received[i] = make(map[uint16][]byte)
	}
	for _, p := range participants {
		shares, err := p.Shares(commitments)
		if err != nil {
			t.Fatalf("Shares: %v", err)
		}
		for recipient, share := range shares {
			received[recipient-1][p.ID()] = share
		}
	}

	next := make([]DKGShare, len(participants))
	for i, p := range participants {
		share, err := p.Apply(current[i], received[i], commitments)
		if err != nil {
			t.Fatalf("Apply(%d): %v", i+1, err)
		}
		next[i] = share
	}
	return next, commitments
}

// signWithShares signs a fixed entry with the first threshold shares and
// verifies the result under the group verification key.
func signWithShares(t *testing.T, shares []DKGShare, threshold int) ([32]byte, []byte) {
	t.Helper()
	address := testAddress(t, "refresh-group")
	publicKeyShares := make([][]byte, len(shares))
	for i, share := range shares {
		publicKeyShares[i] = share.PublicKeyShare
	}
	coord, err := NewFROSTCoordinator(shares[0].VerificationKey, publicKeyShares,
		threshold, len(shares), address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	participants := make([]*FROSTParticipant, threshold)
	for i := 0; i < threshold; i++ {
		participant, err := NewFROSTParticipant(shares[i].SecretShare, shares[i].PublicKeyShare, uint16(i+1), coord)
		if err != nil {
			t.Fatalf("NewFROSTParticipant(%d): %v", i+1, err)
		}
		participants[i] = participant
	}
	signer, err := NewFROSTSigner(coord, participants)
	if err != nil {
		t.Fatalf("NewFROSTSigner: %v", err)
	}

	entry := dkgEntry(t, address)
	preimage, payload := testPreimagePayload(t, entry)
	value, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signature := extractSignatureBytes(value)
	if err := VerifySignature(shares[0].VerificationKey, payload[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	return payload, signature
}

func TestRefreshPreservesGroupKeyAndSigns(t *testing.T) {
	shares, _, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})
	beforePayload, beforeSignature := signWithShares(t, shares, 2)

	next, commitments := refreshAll(t, shares, 1)
	if err := VerifySignature(shares[0].VerificationKey, beforePayload[:], beforeSignature); err != nil {
		t.Fatalf("the pre-refresh signature no longer verifies: %v", err)
	}

	for i := range next {
		if !bytes.Equal(next[i].VerificationKey, shares[i].VerificationKey) {
			t.Fatalf("participant %d's group key changed across the refresh", i+1)
		}
		if next[i].Epoch != 1 {
			t.Fatalf("participant %d epoch = %d, want 1", i+1, next[i].Epoch)
		}
		if bytes.Equal(next[i].SecretShare, shares[i].SecretShare) {
			t.Fatalf("participant %d's secret share did not change", i+1)
		}
		if bytes.Equal(next[i].PublicKeyShare, shares[i].PublicKeyShare) {
			t.Fatalf("participant %d's public key share did not change", i+1)
		}
	}
	if len(commitments) != 3 {
		t.Fatalf("commitments = %d, want 3", len(commitments))
	}

	// The refreshed group signs under exactly the same verification key.
	signWithShares(t, next, 2)
}

func TestRefreshRejectsMixedEpochShares(t *testing.T) {
	shares, _, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})
	next, _ := refreshAll(t, shares, 1)

	address := testAddress(t, "refresh-group")
	publicKeyShares := [][]byte{next[0].PublicKeyShare, next[1].PublicKeyShare, next[2].PublicKeyShare}
	coord, err := NewFROSTCoordinator(next[0].VerificationKey, publicKeyShares, 2, 3, address)
	if err != nil {
		t.Fatalf("NewFROSTCoordinator: %v", err)
	}

	// Participant 1 missed the refresh and still holds its epoch-0 secret.
	stale, err := NewFROSTParticipant(shares[0].SecretShare, next[0].PublicKeyShare, 1, coord)
	if err != nil {
		return // rejected at construction, which is also a failure to sign
	}
	fresh, err := NewFROSTParticipant(next[1].SecretShare, next[1].PublicKeyShare, 2, coord)
	if err != nil {
		t.Fatalf("NewFROSTParticipant (fresh): %v", err)
	}
	signer, err := NewFROSTSigner(coord, []*FROSTParticipant{stale, fresh})
	if err != nil {
		t.Fatalf("NewFROSTSigner: %v", err)
	}

	entry := dkgEntry(t, address)
	preimage, payload := testPreimagePayload(t, entry)
	if _, err := signer.Sign(context.Background(), preimage, payload); err == nil {
		t.Fatal("a stale share combined with a refreshed share produced a signature")
	}
}

func TestRefreshMissingParticipantIsNamed(t *testing.T) {
	cfg := RefreshConfig{Threshold: 2, MaxSigners: 3, Epoch: 1}

	participants := make([]*RefreshParticipant, 2)
	for i := range participants {
		p, err := NewRefreshParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewRefreshParticipant: %v", err)
		}
		participants[i] = p
	}
	commitments := []RefreshCommitment{participants[0].Commitment(), participants[1].Commitment()}

	_, err := participants[0].Shares(commitments)
	if err == nil {
		t.Fatal("Shares accepted an incomplete commitment set")
	}
	if !errors.Is(err, ErrDKGIncomplete) {
		t.Fatalf("error = %v, want ErrDKGIncomplete", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 3 {
		t.Fatalf("error does not name participant 3: %v", err)
	}
}

func TestRefreshWrongEpochFailsClosed(t *testing.T) {
	shares, _, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})
	cfg := RefreshConfig{Threshold: 2, MaxSigners: 3, Epoch: 2}
	participant, err := NewRefreshParticipant(cfg, 1)
	if err != nil {
		t.Fatalf("NewRefreshParticipant: %v", err)
	}
	others := make([]RefreshCommitment, 0, 3)
	for id := uint16(1); id <= 3; id++ {
		if id == 1 {
			others = append(others, participant.Commitment())
			continue
		}
		p, err := NewRefreshParticipant(cfg, id)
		if err != nil {
			t.Fatalf("NewRefreshParticipant: %v", err)
		}
		others = append(others, p.Commitment())
	}
	if _, err := participant.Apply(shares[0], nil, others); !errors.Is(err, ErrRefreshEpoch) {
		t.Fatalf("Apply with a skipped epoch = %v, want ErrRefreshEpoch", err)
	}
}

func TestRefreshRejectsNonZeroConstantTerm(t *testing.T) {
	cfg := RefreshConfig{Threshold: 2, MaxSigners: 3, Epoch: 1}
	participants := make([]*RefreshParticipant, 3)
	commitments := make([]RefreshCommitment, 3)
	for i := range participants {
		p, err := NewRefreshParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewRefreshParticipant: %v", err)
		}
		participants[i] = p
		commitments[i] = p.Commitment()
	}

	// A contribution whose constant term is not the identity would change the
	// group secret instead of refreshing it.
	commitments[1].Commitment[0] = dkgGroup().Base().Encode()
	_, err := participants[0].Shares(commitments)
	if err == nil {
		t.Fatal("Shares accepted a contribution with a non-zero constant term")
	}
	if !errors.Is(err, ErrDKGInvalidContribution) {
		t.Fatalf("error = %v, want ErrDKGInvalidContribution", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 2 {
		t.Fatalf("error does not name participant 2: %v", err)
	}
}

func TestRefreshRejectsTamperedShare(t *testing.T) {
	shares, _, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})
	cfg := RefreshConfig{Threshold: 2, MaxSigners: 3, Epoch: 1}

	participants := make([]*RefreshParticipant, 3)
	for i := range participants {
		p, err := NewRefreshParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewRefreshParticipant: %v", err)
		}
		participants[i] = p
	}
	commitments := make([]RefreshCommitment, 3)
	for i, p := range participants {
		commitments[i] = p.Commitment()
	}

	received := make(map[uint16][]byte, 2)
	for _, p := range participants[1:] {
		sent, err := p.Shares(commitments)
		if err != nil {
			t.Fatalf("Shares: %v", err)
		}
		received[p.ID()] = sent[1]
	}
	received[2] = dkgGroup().NewScalar().SetUInt64(9).Encode()

	if _, err := participants[0].Apply(shares[0], received, commitments); err == nil {
		t.Fatal("Apply accepted a refresh share that fails vss_verify")
	} else {
		if !errors.Is(err, ErrDKGInvalidContribution) {
			t.Fatalf("error = %v, want ErrDKGInvalidContribution", err)
		}
		var attributed *DKGError
		if !errors.As(err, &attributed) || attributed.ParticipantID != 2 {
			t.Fatalf("error does not name participant 2: %v", err)
		}
	}
}
