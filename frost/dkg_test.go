package frost

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bytemare/dkg"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// dkgEntry builds the smallest V2 entry the signer can approve. The invocation
// is fixed so every run signs the same payload.
func dkgEntry(t *testing.T, address string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	parsed, err := soroauth.ParseAddress(address)
	if err != nil {
		t.Fatalf("ParseAddress(%q): %v", address, err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   parsed,
				Nonce:                     1,
				SignatureExpirationLedger: 1000,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &xdr.ContractId{1},
					},
					FunctionName: xdr.ScSymbol("transfer"),
					Args:         []xdr.ScVal{},
				},
			},
		},
	}
}

// dkgCeremony runs a complete honest ceremony and returns each participant's
// share plus the round-one packages and the round-two shares each participant
// received. The raw values are returned so a test can tamper with one.
func dkgCeremony(t *testing.T, cfg DKGConfig) ([]DKGShare, DKGTranscript, []*dkg.Round1Data, [](map[uint16]*dkg.Round2Data)) {
	t.Helper()
	participants := make([]*DKGParticipant, cfg.MaxSigners)
	for i := range participants {
		p, err := NewDKGParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewDKGParticipant(%d): %v", i+1, err)
		}
		participants[i] = p
	}

	round1 := make([]*dkg.Round1Data, len(participants))
	for i, p := range participants {
		data, err := p.Start()
		if err != nil {
			t.Fatalf("participant %d Start: %v", i+1, err)
		}
		round1[i] = data
	}

	// shareFor[i] is the round-two share participant i owes every peer.
	shareFor := make([]map[uint16]*dkg.Round2Data, len(participants))
	for i, p := range participants {
		shares, err := p.Continue(round1)
		if err != nil {
			t.Fatalf("participant %d Continue: %v", i+1, err)
		}
		shareFor[i] = shares
	}

	// received[i] is every round-two share addressed to participant i.
	received := make([]map[uint16]*dkg.Round2Data, len(participants))
	total := make([]map[uint16]*dkg.Round2Data, len(participants))
	for i := range received {
		received[i] = make(map[uint16]*dkg.Round2Data)
		total[i] = make(map[uint16]*dkg.Round2Data)
	}
	for sender, shares := range shareFor {
		for recipient, data := range shares {
			received[recipient-1][uint16(sender+1)] = data
			total[recipient-1][uint16(sender+1)] = data
		}
	}

	shares := make([]DKGShare, len(participants))
	for i, p := range participants {
		batch := make([]*dkg.Round2Data, 0, len(received[i]))
		for _, data := range received[i] {
			batch = append(batch, data)
		}
		share, err := p.Finalize(round1, batch)
		if err != nil {
			t.Fatalf("participant %d Finalize: %v", i+1, err)
		}
		shares[i] = share
	}

	transcript, err := NewDKGTranscript(cfg, round1)
	if err != nil {
		t.Fatalf("NewDKGTranscript: %v", err)
	}
	return shares, transcript, round1, total
}

func TestDKGCeremonyProducesUsableShares(t *testing.T) {
	const threshold, maxSigners = 2, 3
	shares, transcript, _, _ := dkgCeremony(t, DKGConfig{Threshold: threshold, MaxSigners: maxSigners})

	if err := transcript.Verify(); err != nil {
		t.Fatalf("transcript Verify: %v", err)
	}
	for i, share := range shares {
		if share.ParticipantID != uint16(i+1) {
			t.Errorf("share %d identifier = %d", i, share.ParticipantID)
		}
		if len(share.SecretShare) != 32 {
			t.Errorf("share %d secret length = %d", i, len(share.SecretShare))
		}
		if !bytes.Equal(share.VerificationKey, transcript.VerificationKey) {
			t.Errorf("share %d verification key differs from the transcript", i)
		}
		if share.Epoch != 0 {
			t.Errorf("share %d epoch = %d, want 0", i, share.Epoch)
		}
	}

	address := testAddress(t, "dkg-group")
	coord, err := NewFROSTCoordinator(
		transcript.VerificationKey,
		[][]byte{shares[0].PublicKeyShare, shares[1].PublicKeyShare, shares[2].PublicKeyShare},
		threshold, maxSigners, address)
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
	signature, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign with DKG shares: %v", err)
	}
	if err := VerifySignature(transcript.VerificationKey, payload[:], extractSignatureBytes(signature)); err != nil {
		t.Fatalf("the signature does not verify under the transcript's group key: %v", err)
	}
}

func TestDKGNoParticipantHoldsTheFullKey(t *testing.T) {
	shares, transcript, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})

	for i := range shares {
		for j := i + 1; j < len(shares); j++ {
			if bytes.Equal(shares[i].SecretShare, shares[j].SecretShare) {
				t.Fatalf("participants %d and %d received the same share", i+1, j+1)
			}
		}
	}

	// The transcript is public and must never carry a secret share. This is
	// the property that makes publishing it safe.
	encoded, err := json.Marshal(transcript)
	if err != nil {
		t.Fatalf("marshalling the transcript: %v", err)
	}
	for i, share := range shares {
		if strings.Contains(string(encoded), hex.EncodeToString(share.SecretShare)) {
			t.Errorf("the transcript contains participant %d's secret share", i+1)
		}
	}
}

func TestDKGAbortingParticipantIsNamed(t *testing.T) {
	cfg := DKGConfig{Threshold: 2, MaxSigners: 3}
	participants := make([]*DKGParticipant, 3)
	for i := range participants {
		p, err := NewDKGParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewDKGParticipant: %v", err)
		}
		participants[i] = p
	}

	// Only participants 1 and 2 contribute; 3 never starts.
	var round1 []*dkg.Round1Data
	for _, p := range participants[:2] {
		data, err := p.Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		round1 = append(round1, data)
	}

	_, err := participants[0].Continue(round1)
	if err == nil {
		t.Fatal("Continue accepted a set with an aborting participant")
	}
	if !errors.Is(err, ErrDKGIncomplete) {
		t.Fatalf("error = %v, want ErrDKGIncomplete", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 3 {
		t.Fatalf("error does not name participant 3: %v", err)
	}
}

func TestDKGWithheldRoundTwoShareIsNamed(t *testing.T) {
	cfg := DKGConfig{Threshold: 2, MaxSigners: 3}
	participants := make([]*DKGParticipant, 3)
	for i := range participants {
		p, err := NewDKGParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewDKGParticipant: %v", err)
		}
		participants[i] = p
	}
	round1 := make([]*dkg.Round1Data, 3)
	for i, p := range participants {
		data, err := p.Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		round1[i] = data
	}

	selfShares := make(map[uint16]*dkg.Round2Data, 2)
	for _, sender := range participants {
		shares, err := sender.Continue(round1)
		if err != nil {
			t.Fatalf("Continue: %v", err)
		}
		if data := shares[1]; data != nil {
			selfShares[data.SenderIdentifier] = data
		}
	}

	delete(selfShares, 3)
	_, err := participants[0].Finalize(round1, []*dkg.Round2Data{selfShares[2]})
	if err == nil {
		t.Fatal("Finalize accepted a set with a withheld share")
	}
	if !errors.Is(err, ErrDKGIncomplete) {
		t.Fatalf("error = %v, want ErrDKGIncomplete", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 3 {
		t.Fatalf("error does not name participant 3: %v", err)
	}
}

func TestDKGMalformedRoundOneIsAttributed(t *testing.T) {
	cfg := DKGConfig{Threshold: 2, MaxSigners: 3}
	round1 := make([]*dkg.Round1Data, 3)
	for i := range round1 {
		p, err := NewDKGParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewDKGParticipant: %v", err)
		}
		data, err := p.Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		round1[i] = data
	}

	round1[1].ProofOfKnowledge = nil
	observer, err := NewDKGParticipant(cfg, 3)
	if err != nil {
		t.Fatalf("NewDKGParticipant: %v", err)
	}
	_, err = observer.Continue(round1)
	if err == nil {
		t.Fatal("Continue accepted a package with no proof of knowledge")
	}
	if !errors.Is(err, ErrDKGInvalidContribution) {
		t.Fatalf("error = %v, want ErrDKGInvalidContribution", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 2 {
		t.Fatalf("error does not name participant 2: %v", err)
	}
}

func TestDKGMalformedRoundTwoIsAttributed(t *testing.T) {
	cfg := DKGConfig{Threshold: 2, MaxSigners: 3}
	participants := make([]*DKGParticipant, 3)
	for i := range participants {
		p, err := NewDKGParticipant(cfg, uint16(i+1))
		if err != nil {
			t.Fatalf("NewDKGParticipant: %v", err)
		}
		participants[i] = p
	}
	round1 := make([]*dkg.Round1Data, 3)
	for i, p := range participants {
		data, err := p.Start()
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
		round1[i] = data
	}

	selfShares := make(map[uint16]*dkg.Round2Data, 2)
	for _, sender := range participants {
		shares, err := sender.Continue(round1)
		if err != nil {
			t.Fatalf("Continue: %v", err)
		}
		if data := shares[1]; data != nil {
			selfShares[data.SenderIdentifier] = data
		}
	}

	// Participant 2 sends participant 1 a share that is not on the polynomial
	// participant 2 committed to.
	selfShares[2].SecretShare = dkg.Edwards25519Sha512.Group().NewScalar().SetUInt64(7)
	_, err := participants[0].Finalize(round1, []*dkg.Round2Data{selfShares[2], selfShares[3]})
	if err == nil {
		t.Fatal("Finalize accepted a share that fails vss_verify")
	}
	if !errors.Is(err, ErrDKGInvalidContribution) {
		t.Fatalf("error = %v, want ErrDKGInvalidContribution", err)
	}
	var attributed *DKGError
	if !errors.As(err, &attributed) || attributed.ParticipantID != 2 {
		t.Fatalf("error does not name participant 2: %v", err)
	}
}

func TestDKGTranscriptVerifyRejectsTampering(t *testing.T) {
	_, transcript, _, _ := dkgCeremony(t, DKGConfig{Threshold: 2, MaxSigners: 3})
	if err := transcript.Verify(); err != nil {
		t.Fatalf("honest transcript does not verify: %v", err)
	}

	tampered := transcript
	tampered.VerificationKey = append([]byte(nil), transcript.VerificationKey...)
	tampered.VerificationKey[0] ^= 0xff
	if err := tampered.Verify(); !errors.Is(err, ErrDKGVerification) {
		t.Fatalf("tampered verification key: error = %v, want ErrDKGVerification", err)
	}

	duplicated := transcript
	duplicated.Round1 = append(append([]*dkg.Round1Data(nil), transcript.Round1...), transcript.Round1[0])
	if err := duplicated.Verify(); err == nil {
		t.Fatal("a transcript with a duplicated participant verified")
	}
}

func TestDKGConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  DKGConfig
		id   uint16
		want error
	}{
		{"zero signers", DKGConfig{Threshold: 1, MaxSigners: 0}, 1, ErrDKGConfig},
		{"zero threshold", DKGConfig{Threshold: 0, MaxSigners: 3}, 1, ErrDKGConfig},
		{"threshold above signers", DKGConfig{Threshold: 4, MaxSigners: 3}, 1, ErrDKGConfig},
		{"threshold above account cap", DKGConfig{Threshold: 21, MaxSigners: 21}, 1, ErrDKGConfig},
		{"zero identifier", DKGConfig{Threshold: 2, MaxSigners: 3}, 0, ErrDKGConfig},
		{"identifier above signers", DKGConfig{Threshold: 2, MaxSigners: 3}, 4, ErrDKGConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDKGParticipant(tc.cfg, tc.id); !errors.Is(err, tc.want) {
				t.Fatalf("NewDKGParticipant(%+v, %d) = %v, want %v", tc.cfg, tc.id, err, tc.want)
			}
		})
	}
}
