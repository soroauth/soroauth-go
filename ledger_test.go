package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ledgerTestSeed is a public, deterministic seed used only by these tests.
var ledgerTestSeed = sha256.Sum256([]byte("soroauth-ledger-test-key"))

func ledgerTestKeypair(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(ledgerTestSeed)
	if err != nil {
		t.Fatalf("deriving the Ledger test keypair: %v", err)
	}
	return kp
}

func ledgerStatus(code uint16) []byte {
	return []byte{byte(code >> 8), byte(code)}
}

// fakeLedger implements LedgerTransport. It speaks the Stellar app's APDU
// surface: INS_GET_PK returns the public key, and INS_SIGN_SOROBAN_AUTH
// accumulates the preimage across chunks, SHA-256-hashes it and signs it, just
// as the device does.
type fakeLedger struct {
	seed             []byte
	locked           bool
	wrongApp         bool
	blindDisabled    bool
	deny             bool
	corruptSignature bool
	truncatedKey     bool
	transportErr     error

	apdus       [][]byte
	accumulated []byte
}

func (f *fakeLedger) Exchange(ctx context.Context, apdu []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.transportErr != nil {
		return nil, f.transportErr
	}
	f.apdus = append(f.apdus, append([]byte{}, apdu...))

	if len(apdu) < 5 {
		return nil, errors.New("short apdu")
	}
	if f.locked {
		return ledgerStatus(ledgerSWLocked), nil
	}
	if f.wrongApp {
		return ledgerStatus(ledgerSWCLANotSupported), nil
	}

	ins, lc := apdu[1], int(apdu[4])
	if len(apdu) < 5+lc {
		return nil, errors.New("truncated apdu")
	}
	data := apdu[5 : 5+lc]

	switch ins {
	case ledgerINSGetPubKey:
		publicKey := ed25519.NewKeyFromSeed(f.seed).Public().(ed25519.PublicKey)
		if f.truncatedKey {
			publicKey = publicKey[:16]
		}
		return append(append([]byte{}, publicKey...), ledgerStatus(ledgerSWOK)...), nil

	case ledgerINSSignSoroban:
		if f.blindDisabled {
			return ledgerStatus(ledgerSWBlindSigningNotEnabled), nil
		}
		if f.deny {
			return ledgerStatus(ledgerSWDeny), nil
		}
		if apdu[2] == ledgerP1First {
			segments := int(data[0])
			f.accumulated = append(f.accumulated, data[1+4*segments:]...)
		} else {
			f.accumulated = append(f.accumulated, data...)
		}
		if apdu[3] == ledgerP2More {
			return ledgerStatus(ledgerSWOK), nil
		}
		hash := sha256.Sum256(f.accumulated)
		f.accumulated = nil
		signature := ed25519.Sign(ed25519.NewKeyFromSeed(f.seed), hash[:])
		if f.corruptSignature {
			signature = make([]byte, ed25519.SignatureSize)
		}
		return append(append([]byte{}, signature...), ledgerStatus(ledgerSWOK)...), nil
	}
	return ledgerStatus(ledgerSWInsNotSupported), nil
}

func TestLedgerSignerProducesTheAccountShape(t *testing.T) {
	kp := ledgerTestKeypair(t)
	device := &fakeLedger{seed: ledgerTestSeed[:]}

	signer, err := NewLedgerSigner(context.Background(), device)
	if err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	if got := signer.Address(); got != kp.Address() {
		t.Errorf("Address is %q, want %q", got, kp.Address())
	}

	preimage, payload := vaultTestPreimage(t)
	got, err := signer.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	want, err := NewEd25519Signer(kp).Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("the reference ed25519 signer failed: %v", err)
	}
	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the Ledger signature: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the reference signature: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("Ledger signature shape differs from the account shape\n want %x\n  got %x", wantBytes, gotBytes)
	}
}

func TestLedgerSignerChunksALargePreimage(t *testing.T) {
	device := &fakeLedger{seed: ledgerTestSeed[:]}
	signer, err := NewLedgerSigner(context.Background(), device)
	if err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	device.apdus = nil

	preimage, payload := ledgerLargePreimage(t)
	preimageXDR, err := preimage.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the preimage: %v", err)
	}
	if len(preimageXDR) <= maxLedgerAPDUData {
		t.Fatalf("the preimage is only %d bytes; it does not exercise chunking", len(preimageXDR))
	}

	if _, err := signer.Sign(context.Background(), preimage, payload); err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	// The chunk framing must be: first chunk P1=0x00, later chunks P1=0x80, and
	// exactly the last chunk carries P2=0x00.
	if len(device.apdus) < 2 {
		t.Fatalf("the signer sent %d APDUs, want more than one", len(device.apdus))
	}
	for i, apdu := range device.apdus {
		p1, p2 := apdu[2], apdu[3]
		if i == 0 && p1 != ledgerP1First {
			t.Errorf("APDU %d has P1 0x%02X, want the first-chunk value", i, p1)
		}
		if i > 0 && p1 != ledgerP1More {
			t.Errorf("APDU %d has P1 0x%02X, want the more-chunks value", i, p1)
		}
		last := i == len(device.apdus)-1
		if last && p2 != ledgerP2Last {
			t.Errorf("the last APDU has P2 0x%02X, want the last-chunk value", p2)
		}
		if !last && p2 != ledgerP2More {
			t.Errorf("APDU %d has P2 0x%02X, want the more-chunks value", i, p2)
		}
	}
}

func TestLedgerSignerReadsThePublicKeyWithTheExpectedAPDU(t *testing.T) {
	device := &fakeLedger{seed: ledgerTestSeed[:]}
	if _, err := NewLedgerSigner(context.Background(), device); err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	if len(device.apdus) != 1 {
		t.Fatalf("the constructor sent %d APDUs, want 1", len(device.apdus))
	}
	apdu := device.apdus[0]
	want := []byte{ledgerCLA, ledgerINSGetPubKey, 0x00, 0x00, 0x0D, 0x03,
		0x80, 0x00, 0x00, 0x2C, // 44'
		0x80, 0x00, 0x00, 0x94, // 148'
		0x80, 0x00, 0x00, 0x00, // 0'
	}
	if !bytes.Equal(apdu, want) {
		t.Errorf("get-public-key APDU is\n got %x\nwant %x", apdu, want)
	}
}

func TestLedgerSignerAccountOptionChangesThePath(t *testing.T) {
	device := &fakeLedger{seed: ledgerTestSeed[:]}
	if _, err := NewLedgerSigner(context.Background(), device, WithLedgerAccount(2)); err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	apdu := device.apdus[0]
	wantLast := []byte{0x80, 0x00, 0x00, 0x02}
	if !bytes.Equal(apdu[len(apdu)-4:], wantLast) {
		t.Errorf("path ends with %x, want account 2 %x", apdu[len(apdu)-4:], wantLast)
	}
}

func TestLedgerSignerMapsStatusWordsToNamedErrors(t *testing.T) {
	cases := []struct {
		name   string
		device *fakeLedger
		want   error
	}{
		{name: "locked", device: &fakeLedger{seed: ledgerTestSeed[:], locked: true}, want: ErrLedgerLocked},
		{name: "wrong app", device: &fakeLedger{seed: ledgerTestSeed[:], wrongApp: true}, want: ErrLedgerWrongApp},
		{name: "blind signing disabled", device: &fakeLedger{seed: ledgerTestSeed[:], blindDisabled: true}, want: ErrLedgerBlindSigningDisabled},
		{name: "denied", device: &fakeLedger{seed: ledgerTestSeed[:], deny: true}, want: ErrLedgerDenied},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// A device that fails at construction (locked, wrong app) errors
			// there; one that fails at signing errors on Sign. Cover both.
			signer, err := NewLedgerSigner(context.Background(), testCase.device)
			if err != nil {
				if !errors.Is(err, testCase.want) {
					t.Fatalf("constructor error %v does not match %v", err, testCase.want)
				}
				return
			}
			preimage, payload := vaultTestPreimage(t)
			if _, err := signer.Sign(context.Background(), preimage, payload); !errors.Is(err, testCase.want) {
				t.Fatalf("Sign error %v does not match %v", err, testCase.want)
			}
		})
	}
}

func TestLedgerSignerRejectsACorruptSignature(t *testing.T) {
	signer, err := NewLedgerSigner(context.Background(), &fakeLedger{seed: ledgerTestSeed[:], corruptSignature: true})
	if err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	preimage, payload := vaultTestPreimage(t)
	if _, err := signer.Sign(context.Background(), preimage, payload); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error %v does not match ErrSignatureMismatch", err)
	}
}

func TestLedgerSignerRejectsAMismatchedPayload(t *testing.T) {
	signer, err := NewLedgerSigner(context.Background(), &fakeLedger{seed: ledgerTestSeed[:]})
	if err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	preimage, _ := vaultTestPreimage(t)
	if _, err := signer.Sign(context.Background(), preimage, testPayload("wrong")); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("error %v does not match ErrSignatureMismatch", err)
	}
}

func TestLedgerSignerRejectsAShortPublicKeyResponse(t *testing.T) {
	_, err := NewLedgerSigner(context.Background(), &fakeLedger{seed: ledgerTestSeed[:], truncatedKey: true})
	if !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error %v does not match ErrLedgerUnavailable", err)
	}
}

func TestLedgerSignerRejectsATransportFailure(t *testing.T) {
	transportErr := errors.New("no device on the bus")
	_, err := NewLedgerSigner(context.Background(), &fakeLedger{transportErr: transportErr})
	if !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error %v does not match ErrLedgerUnavailable", err)
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("error %v does not wrap the transport error", err)
	}
}

func TestNewLedgerSignerRejectsANilTransport(t *testing.T) {
	if _, err := NewLedgerSigner(context.Background(), nil); !errors.Is(err, ErrLedgerUnavailable) {
		t.Fatalf("error %v does not match ErrLedgerUnavailable", err)
	}
}

func TestLedgerSignerHonorsContextCancellation(t *testing.T) {
	signer, err := NewLedgerSigner(context.Background(), &fakeLedger{seed: ledgerTestSeed[:]})
	if err != nil {
		t.Fatalf("NewLedgerSigner returned an unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	preimage, payload := vaultTestPreimage(t)
	if _, err := signer.Sign(ctx, preimage, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v does not match context.Canceled", err)
	}
}

// ledgerLargePreimage builds a preimage whose XDR exceeds one APDU, so chunk
// framing is exercised.
func ledgerLargePreimage(t *testing.T) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	contract, err := ParseAddress(testContractAddress(t, "soroauth-ledger-large-contract"))
	if err != nil {
		t.Fatalf("parsing the contract address: %v", err)
	}
	args := make([]xdr.ScVal, 0, 40)
	for i := 0; i < 40; i++ {
		value := xdr.Uint32(i)
		args = append(args, xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &value})
	}
	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			Nonce:                     xdr.Int64(99),
			SignatureExpirationLedger: 500,
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: contract,
						FunctionName:    xdr.ScSymbol("bulk"),
						Args:            args,
					},
				},
			},
		},
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the large preimage: %v", err)
	}
	return preimage, payload
}

func TestLedgerEncodePath(t *testing.T) {
	got := ledgerEncodePath([]uint32{44 | 0x80000000, 148 | 0x80000000, 0 | 0x80000000})
	want := []byte{0x03, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x94, 0x80, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("ledgerEncodePath returned %x, want %x", got, want)
	}
}
