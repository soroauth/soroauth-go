package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// The Ledger Stellar app's APDU surface, read from LedgerHQ/app-stellar
// src/main.rs: CLA 0xE0, INS_GET_PK 0x02, INS_SIGN_SOROBAN_AUTH 0x0A, with
// P1 0x00/0x80 for first/subsequent chunks and P2 0x80/0x00 for more/last.
const (
	ledgerCLA            = 0xE0
	ledgerINSGetPubKey   = 0x02
	ledgerINSSignSoroban = 0x0A

	ledgerP1First = 0x00
	ledgerP1More  = 0x80
	ledgerP2Last  = 0x00
	ledgerP2More  = 0x80

	// maxLedgerAPDUData keeps every command APDU inside the short-APDU limit of
	// 255 data bytes with room to spare. The device caps raw data far above
	// this (4 KiB on Nano X, 8 KiB elsewhere), so the chunk size is a transport
	// concern, not a device one.
	maxLedgerAPDUData = 240
)

// Status words returned by the Ledger Stellar app, from LedgerHQ/app-stellar
// src/sw.rs, plus Ledger's device-wide LockedDevice status word.
const (
	ledgerSWOK                     = 0x9000
	ledgerSWLocked                 = 0x5515
	ledgerSWDeny                   = 0x6985
	ledgerSWWrongLength            = 0x6700
	ledgerSWWrongApduLength        = 0x6A87
	ledgerSWWrongP1P2              = 0x6B00
	ledgerSWBlindSigningNotEnabled = 0x6C66
	ledgerSWInsNotSupported        = 0x6D00
	ledgerSWCLANotSupported        = 0x6E00
)

// LedgerTransport exchanges one APDU with a connected device. Implementations
// speak whatever link is available — USB HID, a Speculos emulator over TCP, a
// test double — but the bytes are always a raw command APDU and the return
// value is always the raw response APDU (data followed by the two status bytes).
//
// This library ships no transport, on purpose: the transport is the part that
// depends on the operating system, the device model and the caller's I/O
// library, and none of those belong in a signing library. It ships the logic
// that turns a payload into the right APDUs and interprets the answers.
type LedgerTransport interface {
	// Exchange sends apdu and returns the device's response, including the two
	// trailing status bytes. It returns an error only for a transport-level
	// failure; a device-level refusal is a status word in the response.
	Exchange(ctx context.Context, apdu []byte) ([]byte, error)
}

// LedgerSignerOption configures a LedgerSigner.
type LedgerSignerOption func(*ledgerSignerConfig)

type ledgerSignerConfig struct {
	accountIndex uint32
}

// WithLedgerAccount selects the account in the Stellar BIP-44 path. The path is
// fixed to 44'/148'/account'; the default account is 0.
func WithLedgerAccount(index uint32) LedgerSignerOption {
	return func(cfg *ledgerSignerConfig) { cfg.accountIndex = index }
}

// LedgerSigner is a Signer backed by a Ledger hardware wallet running the
// Stellar app.
//
// It produces the built-in classic-account signature shape, because the device
// derives an ordinary ed25519 Stellar key at 44'/148'/account'.
//
// # What the device displays
//
// The signer sends the full HashIdPreimage XDR to the device using
// INS_SIGN_SOROBAN_AUTH (0x0A). The Stellar app parses that preimage and shows a
// "Review Soroban Authorization" screen whose fields are rendered from the
// parsed `HashIDPreimage::SorobanAuthorization`
// (LedgerHQ/app-stellar src/app_ui/sign_soroban_auth.rs), then computes
// SHA-256 over the preimage and signs it (src/handlers/sign_soroban_auth.rs,
// src/crypto.rs `hash`). Because the payload this library signs is exactly
// SHA-256(XDR(HashIdPreimage)), the bytes the device signs and the payload are
// the same, and Sign verifies that before sending anything.
//
// Two limits you must not assume away:
//
//   - The review is gated on the app's "Blind signing" setting. Even though a
//     decoded review is displayed, the app refuses with status 0x6C66 when that
//     setting is off (src/app_ui/sign_soroban_auth.rs checks
//     `is_blind_signing_enabled`). The user must enable it in the Stellar app's
//     settings, and a refusal surfaces here as ErrLedgerBlindSigningDisabled.
//   - What is displayed is the parsed preimage, not a human explanation of the
//     transaction. Deciding whether the invocation is the one the user intends
//     is the wallet's job; this library neither renders nor interprets it.
//
// # Errors
//
// A missing or unreachable device is ErrLedgerUnavailable, a locked device is
// ErrLedgerLocked, a device not running the Stellar app is ErrLedgerWrongApp,
// a user rejection is ErrLedgerDenied, and disabled blind signing is
// ErrLedgerBlindSigningDisabled — four distinct actions for four distinct
// problems, rather than one "device error".
type LedgerSigner struct {
	transport LedgerTransport
	path      []uint32
	address   string
	rawKey    []byte
	publicKey ed25519.PublicKey
}

// NewLedgerSigner opens a session: it reads the public key for
// 44'/148'/account' from the device and derives the account address, which
// Address reports. It performs device I/O, so it takes a context.
//
// The address is derived from the device rather than supplied by the caller: a
// hardware signer that signs for an address it was merely told about could be
// pointed at the wrong account, and this removes that possibility.
func NewLedgerSigner(ctx context.Context, transport LedgerTransport, opts ...LedgerSignerOption) (*LedgerSigner, error) {
	if transport == nil {
		return nil, fmt.Errorf("soroauth: new ledger signer: %w", ErrLedgerUnavailable)
	}
	var cfg ledgerSignerConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	path := []uint32{
		44 | 0x80000000,
		148 | 0x80000000,
		cfg.accountIndex | 0x80000000,
	}

	s := &LedgerSigner{transport: transport, path: path}

	response, err := s.exchange(ctx, ledgerBuildGetPubKeyAPDU(path))
	if err != nil {
		return nil, fmt.Errorf("soroauth: new ledger signer: %w", err)
	}
	if len(response) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("soroauth: new ledger signer: public key response is %d bytes, want %d: %w",
			len(response), ed25519.PublicKeySize, ErrLedgerUnavailable)
	}
	address, err := strkey.Encode(strkey.VersionByteAccountID, response)
	if err != nil {
		return nil, fmt.Errorf("soroauth: new ledger signer: encoding the device's address: %w", err)
	}

	s.address = address
	s.rawKey = response
	s.publicKey = ed25519.PublicKey(response)
	return s, nil
}

// Address returns the G… account the device's key derives.
func (s *LedgerSigner) Address() string { return s.address }

// Sign sends the preimage to the device for review and signing, verifies the
// returned signature, and returns the classic-account signature shape.
func (s *LedgerSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: %w", err)
	}
	if s.transport == nil || s.publicKey == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: %w", ErrMissingSigner)
	}

	// The device hashes the preimage itself; check that the digest the caller
	// handed over is the same one, rather than discovering the mismatch only
	// after the user has approved a review on the device.
	expected, err := Payload(preimage)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: %w", err)
	}
	if !bytes.Equal(expected[:], payload[:]) {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: payload does not match the preimage: %w", ErrSignatureMismatch)
	}

	preimageXDR, err := preimage.MarshalBinary()
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: encoding the preimage: %w", err)
	}

	signature, err := s.signPreimage(ctx, preimageXDR)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: device returned a %d-byte signature, want %d: %w",
			len(signature), ed25519.SignatureSize, ErrLedgerUnavailable)
	}
	if !ed25519.Verify(s.publicKey, payload[:], signature) {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ledger sign: %w", ErrSignatureMismatch)
	}

	return scVec(accountSignature(s.rawKey, signature)), nil
}

// signPreimage chunks preimageXDR across INS_SIGN_SOROBAN_AUTH APDUs. The first
// chunk carries the BIP-32 path ahead of the data; only the final chunk carries
// a response, which is the signature.
func (s *LedgerSigner) signPreimage(ctx context.Context, preimageXDR []byte) ([]byte, error) {
	path := ledgerEncodePath(s.path)

	var signature []byte
	offset := 0
	for {
		first := offset == 0

		capacity := maxLedgerAPDUData
		if first {
			capacity -= len(path)
		}
		if capacity <= 0 {
			return nil, fmt.Errorf("the path leaves no room for preimage data: %w", ErrLedgerUnavailable)
		}

		remaining := len(preimageXDR) - offset
		size := remaining
		if size > capacity {
			size = capacity
		}
		last := offset+size >= len(preimageXDR)

		data := make([]byte, 0, len(path)+size)
		if first {
			data = append(data, path...)
		}
		data = append(data, preimageXDR[offset:offset+size]...)

		p1 := byte(ledgerP1More)
		if first {
			p1 = ledgerP1First
		}
		p2 := byte(ledgerP2More)
		if last {
			p2 = ledgerP2Last
		}

		response, err := s.exchange(ctx, ledgerBuildAPDU(ledgerINSSignSoroban, p1, p2, data))
		if err != nil {
			return nil, err
		}
		if last {
			signature = response
			break
		}
		offset += size
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("the device returned no signature: %w", ErrLedgerUnavailable)
	}
	return signature, nil
}

// exchange sends one APDU and decodes the status word.
func (s *LedgerSigner) exchange(ctx context.Context, apdu []byte) ([]byte, error) {
	response, err := s.transport.Exchange(ctx, apdu)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLedgerUnavailable, err)
	}
	if len(response) < 2 {
		return nil, fmt.Errorf("the device returned a %d-byte response, too short for a status word: %w",
			len(response), ErrLedgerUnavailable)
	}
	data := response[:len(response)-2]
	status := uint16(response[len(response)-2])<<8 | uint16(response[len(response)-1])

	switch status {
	case ledgerSWOK:
		return data, nil
	case ledgerSWLocked:
		return nil, ErrLedgerLocked
	case ledgerSWDeny:
		return nil, ErrLedgerDenied
	case ledgerSWBlindSigningNotEnabled:
		return nil, ErrLedgerBlindSigningDisabled
	case ledgerSWCLANotSupported, ledgerSWInsNotSupported:
		return nil, ErrLedgerWrongApp
	case ledgerSWWrongLength, ledgerSWWrongApduLength, ledgerSWWrongP1P2:
		return nil, fmt.Errorf("the device rejected the APDU (status 0x%04X): %w", status, ErrLedgerUnavailable)
	default:
		return nil, fmt.Errorf("the device returned status 0x%04X: %w", status, ErrLedgerUnavailable)
	}
}

// ledgerEncodePath serializes the BIP-32 path the way the Stellar app expects:
// a length byte followed by one big-endian uint32 per segment
// (LedgerHQ/app-stellar src/bip32.rs).
func ledgerEncodePath(path []uint32) []byte {
	out := make([]byte, 0, 1+4*len(path))
	out = append(out, byte(len(path)))
	for _, segment := range path {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], segment)
		out = append(out, encoded[:]...)
	}
	return out
}

// ledgerBuildGetPubKeyAPDU builds INS_GET_PK with P1/P2 0, which returns the
// public key without an on-device confirmation prompt.
func ledgerBuildGetPubKeyAPDU(path []uint32) []byte {
	return ledgerBuildAPDU(ledgerINSGetPubKey, 0, 0, ledgerEncodePath(path))
}

// ledgerBuildAPDU builds a short command APDU: CLA INS P1 P2 Lc data.
func ledgerBuildAPDU(ins, p1, p2 byte, data []byte) []byte {
	apdu := make([]byte, 0, 5+len(data))
	apdu = append(apdu, ledgerCLA, ins, p1, p2, byte(len(data)))
	apdu = append(apdu, data...)
	return apdu
}

// Compile-time checks that the signers satisfy Signer.
var (
	_ Signer = (*VaultSigner)(nil)
	_ Signer = (*LedgerSigner)(nil)
)
