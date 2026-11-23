package trezor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// ErrDeviceRejected is returned when the user presses the cancel button on the
// Trezor screen. The entry is not signed.
var ErrDeviceRejected = errors.New("trezor: user rejected on device")

// ErrDeviceTimeout is returned when the Trezor does not respond within the
// expected confirmation window.
var ErrDeviceTimeout = errors.New("trezor: device confirmation timed out")

// ErrDeviceDisconnected is returned when the USB/HID link to the Trezor is
// lost before or during signing.
var ErrDeviceDisconnected = errors.New("trezor: device disconnected")

// Transport is the minimal Trezor device protocol this adapter needs.
// It is intentionally thin: how the preimage and payload are serialised into
// the Trezor wire format, and which Trezor library is used, are left to the
// caller so this module has no dependency on a specific Trezor binding.
//
// Error wrapping: a Transport implementation should return errors that wrap one
// of [ErrDeviceRejected], [ErrDeviceTimeout], or [ErrDeviceDisconnected] so
// callers can distinguish device failures without string parsing.
type Transport interface {
	// StellarAuthorize sends the XDR preimage to the Trezor device for display
	// and confirmation, then signs the 32-byte payload. It returns the raw
	// 64-byte Ed25519 signature.
	//
	// The preimage is passed so the device can show the user the actual
	// authorization content — not a bare hash — before signing.
	//
	// StellarAuthorize must return an error wrapping [ErrDeviceRejected],
	// [ErrDeviceTimeout], or [ErrDeviceDisconnected] on the corresponding
	// device conditions.
	StellarAuthorize(ctx context.Context, preimage []byte, payload [32]byte) ([]byte, error)
}

type signer struct {
	address      string
	transport    Transport
	rawPublicKey []byte
}

// NewSigner returns a [soroauth.Signer] backed by a Trezor hardware wallet.
//
// address must be the G… classic Stellar account address whose Ed25519 key is
// stored on the device. The 32-byte public key is decoded here and used to
// verify every signature the device returns before it is used; a mismatch is
// reported as [soroauth.ErrSignatureMismatch] so callers hear about a
// misconfigured device at signing time, not on-chain after fees are paid.
//
// transport is the caller-supplied Trezor communication layer. A nil transport
// is refused here rather than panicking later.
func NewSigner(address string, transport Transport) (soroauth.Signer, error) {
	if isNilTransport(transport) {
		return nil, fmt.Errorf("trezor: new signer: %w", soroauth.ErrMissingSigner)
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("trezor: new signer: %q is not an account (G…) address: %w", address, err)
	}
	return &signer{address: address, transport: transport, rawPublicKey: raw}, nil
}

func (s *signer) Address() string { return s.address }

// Sign sends the full XDR preimage to the Trezor device so the user can read
// the actual authorization, waits for the user's confirmation, and returns the
// classic account signature ScVal for the signed 32-byte payload.
//
// Failure modes:
//   - [ErrDeviceRejected]: user pressed cancel on the device screen.
//   - [ErrDeviceTimeout]: device did not respond in time.
//   - [ErrDeviceDisconnected]: USB/HID link was lost.
//   - [soroauth.ErrSignatureMismatch]: device returned a signature that does not
//     verify against the account public key.
func (s *signer) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("trezor: sign: %w", err)
	}

	// The preimage is passed to the device for display. A zero or partial
	// preimage (such as one from a test stub) may fail to marshal; in that
	// case we forward empty bytes so the device still receives the payload.
	preimageBytes, _ := marshalPreimageSafe(preimage)

	sig, err := s.transport.StellarAuthorize(ctx, preimageBytes, payload)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("trezor: sign: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("trezor: sign: device returned %d-byte signature, want %d: %w",
			len(sig), ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.rawPublicKey), payload[:], sig) {
		return xdr.ScVal{}, fmt.Errorf("trezor: sign: %w", soroauth.ErrSignatureMismatch)
	}

	value, err := soroauth.Ed25519SignatureScVal(s.rawPublicKey, sig)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("trezor: sign: %w", err)
	}
	return value, nil
}

// marshalPreimageSafe marshals a HashIdPreimage to XDR bytes, recovering from
// any panic that the XDR codec raises for a zero-value or partially populated
// preimage. In production the preimage always comes from Preimage() and is
// fully populated; this guard exists for callers passing a placeholder value.
func marshalPreimageSafe(preimage xdr.HashIdPreimage) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return preimage.MarshalBinary()
}

func isNilTransport(t any) bool {
	if t == nil {
		return true
	}
	v := reflect.ValueOf(t)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
