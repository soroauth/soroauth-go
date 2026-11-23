package pkcs11

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// PKCS#11 constants used when searching for keys and opening sessions.
// Values are from the PKCS#11 v3.0 specification.
const (
	// CKF_SERIAL_SESSION must be set when opening a session.
	CKF_SERIAL_SESSION uint = 0x00000004
	// CKU_USER is the standard user role for Login.
	CKU_USER uint = 1
	// CKA_CLASS identifies the object class attribute.
	CKA_CLASS uint = 0x0000_0000
	// CKA_LABEL is the object label attribute.
	CKA_LABEL uint = 0x0000_0003
	// CKO_PRIVATE_KEY is the object class value for private keys.
	CKO_PRIVATE_KEY uint = 0x0000_0003
	// CKM_EDDSA is the PKCS#11 v3.0 mechanism for Ed25519/Ed448 signatures.
	CKM_EDDSA uint = 0x0000_1057
)

// SessionHandle is a PKCS#11 session identifier.
type SessionHandle uint

// ObjectHandle is a PKCS#11 object identifier within a session.
type ObjectHandle uint

// Attribute is a single PKCS#11 attribute used to search for or describe
// an object. Type is a CKA_* constant; Value is the raw attribute bytes.
type Attribute struct {
	Type  uint
	Value []byte
}

// PINFunc is called by [signer.Sign] each time it needs to authenticate a
// PKCS#11 session. Using a function rather than a string field ensures the
// PIN is never stored in a struct that could appear in a log or error message.
type PINFunc func() ([]byte, error)

// P11Ctx is the minimal PKCS#11 session interface this adapter needs. It is
// satisfied by wrapping github.com/miekg/pkcs11 or any compatible binding.
// Tests supply a local fake so no real token is required.
type P11Ctx interface {
	// OpenSession opens a new PKCS#11 session on the given slot.
	OpenSession(slotID uint, flags uint) (SessionHandle, error)
	// CloseSession closes sh. The signer calls it after every Sign.
	CloseSession(sh SessionHandle) error
	// Login authenticates sh with the given user type and PIN.
	// The PIN comes from [PINFunc]; the signer never stores it.
	Login(sh SessionHandle, userType uint, pin string) error
	// Logout removes the session's authentication.
	Logout(sh SessionHandle) error
	// FindObjectsInit begins an object search filtered by template.
	FindObjectsInit(sh SessionHandle, template []Attribute) error
	// FindObjects returns up to max matching object handles.
	FindObjects(sh SessionHandle, max int) ([]ObjectHandle, bool, error)
	// FindObjectsFinal ends the search started by FindObjectsInit.
	FindObjectsFinal(sh SessionHandle) error
	// SignInit initialises a signing operation using mechanismType on key.
	SignInit(sh SessionHandle, mechanismType uint, key ObjectHandle) error
	// Sign returns the signature over msg using the operation from SignInit.
	Sign(sh SessionHandle, msg []byte) ([]byte, error)
}

type signer struct {
	address      string
	slotID       uint
	keyLabel     string
	ctx          P11Ctx
	pin          PINFunc
	rawPublicKey []byte
}

// NewSigner returns a [soroauth.Signer] backed by the Ed25519 private key
// stored in the PKCS#11 token at slotID under the given keyLabel.
//
// address must be the G… classic Stellar account address whose public key
// corresponds to the PKCS#11 key. The 32-byte public key is decoded here and
// used to verify the signature after each call; a mismatch is returned as
// [soroauth.ErrSignatureMismatch] rather than passed to the network.
//
// pin is called on every Sign to obtain the PKCS#11 user PIN. It is never
// stored; it is zeroed from local memory immediately after use. No error
// message produced by this adapter ever contains the PIN value.
//
// A nil ctx is refused here rather than panicking later.
func NewSigner(address string, slotID uint, keyLabel string, ctx P11Ctx, pin PINFunc) (soroauth.Signer, error) {
	if isNilCtx(ctx) {
		return nil, fmt.Errorf("pkcs11: new signer: %w", soroauth.ErrMissingSigner)
	}
	if keyLabel == "" {
		return nil, fmt.Errorf("pkcs11: new signer: key label is empty: %w", soroauth.ErrMissingSigner)
	}
	if pin == nil {
		return nil, fmt.Errorf("pkcs11: new signer: pin func is nil: %w", soroauth.ErrMissingSigner)
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: new signer: %q is not an account (G…) address: %w", address, err)
	}
	return &signer{
		address:      address,
		slotID:       slotID,
		keyLabel:     keyLabel,
		ctx:          ctx,
		pin:          pin,
		rawPublicKey: raw,
	}, nil
}

func (s *signer) Address() string { return s.address }

// Sign opens a PKCS#11 session, authenticates with the PIN from s.pin, finds
// the Ed25519 private key by label, signs the 32-byte payload, verifies the
// returned signature against the account's public key, and returns the classic
// account signature ScVal.
//
// The session is closed and the PIN is discarded whether Sign succeeds or
// fails. The error message never contains the PIN value.
func (s *signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: %w", err)
	}

	sh, err := s.ctx.OpenSession(s.slotID, CKF_SERIAL_SESSION)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: open session on slot %d: %w", s.slotID, err)
	}
	defer func() { _ = s.ctx.CloseSession(sh) }()

	pinBytes, err := s.pin()
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: get pin: %w", err)
	}
	pinStr := string(pinBytes)
	// Zero the local copy of the PIN as soon as Login is done.
	defer func() {
		for i := range pinBytes {
			pinBytes[i] = 0
		}
	}()

	if err := s.ctx.Login(sh, CKU_USER, pinStr); err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: login on slot %d: %w", s.slotID, err)
	}
	defer func() { _ = s.ctx.Logout(sh) }()

	key, err := s.findKey(sh)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: find key %q: %w", s.keyLabel, err)
	}

	if err := s.ctx.SignInit(sh, CKM_EDDSA, key); err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: init for key %q: %w", s.keyLabel, err)
	}

	sig, err := s.ctx.Sign(sh, payload[:])
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: sign with key %q: %w", s.keyLabel, err)
	}

	if len(sig) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: key %q returned %d-byte signature, want %d: %w",
			s.keyLabel, len(sig), ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.rawPublicKey), payload[:], sig) {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: signature for key %q did not verify: %w",
			s.keyLabel, soroauth.ErrSignatureMismatch)
	}

	value, err := soroauth.Ed25519SignatureScVal(s.rawPublicKey, sig)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("pkcs11: sign: %w", err)
	}
	return value, nil
}

// findKey searches the open session for a CKO_PRIVATE_KEY with the signer's
// key label and returns the first matching handle.
func (s *signer) findKey(sh SessionHandle) (ObjectHandle, error) {
	template := []Attribute{
		{Type: CKA_CLASS, Value: uint32ToBytes(uint32(CKO_PRIVATE_KEY))},
		{Type: CKA_LABEL, Value: []byte(s.keyLabel)},
	}
	if err := s.ctx.FindObjectsInit(sh, template); err != nil {
		return 0, fmt.Errorf("find objects init: %w", err)
	}
	handles, _, err := s.ctx.FindObjects(sh, 1)
	_ = s.ctx.FindObjectsFinal(sh)
	if err != nil {
		return 0, fmt.Errorf("find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("no private key with label %q found in slot %d", s.keyLabel, s.slotID)
	}
	return handles[0], nil
}

// uint32ToBytes encodes a uint32 as 4 big-endian bytes for a PKCS#11
// CKA_CLASS attribute value.
func uint32ToBytes(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// isNilCtx reports whether ctx is nil or holds a typed nil pointer.
func isNilCtx(ctx any) bool {
	if ctx == nil {
		return true
	}
	v := reflect.ValueOf(ctx)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
