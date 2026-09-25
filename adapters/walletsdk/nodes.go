package walletsdk

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

var (
	// ErrSignatureNotFound is returned when an entry carries no credential
	// node naming the address, so there is no signature to verify.
	ErrSignatureNotFound = errors.New("the entry stores no signature for this address")

	// ErrSignatureNotByKey is returned when a stored signature is present but
	// is not this key's signature over the entry's payload.
	ErrSignatureNotByKey = errors.New("the stored signature is not this key's signature over the entry")

	// ErrUnreadableSignature is returned when a stored signature is not in the
	// built-in {public_key, signature} shape an account signature must be. A
	// node left unsigned — whose signature is ScvVoid — is this error, which is
	// how an unsigned node fails verification.
	ErrUnreadableSignature = errors.New("the stored signature is not in the built-in account signature shape")
)

// signatureNodes returns the ScVal stored as the signature of every credential
// node in entry that names address.
//
// Nodes are returned in stored order, top-level first, then depth-first through
// the delegates — the order soroauth.Inspect reports them in. One address may
// appear at several nodes; CAP-71-01 has every node naming the same address
// carry byte-identical signatures, and this returns all of them so VerifyEntry
// checks all of them.
//
// A source-account entry has no node that carries a signature: the envelope's
// own signature covers it. That arm returns no nodes and no error, which is the
// same reading soroauth.Preimage and soroauth.Inspect take.
func signatureNodes(entry xdr.SorobanAuthorizationEntry, address string) ([]xdr.ScVal, error) {
	credentials := entry.Credentials

	switch credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return nil, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if credentials.Address == nil {
			return nil, fmt.Errorf("the address arm is empty")
		}
		return collectSignature(credentials.Address.Address, credentials.Address.Signature, address, nil)

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if credentials.AddressV2 == nil {
			return nil, fmt.Errorf("the address_v2 arm is empty")
		}
		return collectSignature(credentials.AddressV2.Address, credentials.AddressV2.Signature, address, nil)

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		withDelegates := credentials.AddressWithDelegates
		if withDelegates == nil {
			return nil, fmt.Errorf("the delegates arm is empty")
		}
		return collectSignature(
			withDelegates.AddressCredentials.Address,
			withDelegates.AddressCredentials.Signature,
			address,
			withDelegates.Delegates,
		)

	default:
		return nil, soroauth.ErrUnsupportedCredentials
	}
}

// collectSignature returns the signatures of every node naming wanted beneath
// one node, top-level node first.
func collectSignature(
	address xdr.ScAddress,
	signature xdr.ScVal,
	wanted string,
	delegates []xdr.SorobanDelegateSignature,
) ([]xdr.ScVal, error) {
	found, err := collectDelegates(delegates, wanted)
	if err != nil {
		return nil, err
	}

	matches, err := sameAddress(address, wanted)
	if err != nil {
		return nil, err
	}
	if matches {
		found = append([]xdr.ScVal{signature}, found...)
	}
	return found, nil
}

// collectDelegates walks one delegates level and everything beneath it.
func collectDelegates(delegates []xdr.SorobanDelegateSignature, wanted string) ([]xdr.ScVal, error) {
	var found []xdr.ScVal
	for i := range delegates {
		nested, err := collectSignature(
			delegates[i].Address,
			delegates[i].Signature,
			wanted,
			delegates[i].NestedDelegates,
		)
		if err != nil {
			return nil, err
		}
		found = append(found, nested...)
	}
	return found, nil
}

// sameAddress reports whether candidate is the given G… or C… address.
//
// FormatAddress is what turns an ScAddress into the string a wallet knows, and
// it is the function soroauth.Inspect uses to report the addresses in an entry,
// so comparing against it means the same thing as comparing against what
// Inspect printed.
func sameAddress(candidate xdr.ScAddress, wanted string) (bool, error) {
	formatted, err := soroauth.FormatAddress(candidate)
	if err != nil {
		return false, err
	}
	return formatted == wanted, nil
}

// parseAccountSignature reads back the one {public_key, signature} map that
// accountSignature writes and that soroauth.NewEd25519Signer writes.
//
// The keys are looked up by name rather than by position, so a map written in
// either order reads back — though the host requires key order, so only one
// order is ever valid on-chain. Anything that is not exactly one map carrying
// two byte strings of the right lengths is ErrUnreadableSignature.
func parseAccountSignature(value xdr.ScVal) (publicKey, signature []byte, err error) {
	if value.Type != xdr.ScValTypeScvVec || value.Vec == nil || *value.Vec == nil {
		return nil, nil, fmt.Errorf("stored signature is %s, want a vector: %w",
			value.Type, ErrUnreadableSignature)
	}

	entries := **value.Vec
	if len(entries) != 1 {
		return nil, nil, fmt.Errorf("stored signature holds %d entries, want exactly 1: %w",
			len(entries), ErrUnreadableSignature)
	}

	element := entries[0]
	if element.Type != xdr.ScValTypeScvMap || element.Map == nil || *element.Map == nil {
		return nil, nil, fmt.Errorf("stored signature holds %s, want a map: %w",
			element.Type, ErrUnreadableSignature)
	}

	for _, entry := range **element.Map {
		if entry.Key.Type != xdr.ScValTypeScvSymbol || entry.Key.Sym == nil {
			continue
		}
		if entry.Val.Type != xdr.ScValTypeScvBytes || entry.Val.Bytes == nil {
			return nil, nil, fmt.Errorf("stored signature field %q is %s, want bytes: %w",
				*entry.Key.Sym, entry.Val.Type, ErrUnreadableSignature)
		}
		switch string(*entry.Key.Sym) {
		case "public_key":
			publicKey = *entry.Val.Bytes
		case "signature":
			signature = *entry.Val.Bytes
		}
	}

	if publicKey == nil || signature == nil {
		return nil, nil, fmt.Errorf("stored signature is missing public_key or signature: %w",
			ErrUnreadableSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("stored public key is %d bytes, want %d: %w",
			len(publicKey), ed25519.PublicKeySize, ErrUnreadableSignature)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("stored signature is %d bytes, want %d: %w",
			len(signature), ed25519.SignatureSize, ErrUnreadableSignature)
	}
	return publicKey, signature, nil
}
