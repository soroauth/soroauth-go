// Package testentry provides deterministic soroauth test fixtures for use in
// downstream test suites.
//
// Every function in this package is deterministic: calling it twice with the
// same parameters produces byte-identical XDR. The key derivation uses
//
//	keypair.FromRawSeed(sha256(label))
//
// which is the scheme documented in CONTRIBUTING.md#deterministic-test-keys.
// All keys exposed here are public test keys derived from well-known labels.
//
// WARNING: Never fund these keys on mainnet or Stellar testnet. They are
// derived from public labels and are known to anyone who reads this package.
// They exist only to produce deterministic XDR for tests.
package testentry

import (
	"crypto/sha256"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Well-known labels used by the standard entries. Downstream tests that need
// the corresponding keys can call Key(LabelSigner) etc.
const (
	LabelSigner    = "soroauth-testentry-signer"
	LabelDelegate1 = "soroauth-testentry-delegate-1"
	LabelDelegate2 = "soroauth-testentry-delegate-2"
	LabelNested    = "soroauth-testentry-nested-1"
	LabelContract  = "soroauth-testentry-contract"
	LabelSubcall   = "soroauth-testentry-subcall"
)

// DefaultNonce is the nonce every standard entry uses. It is a fixed
// non-zero value so nonces are non-trivial to test against.
const DefaultNonce = int64(42)

// Key derives a *keypair.Full from label using sha256(label) as the seed.
// The resulting key is deterministic and platform-independent.
func Key(label string) (*keypair.Full, error) {
	seed := sha256.Sum256([]byte(label))
	return keypair.FromRawSeed(seed)
}

// MustKey is like Key but panics on error. For use in test init functions and
// package-level variable initialisers, where an error means a programming mistake.
func MustKey(label string) *keypair.Full {
	kp, err := Key(label)
	if err != nil {
		panic(fmt.Sprintf("testentry.MustKey(%q): %v", label, err))
	}
	return kp
}

// ContractAddress derives a C… strkey from label using sha256(label) as the
// contract ID bytes. Deterministic and platform-independent.
func ContractAddress(label string) (string, error) {
	sum := sha256.Sum256([]byte(label))
	return strkey.Encode(strkey.VersionByteContract, sum[:])
}

// MustContractAddress is like ContractAddress but panics on error.
func MustContractAddress(label string) string {
	addr, err := ContractAddress(label)
	if err != nil {
		panic(fmt.Sprintf("testentry.MustContractAddress(%q): %v", label, err))
	}
	return addr
}

// parseAddress is the same as soroauth.ParseAddress but inlined here to avoid
// an import cycle (testentry imports soroauth types, not soroauth itself).
func parseAddress(s string) (xdr.ScAddress, error) {
	switch {
	case len(s) > 0 && s[0] == 'G':
		raw, err := strkey.Decode(strkey.VersionByteAccountID, s)
		if err != nil {
			return xdr.ScAddress{}, fmt.Errorf("testentry: G-address: %w", err)
		}
		var key xdr.Uint256
		copy(key[:], raw)
		accountID := xdr.AccountId(xdr.PublicKey{
			Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
			Ed25519: &key,
		})
		return xdr.ScAddress{
			Type:      xdr.ScAddressTypeScAddressTypeAccount,
			AccountId: &accountID,
		}, nil
	case len(s) > 0 && s[0] == 'C':
		raw, err := strkey.Decode(strkey.VersionByteContract, s)
		if err != nil {
			return xdr.ScAddress{}, fmt.Errorf("testentry: C-address: %w", err)
		}
		var id xdr.ContractId
		copy(id[:], raw)
		return xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &id,
		}, nil
	default:
		return xdr.ScAddress{}, fmt.Errorf("testentry: %q: not a G… or C… address", s)
	}
}

// Invocation returns the standard test invocation: a contract call with one
// int64 argument and one sub-invocation. It is used by all standard entries so
// their payloads cover the recursive part of the XDR encoding.
func Invocation() (xdr.SorobanAuthorizedInvocation, error) {
	contract, err := ContractAddress(LabelContract)
	if err != nil {
		return xdr.SorobanAuthorizedInvocation{}, fmt.Errorf("testentry.Invocation: contract: %w", err)
	}
	subcall, err := ContractAddress(LabelSubcall)
	if err != nil {
		return xdr.SorobanAuthorizedInvocation{}, fmt.Errorf("testentry.Invocation: subcall: %w", err)
	}

	contractAddr, err := parseAddress(contract)
	if err != nil {
		return xdr.SorobanAuthorizedInvocation{}, fmt.Errorf("testentry.Invocation: parsing contract: %w", err)
	}
	subcallAddr, err := parseAddress(subcall)
	if err != nil {
		return xdr.SorobanAuthorizedInvocation{}, fmt.Errorf("testentry.Invocation: parsing subcall: %w", err)
	}

	amount := xdr.Int64(100)
	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contractAddr,
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: &amount}},
			},
		},
		SubInvocations: []xdr.SorobanAuthorizedInvocation{{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: subcallAddr,
					FunctionName:    xdr.ScSymbol("approve"),
					Args:            []xdr.ScVal{},
				},
			},
		}},
	}, nil
}

// newScVec returns a pointer-to-pointer-to-ScVec, the shape xdr.ScVal.Vec expects.
func newScVec(vals ...xdr.ScVal) **xdr.ScVec {
	vec := xdr.ScVec(vals)
	p := &vec
	return &p
}

// addressCredentials builds the shared credentials block for a given signer label.
func addressCredentials(label string, nonce int64) (xdr.SorobanAddressCredentials, error) {
	kp, err := Key(label)
	if err != nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("testentry: key(%q): %w", label, err)
	}
	addr, err := parseAddress(kp.Address())
	if err != nil {
		return xdr.SorobanAddressCredentials{}, fmt.Errorf("testentry: parseAddress(%q): %w", kp.Address(), err)
	}
	return xdr.SorobanAddressCredentials{
		Address:                   addr,
		Nonce:                     xdr.Int64(nonce),
		SignatureExpirationLedger: 0,
		Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
	}, nil
}

// SourceAccountEntry returns an unsigned SOURCE_ACCOUNT arm entry.
func SourceAccountEntry() (xdr.SorobanAuthorizationEntry, error) {
	inv, err := Invocation()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
		RootInvocation: inv,
	}, nil
}

// LegacyEntry returns an unsigned ADDRESS (legacy V1) arm entry. The signer
// is Key(LabelSigner) with DefaultNonce.
func LegacyEntry() (xdr.SorobanAuthorizationEntry, error) {
	return LegacyEntryWith(LabelSigner, DefaultNonce)
}

// LegacyEntryWith returns an unsigned ADDRESS arm entry for the given signer label and nonce.
func LegacyEntryWith(signerLabel string, nonce int64) (xdr.SorobanAuthorizationEntry, error) {
	creds, err := addressCredentials(signerLabel, nonce)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	inv, err := Invocation()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &creds,
		},
		RootInvocation: inv,
	}, nil
}

// V2Entry returns an unsigned ADDRESS_V2 arm entry. The signer is
// Key(LabelSigner) with DefaultNonce.
func V2Entry() (xdr.SorobanAuthorizationEntry, error) {
	return V2EntryWith(LabelSigner, DefaultNonce)
}

// V2EntryWith returns an unsigned ADDRESS_V2 arm entry for the given signer label and nonce.
func V2EntryWith(signerLabel string, nonce int64) (xdr.SorobanAuthorizationEntry, error) {
	creds, err := addressCredentials(signerLabel, nonce)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	inv, err := Invocation()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &creds,
		},
		RootInvocation: inv,
	}, nil
}

// DelegatesEntry returns an unsigned ADDRESS_WITH_DELEGATES arm entry. The
// top-level account is Key(LabelSigner), and the tree is:
//
//	LabelSigner (top-level, Void signature)
//	├── LabelDelegate1 (Void)
//	│   └── LabelNested (Void)
//	└── LabelDelegate2 (Void)
//
// The delegates are pre-sorted by XDR address bytes ascending, as the
// protocol requires.
func DelegatesEntry() (xdr.SorobanAuthorizationEntry, error) {
	return DelegatesEntryWith(LabelSigner, DefaultNonce, LabelDelegate1, LabelDelegate2, LabelNested)
}

// DelegatesEntryWith returns an ADDRESS_WITH_DELEGATES entry for the given labels.
// The tree has two top-level delegates (d1Label and d2Label), with nestedLabel
// nested under d1Label.
func DelegatesEntryWith(signerLabel string, nonce int64, d1Label, d2Label, nestedLabel string) (xdr.SorobanAuthorizationEntry, error) {
	creds, err := addressCredentials(signerLabel, nonce)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	inv, err := Invocation()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}

	// Build delegate addresses.
	d1kp, err := Key(d1Label)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("testentry: key(%q): %w", d1Label, err)
	}
	d2kp, err := Key(d2Label)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("testentry: key(%q): %w", d2Label, err)
	}
	nestedkp, err := Key(nestedLabel)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("testentry: key(%q): %w", nestedLabel, err)
	}

	d1Addr, err := parseAddress(d1kp.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	d2Addr, err := parseAddress(d2kp.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	nestedAddr, err := parseAddress(nestedkp.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}

	// Sort delegates by XDR byte encoding, as required by CAP-71-01.
	d1Bytes, err := d1Addr.MarshalBinary()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("testentry: encoding d1 address: %w", err)
	}
	d2Bytes, err := d2Addr.MarshalBinary()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("testentry: encoding d2 address: %w", err)
	}

	d1 := xdr.SorobanDelegateSignature{
		Address:   d1Addr,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		NestedDelegates: []xdr.SorobanDelegateSignature{{
			Address:   nestedAddr,
			Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		}},
	}
	d2 := xdr.SorobanDelegateSignature{
		Address:   d2Addr,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}

	// Order delegates by XDR bytes ascending.
	var delegates []xdr.SorobanDelegateSignature
	if string(d1Bytes) <= string(d2Bytes) {
		delegates = []xdr.SorobanDelegateSignature{d1, d2}
	} else {
		delegates = []xdr.SorobanDelegateSignature{d2, d1}
	}

	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: creds,
				Delegates:          delegates,
			},
		},
		RootInvocation: inv,
	}, nil
}
