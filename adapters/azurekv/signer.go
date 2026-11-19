package azurekv

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"reflect"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// SignerClient is the part of the Azure Key Vault client used by this adapter.
// The generated *azkeys.Client satisfies it, while tests can supply a local
// fake.
type SignerClient interface {
	Sign(ctx context.Context, keyName, keyVersion string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

type signer struct {
	address      string
	keyName      string
	keyVersion   string
	client       SignerClient
	rawPublicKey []byte
}

// NewSigner returns a soroauth.Signer backed by the Ed25519 key identified by
// keyName and keyVersion in Azure Key Vault. The address must contain the
// corresponding classic Stellar public key (G…). The Azure client is
// intentionally owned by the caller: construct it with the appropriate vault
// URL and credential and pass it here.
//
// Pass an empty keyVersion to target the most recent version of the key. Azure
// Key Vault will resolve the version at sign time.
func NewSigner(address, keyName, keyVersion string, client SignerClient) (soroauth.Signer, error) {
	if isNilClient(client) {
		return nil, fmt.Errorf("azurekv: new signer: %w", soroauth.ErrMissingSigner)
	}
	if keyName == "" {
		return nil, fmt.Errorf("azurekv: new signer: key name is empty: %w", soroauth.ErrMissingSigner)
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("azurekv: new signer: %q is not an account (G…) address: %w", address, err)
	}
	return &signer{
		address:      address,
		keyName:      keyName,
		keyVersion:   keyVersion,
		client:       client,
		rawPublicKey: raw,
	}, nil
}

func (s *signer) Address() string { return s.address }

// Sign asks Azure Key Vault to perform EdDSA over the exact 32-byte Soroban
// payload, verifies the returned raw Ed25519 signature locally, and only then
// builds the classic account signature ScVal.
func (s *signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("azurekv: sign: %w", err)
	}
	// EdDSA is the JWA algorithm identifier for Ed25519. The SDK version may not
	// yet expose a named constant for it; the wire value is stable.
	algo := azkeys.SignatureAlgorithm("EdDSA")
	resp, err := s.client.Sign(ctx, s.keyName, s.keyVersion, azkeys.SignParameters{
		Algorithm: &algo,
		Value:     payload[:],
	}, nil)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("azurekv: sign: %w", err)
	}
	if len(resp.Result) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("azurekv: sign: Key Vault returned a %d-byte signature, want %d: %w",
			len(resp.Result), ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.rawPublicKey), payload[:], resp.Result) {
		return xdr.ScVal{}, fmt.Errorf("azurekv: sign: %w", soroauth.ErrSignatureMismatch)
	}
	value, err := soroauth.Ed25519SignatureScVal(s.rawPublicKey, resp.Result)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("azurekv: sign: %w", err)
	}
	return value, nil
}

// isNilClient reports whether client is nil, including the typed nil an
// interface holds when a nil *azkeys.Client is passed as a SignerClient.
// Without this, `client == nil` is false for `var c *azkeys.Client`, the
// signer is constructed, and it panics on the first Sign. Refusing at
// construction turns that into an error the caller can see. The gcpkms and
// awskms adapters apply the same guard for the same reason.
func isNilClient(client any) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}
