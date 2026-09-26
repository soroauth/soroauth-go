package gcpkms

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// AsymmetricSigner is the part of Cloud KMS this package uses. *kms.KeyManagementClient
// satisfies it; a test supplies a fake so the signing path never needs live GCP.
//
// It is deliberately the SDK's own method signature rather than a re-shaped
// wrapper, so the real client is passed through without an adapter layer that
// could silently drop a gax option.
type AsymmetricSigner interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// signer is a soroauth.Signer backed by one Cloud KMS ed25519 key version.
type signer struct {
	address      string
	keyVersion   string
	client       AsymmetricSigner
	rawPublicKey []byte
}

// NewSigner returns a soroauth.Signer that signs through client, using the
// Cloud KMS key version named by keyVersion, for the classic Stellar account
// address.
//
// The address is decoded at construction: it must be a G… account address, and
// its 32-byte ed25519 public key is what signatures are verified against before
// they are returned. A key version whose public key is not that account's key
// therefore fails on the first signature rather than on-chain, which is the
// point of verifying locally.
//
// A nil client, an empty key version or an address that is not a classic
// account is refused here.
func NewSigner(address, keyVersion string, client AsymmetricSigner) (soroauth.Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("gcpkms: new signer: %s: %w", address, soroauth.ErrMissingSigner)
	}
	if keyVersion == "" {
		return nil, fmt.Errorf("gcpkms: new signer: key version is empty: %w", soroauth.ErrMissingSigner)
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: new signer: %q is not an account (G…) address: %w", address, err)
	}
	return &signer{
		address:      address,
		keyVersion:   keyVersion,
		client:       client,
		rawPublicKey: raw,
	}, nil
}

// Address returns the G… account address this signer signs for.
func (s *signer) Address() string { return s.address }

// Sign sends the payload to Cloud KMS, verifies the returned ed25519 signature
// against the account's public key, and returns the classic account signature
// ScVal.
//
// The signature is verified before it is returned. A KMS response that is not a
// 64-byte ed25519 signature, or that does not verify, is reported as
// soroauth.ErrSignatureMismatch: writing it into the entry would only move the
// failure on-chain, after fees were paid.
func (s *signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("gcpkms: sign: %w", err)
	}

	response, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyVersion,
		Data: payload[:],
	})
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("gcpkms: sign: %w", err)
	}

	signature := response.GetSignature()
	if len(signature) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("gcpkms: sign: KMS returned a %d-byte signature, want %d: %w",
			len(signature), ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.rawPublicKey), payload[:], signature) {
		return xdr.ScVal{}, fmt.Errorf("gcpkms: sign: %w", soroauth.ErrSignatureMismatch)
	}

	scval, err := soroauth.Ed25519SignatureScVal(s.rawPublicKey, signature)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("gcpkms: sign: %w", err)
	}
	return scval, nil
}
