// Package wasmcore is the sandbox-independent body of the WebAssembly
// bindings. The js/wasm target (cmd/soroauthwasm) and the WASI target
// (cmd/soroauthwasi) both call these functions, so the two targets cannot
// drift into two implementations of the signing flow.
//
// Nothing here touches JavaScript or a host capability beyond base64 and the
// soroauth library itself: every function takes and returns strings, which is
// the whole boundary both targets expose.
package wasmcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// PreimageResult is what Preimage returns: the preimage XDR and its payload,
// both encoded for a caller that only moves strings across a boundary.
type PreimageResult struct {
	// PreimageXDR is the base64 XDR HashIdPreimage.
	PreimageXDR string `json:"preimageXdr"`
	// PayloadHex is the lowercase hex SHA-256 digest that a signer signs.
	PayloadHex string `json:"payloadHex"`
}

// Preimage derives the signing preimage and its 32-byte payload from an entry.
//
// A source-account entry has no preimage of its own — the transaction envelope
// authenticates it — so it returns an error naming that, rather than an empty
// success a caller might sign by accident.
func Preimage(entryB64 string, validUntilLedger uint32, networkPassphrase string) (PreimageResult, error) {
	entry, err := decodeEntry(entryB64)
	if err != nil {
		return PreimageResult{}, err
	}
	preimage, err := soroauth.Preimage(entry, validUntilLedger, networkPassphrase)
	if err != nil {
		return PreimageResult{}, err
	}
	raw, err := preimage.MarshalBinary()
	if err != nil {
		return PreimageResult{}, fmt.Errorf("soroauth: wasm: marshalling preimage: %w", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return PreimageResult{}, err
	}
	return PreimageResult{
		PreimageXDR: base64.StdEncoding.EncodeToString(raw),
		PayloadHex:  hex.EncodeToString(payload[:]),
	}, nil
}

// Payload hashes an already constructed preimage to its 32-byte payload.
//
// It is separate from Preimage for remote signers: a service that receives only
// a preimage can return the exact bytes it expects to be signed without
// reconstructing the entry.
//
// decode-allow: the base64 blob is a HashIdPreimage the caller supplies, and
// soroauth publishes no bounded decoder for that type; its bounds cover
// authorization entries and transaction envelopes.
func Payload(preimageB64 string) (string, error) {
	var preimage xdr.HashIdPreimage
	if err := xdr.SafeUnmarshalBase64(preimageB64, &preimage); err != nil {
		return "", fmt.Errorf("soroauth: wasm: decoding preimage: %w", err)
	}
	digest, err := soroauth.Payload(preimage)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// WriteSignature writes an externally produced signature ScVal onto every
// credential node whose address matches.
//
// The signature bytes are produced elsewhere — a passkey, a remote signer — and
// this function never sees a key. An empty forAddress targets the entry's own
// top-level address, which is the useful default for the single-node arms.
//
// decode-allow: the base64 blob is an ScVal signature the caller supplies, and
// soroauth publishes no bounded decoder for that type; its bounds cover
// authorization entries and transaction envelopes.
func WriteSignature(entryB64 string, validUntilLedger uint32, networkPassphrase, forAddress, signatureB64 string) (string, error) {
	entry, err := decodeEntry(entryB64)
	if err != nil {
		return "", err
	}
	var signature xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(signatureB64, &signature); err != nil {
		return "", fmt.Errorf("soroauth: wasm: decoding signature scval: %w", err)
	}

	signerAddress := forAddress
	if signerAddress == "" {
		signerAddress, err = topLevelAddress(entry)
		if err != nil {
			return "", err
		}
	}
	signer := soroauth.SignerFunc(signerAddress, func(
		context.Context, xdr.HashIdPreimage, [32]byte,
	) (xdr.ScVal, error) {
		return signature, nil
	})

	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, signer,
		validUntilLedger, networkPassphrase, options(forAddress)...,
	)
	if err != nil {
		return "", err
	}
	return encodeEntry(signed)
}

// AuthorizeWithSeed signs an entry with an in-memory raw ed25519 seed.
//
// It exists for deterministic conformance tests and browser demos that hold a
// raw key in memory. Real wallets should derive a payload and call
// WriteSignature with a signer they control.
func AuthorizeWithSeed(entryB64 string, validUntilLedger uint32, networkPassphrase, seedHex, forAddress string) (string, error) {
	entry, err := decodeEntry(entryB64)
	if err != nil {
		return "", err
	}
	seedBytes, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: decoding seed: %w", err)
	}
	if len(seedBytes) != 32 {
		return "", fmt.Errorf("soroauth: wasm: seed must be 32 bytes, got %d", len(seedBytes))
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: deriving keypair: %w", err)
	}

	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, soroauth.NewEd25519Signer(kp),
		validUntilLedger, networkPassphrase, options(forAddress)...,
	)
	if err != nil {
		return "", err
	}
	return encodeEntry(signed)
}

// PasskeySignature builds the {public_key, signature} ScVal a passkey wallet
// contract decodes, from an uncompressed SEC1 P-256 public key (65 bytes,
// 0x04 || X || Y) and a raw low-S r||s signature (64 bytes), both hex-encoded.
//
// The shape comes from the same soroauth.Secp256r1SignatureScVal the native
// library uses, so an offline page can produce it without linking the Stellar
// SDK or carrying a second XDR encoder that could drift.
func PasskeySignature(publicKeyHex, signatureHex string) (string, error) {
	publicBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: decoding public key: %w", err)
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: decoding signature: %w", err)
	}
	if len(publicBytes) != 65 || publicBytes[0] != 0x04 {
		return "", fmt.Errorf("soroauth: wasm: public key must be 65-byte uncompressed SEC1, got %d bytes", len(publicBytes))
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if x == nil || y == nil {
		return "", fmt.Errorf("soroauth: wasm: public key is not a valid P-256 point")
	}
	value, err := soroauth.Secp256r1SignatureScVal(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, signatureBytes)
	if err != nil {
		return "", err
	}
	raw, err := value.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: marshalling signature scval: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// decodeEntry parses a base64 XDR SorobanAuthorizationEntry through the
// library's bounded decoder: the value crosses a sandbox boundary and is
// caller-supplied, so the default XDR bounds are the wrong ones to trust.
func decodeEntry(b64 string) (xdr.SorobanAuthorizationEntry, error) {
	entry, err := soroauth.DecodeAuthorizationEntry(b64)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: wasm: decoding entry: %w", err)
	}
	return entry, nil
}

// encodeEntry marshals an entry to base64 XDR.
func encodeEntry(entry xdr.SorobanAuthorizationEntry) (string, error) {
	raw, err := entry.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: encoding entry: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// options turns an optional target address into AuthorizeEntry options.
func options(forAddress string) []soroauth.AuthorizeOption {
	if forAddress == "" {
		return nil
	}
	return []soroauth.AuthorizeOption{soroauth.ForAddress(forAddress)}
}

// topLevelAddress returns the credential address of an address-based entry.
func topLevelAddress(entry xdr.SorobanAuthorizationEntry) (string, error) {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if entry.Credentials.Address == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no address")
		}
		return soroauth.FormatAddress(entry.Credentials.Address.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if entry.Credentials.AddressV2 == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no v2 address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressV2.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if entry.Credentials.AddressWithDelegates == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no delegate address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
	default:
		return "", fmt.Errorf("soroauth: wasm: unsupported credential type")
	}
}
