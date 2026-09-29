package soroauth

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleSignSecp256r1 signs a payload with a P-256 key and shows the two
// properties the wire format depends on: the result is fixed-width r || s, and
// s is always in the low half of the curve order.
//
// The low-S rule is why the same signature has one encoding. n - s is an
// equally valid signature over the same payload, so accepting both would give
// one signature two byte strings — and a signature value is what a custom
// account's __check_auth decodes and the host compares.
//
// The key is derived from a fixed label so a failing run reproduces. The 64
// signature bytes themselves are not printed and cannot be: ES256 draws a fresh
// nonce per signature through crypto/ecdsa, so they differ on every run. What
// is stable, and what this example prints, is the shape and the invariants.
func ExampleSignSecp256r1() {
	// A P-256 key from a fixed label. The public point is derived from the
	// private scalar rather than drawn, so X and Y below belong to D.
	seed := sha256.Sum256([]byte("soroauth-example-secp256r1"))
	secret, err := ecdh.P256().NewPrivateKey(seed[:])
	if err != nil {
		fmt.Println("key:", err)
		return
	}
	public := secret.PublicKey().Bytes() // uncompressed SEC1: 0x04 || X || Y
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(public[1:33]),
			Y:     new(big.Int).SetBytes(public[33:]),
		},
		D: new(big.Int).SetBytes(seed[:]),
	}

	// The payload is already a 32-byte hash. These primitives do not hash: the
	// caller decides what is signed over, which for a Soroban credential is the
	// authorization-entry payload and for a passkey is
	// SHA-256(authenticatorData || SHA-256(clientDataJSON)).
	payload := sha256.Sum256([]byte("soroauth-example-payload"))
	signature, err := SignSecp256r1(key, payload)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}
	fmt.Printf("%d bytes\n", len(signature))

	_, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	fmt.Println("low-S:", s.Cmp(half) <= 0)
	fmt.Println("verifies:", VerifySecp256r1(&key.PublicKey, payload, signature) == nil)

	// Output:
	// 64 bytes
	// low-S: true
	// verifies: true
}

// ExampleVerifySecp256r1 checks a signature and shows the two ways one is
// refused: it does not cover this payload, or it is the high-S encoding.
//
// Both are refused rather than normalised. A wrong payload is the case the
// caller cares about; the high-S case matters because SignSecp256r1 never
// emits one, so accepting it here would verify signatures this library would
// not produce and no contract decodes.
//
// The signature is produced in the example rather than pasted in, because a
// signature is only meaningful against the key and payload that made it, and a
// literal blob would hide both. The printed results are stable even though the
// signature bytes are not.
func ExampleVerifySecp256r1() {
	seed := sha256.Sum256([]byte("soroauth-example-secp256r1"))
	secret, err := ecdh.P256().NewPrivateKey(seed[:])
	if err != nil {
		fmt.Println("key:", err)
		return
	}
	public := secret.PublicKey().Bytes()
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(public[1:33]),
			Y:     new(big.Int).SetBytes(public[33:]),
		},
		D: new(big.Int).SetBytes(seed[:]),
	}
	payload := sha256.Sum256([]byte("soroauth-example-payload"))
	signature, err := SignSecp256r1(key, payload)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	fmt.Println("valid:", VerifySecp256r1(&key.PublicKey, payload, signature))

	// The signature is correct, but it was made over a different payload.
	other := sha256.Sum256([]byte("soroauth-example-other-payload"))
	err = VerifySecp256r1(&key.PublicKey, other, signature)
	fmt.Println("wrong payload:", errors.Is(err, ErrSignatureMismatch))

	// n - s is the same signature with the sign of s flipped. It is arithmetically
	// valid and deliberately refused.
	r, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	highS := make([]byte, Secp256r1SignatureSize)
	r.FillBytes(highS[:32])
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(highS[32:])
	err = VerifySecp256r1(&key.PublicKey, payload, highS)
	fmt.Println("high-S:", errors.Is(err, ErrSignatureMismatch))

	// Output:
	// valid: <nil>
	// wrong payload: true
	// high-S: true
}

// ExampleParseSecp256r1Signature splits the fixed-width r || s a credential
// node carries into the two scalars an ECDSA verifier wants.
//
// The split is at byte 32 and only at byte 32. A shorter or longer input is
// refused rather than zero-padded or truncated, because a fixed-width encoding
// that was mangled in transit is not a signature, and guessing at its intent
// is how a malformed value turns into a valid one.
//
// The signature below is the "typical" case from
// testdata/vectors/passkey, the shape a real wallet library produced.
func ExampleParseSecp256r1Signature() {
	signature, err := hex.DecodeString(
		"362baccdab839b1e315ebe97e441794702217389efb263298cd27b458c0a39f9" +
			"bfaac955abe3a94bea5639ddcd44da650ff0ee2e1f2146f454a7f623f1948335")
	if err != nil {
		fmt.Println("decode:", err)
		return
	}
	r, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	// Both are in [1, n-1], the only range a P-256 signature may take, which is
	// checked before either is used.
	fmt.Printf("r = %x\n", r)
	fmt.Printf("s = %x\n", s)

	// One byte short: refused, not padded.
	_, _, err = ParseSecp256r1Signature(signature[:Secp256r1SignatureSize-1])
	fmt.Println("63 bytes refused:", err != nil)

	// Output:
	// r = 362baccdab839b1e315ebe97e441794702217389efb263298cd27b458c0a39f9
	// s = bfaac955abe3a94bea5639ddcd44da650ff0ee2e1f2146f454a7f623f1948335
	// 63 bytes refused: true
}

// ExampleParseDERECDSASignature decodes the DER encoding a WebAuthn assertion's
// signature field arrives in, into the same two scalars the fixed-width form
// carries.
//
// DER is the input side and raw r || s is the Soroban side, so this is where
// the two meet: the browser sends 71 bytes here, and the credential node holds
// 64. The scalars are identical, only the envelope differs.
//
// The example below encodes the two scalars from
// ExampleParseSecp256r1Signature, so the two functions can be read side by side.
func ExampleParseDERECDSASignature() {
	der, err := hex.DecodeString(
		"30450220362baccdab839b1e315ebe97e441794702217389efb263298cd27b458c0a39f9" +
			"022100bfaac955abe3a94bea5639ddcd44da650ff0ee2e1f2146f454a7f623f1948335")
	if err != nil {
		fmt.Println("decode:", err)
		return
	}
	fmt.Printf("%d DER bytes\n", len(der))

	r, s, err := ParseDERECDSASignature(der)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	// The same scalars the 64-byte form yielded. The extra leading 00 on s is
	// DER's sign byte: s has its high bit set, and DER integers are signed.
	fmt.Printf("r = %x\n", r)
	fmt.Printf("s = %x\n", s)

	// RFC 3279's DER has no trailing bytes and no honest encoder emits one, so
	// a value that decodes only on a prefix is refused.
	_, _, err = ParseDERECDSASignature(append(der, 0x00))
	fmt.Println("trailing byte refused:", err != nil)

	// Output:
	// 71 DER bytes
	// r = 362baccdab839b1e315ebe97e441794702217389efb263298cd27b458c0a39f9
	// s = bfaac955abe3a94bea5639ddcd44da650ff0ee2e1f2146f454a7f623f1948335
	// trailing byte refused: true
}

// ExampleSecp256r1SignatureScVal builds the signature value a passkey wallet's
// credential node holds: a symbol-keyed map of the public key and the
// signature.
//
// No protocol document defines this shape. A custom account's __check_auth
// decides what its signature ScVal looks like, so what a wallet expects is a
// property of that wallet's contract. This is the shape the wallet contracts
// in e2e/contracts decode, and the one testdata/vectors/passkey pins against a
// real wallet library's output. A wallet with a different layout needs
// SignerFunc, which writes back whatever the callback returns.
//
// Both byte strings come from the "typical" passkey vector, so this example and
// the golden test read the same key material.
func ExampleSecp256r1SignatureScVal() {
	publicKey, err := hex.DecodeString(
		"04e29b0163d4728e17c406b3255c766710d7ef64e5042dc68b29db4f9114b83b9" +
			"b5f23786570fad22d1b84e68854489c35a4666272664453fc5889a88428cc76c0")
	if err != nil {
		fmt.Println("decode public key:", err)
		return
	}
	signature, err := hex.DecodeString(
		"362baccdab839b1e315ebe97e441794702217389efb263298cd27b458c0a39f9" +
			"bfaac955abe3a94bea5639ddcd44da650ff0ee2e1f2146f454a7f623f1948335")
	if err != nil {
		fmt.Println("decode signature:", err)
		return
	}

	// The uncompressed SEC1 key is 0x04 followed by the two fixed-width
	// coordinates, so the 65 bytes are the two halves and the leading byte.
	walletKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(publicKey[1:33]),
		Y:     new(big.Int).SetBytes(publicKey[33:]),
	}
	value, err := Secp256r1SignatureScVal(walletKey, signature)
	if err != nil {
		fmt.Println("scval:", err)
		return
	}

	fmt.Println("map:", value.Type == xdr.ScValTypeScvMap)
	for _, element := range **value.Map {
		// Order is load-bearing, not cosmetic: the host requires an ScMap to be
		// sorted by key, so public_key must come first.
		fmt.Printf("  %s: %d bytes\n", *element.Key.Sym, len(*element.Val.Bytes))
	}

	// Output:
	// map: true
	//   public_key: 65 bytes
	//   signature: 64 bytes
}
