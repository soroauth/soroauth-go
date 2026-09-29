package soroauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// signerExampleKey derives an ed25519 keypair from a fixed label, the scheme
// every test key in this package uses. These are public test keys.
func signerExampleKey(label string) (*keypair.Full, error) {
	return keypair.FromRawSeed(sha256.Sum256([]byte(label)))
}

// signerExamplePublicKeys returns the public_key of each {public_key,
// signature} map in a classic-account signature vector, as G… addresses.
func signerExamplePublicKeys(value xdr.ScVal) ([]string, error) {
	vec, ok := value.GetVec()
	if !ok || vec == nil {
		return nil, fmt.Errorf("signature is %v, want a vector", value.Type)
	}
	addresses := []string{}
	for _, element := range *vec {
		m, ok := element.GetMap()
		if !ok || m == nil || len(*m) != 2 {
			return nil, fmt.Errorf("element is not a two-entry map")
		}
		address, err := strkey.Encode(strkey.VersionByteAccountID, []byte(*(*m)[0].Val.Bytes))
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// ExampleNewEd25519Signer_sign signs a payload for a classic account with one
// key. The value it returns is what the host decodes as
// AccountEd25519Signature: a vector holding one {public_key, signature} map,
// keys in sorted order. The signer verifies its own output before returning
// it; the check below repeats that from the outside.
func ExampleNewEd25519Signer_sign() {
	kp, err := signerExampleKey("soroauth-example-account")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	signer := NewEd25519Signer(kp)
	payload := sha256.Sum256([]byte("soroauth-example-payload"))

	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	vec, _ := value.GetVec()
	m, _ := (*vec)[0].GetMap()
	signature := []byte(*(*m)[1].Val.Bytes)
	fmt.Println("address:", signer.Address())
	fmt.Printf("vector of %d map: keys=[%s %s]\n", len(*vec), *(*m)[0].Key.Sym, *(*m)[1].Key.Sym)
	fmt.Println("verifies:", kp.Verify(payload[:], signature) == nil)

	// Output:
	// address: GAE47QJ5KGKGSXUHVS4ZDV6TS54EQXXRWEHGFLNMUC347AOIREDHL6MM
	// vector of 1 map: keys=[public_key signature]
	// verifies: true
}

// ExampleNewAccountMultiSigner_ordering signs for a classic multisig account.
// The keys go in in any order and come out strictly ascending by raw public
// key, because the host rejects any other order ("public keys are not
// ordered").
// The account being authorized need not be one of the signing keys.
//
// More than 20 keys is refused up front with ErrTooManySignatures, the host's
// MAX_ACCOUNT_SIGNATURES, rather than discovered on-chain.
func ExampleNewAccountMultiSigner_ordering() {
	account, err := signerExampleKey("soroauth-example-multisig-account")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	var keys []*keypair.Full
	for _, label := range []string{"soroauth-example-signer-1", "soroauth-example-signer-2"} {
		kp, err := signerExampleKey(label)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		keys = append(keys, kp)
	}

	// The keys are passed in reverse; the signer sorts them.
	signer, err := NewAccountMultiSigner(account.Address(), keys[1], keys[0])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{},
		sha256.Sum256([]byte("soroauth-example-payload")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	publicKeys, err := signerExamplePublicKeys(value)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("address:", signer.Address())
	for _, publicKey := range publicKeys {
		fmt.Println("signed by:", publicKey)
	}
	// Compare the raw keys, not the strkeys: base32 does not sort like bytes.
	first, _ := strkey.Decode(strkey.VersionByteAccountID, publicKeys[0])
	second, _ := strkey.Decode(strkey.VersionByteAccountID, publicKeys[1])
	fmt.Println("strictly ascending:", bytes.Compare(first, second) < 0)

	tooMany := make([]*keypair.Full, 21)
	for i := range tooMany {
		tooMany[i], err = signerExampleKey(fmt.Sprintf("soroauth-example-signer-%d", i+1))
		if err != nil {
			fmt.Println("error:", err)
			return
		}
	}
	_, err = NewAccountMultiSigner(account.Address(), tooMany...)
	fmt.Println("21 keys refused:", errors.Is(err, ErrTooManySignatures))

	// Output:
	// address: GD737IMYCLMR75GOFTLI7E4LEAULEUOFAWBQAL5OPAXQPOKGGO5BIH7M
	// signed by: GCP6CLIBLUXK3JB65B3R3JTNUW5X3N3KPA25TMFAH45LN4PJ6AKHM2JV
	// signed by: GCU34FM77HBDFGCZNXKZV5KUJSZD6SKWYOVIZCGGV4OGWTKBYW4OTZU4
	// strictly ascending: true
	// 21 keys refused: true
}

// ExampleSignerFunc adapts a function to the Signer interface for a custom
// account contract whose __check_auth expects a shape this library does not
// know. Whatever the function returns is written onto the credential node
// verbatim; nothing about it can be verified here.
func ExampleSignerFunc() {
	contractSeed := sha256.Sum256([]byte("soroauth-example-wallet"))
	wallet, err := strkey.Encode(strkey.VersionByteContract, contractSeed[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// A wallet whose __check_auth takes the raw payload echoed back as bytes:
	// a stand-in for whatever shape a real wallet defines.
	signer := SignerFunc(wallet, func(_ context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		b := xdr.ScBytes(payload[:])
		return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &b}, nil
	})

	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{},
		sha256.Sum256([]byte("soroauth-example-payload")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("address:", signer.Address())
	fmt.Printf("returned verbatim: %s of %d bytes\n", value.Type, len(*value.Bytes))

	// Output:
	// address: CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2
	// returned verbatim: ScValTypeScvBytes of 32 bytes
}

// ExampleEd25519SignatureScVal builds the classic-account signature value for
// a key that is not a keypair.Full, such as one held by a KMS or a remote
// signer. Here the standard library's ed25519 stands in for that service. The
// lengths are checked, because a wrong-sized value would only be rejected
// on-chain, after fees.
func ExampleEd25519SignatureScVal() {
	seed := sha256.Sum256([]byte("soroauth-example-account"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	payload := sha256.Sum256([]byte("soroauth-example-payload"))

	value, err := Ed25519SignatureScVal(public, ed25519.Sign(private, payload[:]))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	publicKeys, err := signerExamplePublicKeys(value)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("signed by:", publicKeys[0])

	_, err = Ed25519SignatureScVal(public, []byte("too short"))
	fmt.Println("refused:", err)

	// Output:
	// signed by: GAE47QJ5KGKGSXUHVS4ZDV6TS54EQXXRWEHGFLNMUC347AOIREDHL6MM
	// refused: soroauth: ed25519 signature scval: signature is 9 bytes, want 64
}

// ExampleIsSignatureRejection separates errors that retrying cannot fix from
// transport errors that it might. WithRetry uses it to fail fast on the first
// kind.
func ExampleIsSignatureRejection() {
	for _, err := range []error{
		fmt.Errorf("remote signer: %w", ErrSignatureMismatch),
		fmt.Errorf("remote signer: %w", ErrMissingSigner),
		errors.New("remote signer: connection reset by peer"),
	} {
		fmt.Printf("%v -> rejection=%t\n", err, IsSignatureRejection(err))
	}

	// Output:
	// remote signer: signature does not verify against the payload -> rejection=true
	// remote signer: no signer for address -> rejection=true
	// remote signer: connection reset by peer -> rejection=false
}

// ExampleRequireUserPresence refuses an assertion whose authenticator data
// does not have the user-presence flag set (bit 0 of the flags byte, WebAuthn
// Level 3 §6.1): nobody touched the authenticator. The refusal happens before
// the signing callback runs.
func ExampleRequireUserPresence() {
	authenticatorData := make([]byte, 37) // flags byte at index 32 is 0x00

	signer := NewPasskeySigner("CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2", authenticatorData,
		func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			fmt.Println("callback reached")
			return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
		},
		RequireUserPresence(true),
	)
	_, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
	fmt.Println("refused:", errors.Is(err, ErrVerificationFailed))

	// Output:
	// refused: true
}

// ExampleRequireUserVerification refuses an assertion that has user presence
// but not user verification (bit 2): the user touched the device but did not
// prove who they are with a PIN or biometric.
func ExampleRequireUserVerification() {
	authenticatorData := make([]byte, 37)
	authenticatorData[32] = 0x01 // UP set, UV not set

	signer := NewPasskeySigner("CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2", authenticatorData,
		func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			fmt.Println("callback reached")
			return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
		},
		RequireUserPresence(true),
		RequireUserVerification(true),
	)
	_, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
	fmt.Println("refused:", errors.Is(err, ErrVerificationFailed))

	// Output:
	// refused: true
}

// ExampleNewPasskeySignerFromAssertion_verify turns a WebAuthn assertion into a
// passkey wallet's signature value, verifying it first. The assertion here is
// built in-process with a P-256 key derived from a fixed label; in a real flow
// it comes from the browser and is parsed with ParseWebAuthnAssertion.
//
// The signer checks that the assertion's challenge is the payload it is being
// asked to sign, so an assertion from some other ceremony is refused. ECDSA
// signing draws a fresh nonce, so the signature bytes differ on every run and
// are not printed; their sizes and the verdicts are.
func ExampleNewPasskeySignerFromAssertion_verify() {
	seed := sha256.Sum256([]byte("soroauth-example-passkey-credential"))
	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, elliptic.P256().Params().N)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d.FillBytes(make([]byte, 32)))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	payload := sha256.Sum256([]byte("soroauth-example-payload"))

	// What the authenticator would produce: authenticator data with UP and UV
	// set, client data whose challenge is the payload, and an ES256 signature
	// over authenticatorData || SHA-256(clientDataJSON).
	authenticatorData := make([]byte, 37)
	authenticatorData[32] = 0x05
	challenge := base64.RawURLEncoding.EncodeToString(payload[:])
	assertion := &WebAuthnAssertion{
		AuthenticatorData: authenticatorData,
		ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"` + challenge +
			`","origin":"https://wallet.example"}`),
		ChallengeString: challenge,
	}
	digest := sha256.Sum256(assertion.SignedBytes())
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	assertion.Signature = der

	signer := NewPasskeySignerFromAssertion("CA6XPIBW3YXBR4RES2AWM4ASO7RZDF2MRVCP35W2XZ2XWBQ6X4IPS6A2",
		&key.PublicKey, assertion, RequireUserPresence(true), RequireUserVerification(true))

	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	m, _ := value.GetMap()
	fmt.Printf("%s=%d bytes %s=%d bytes\n",
		*(*m)[0].Key.Sym, len(*(*m)[0].Val.Bytes), *(*m)[1].Key.Sym, len(*(*m)[1].Val.Bytes))

	other := sha256.Sum256([]byte("soroauth-example-other-payload"))
	_, err = signer.Sign(context.Background(), xdr.HashIdPreimage{}, other)
	fmt.Println("other payload refused:", errors.Is(err, ErrWebAuthnChallengeMismatch))

	// Output:
	// public_key=65 bytes signature=64 bytes
	// other payload refused: true
}
