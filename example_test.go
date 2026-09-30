package soroauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleParseAddress shows the two address forms an address credential may
// name, the canonicality rule, and the muxed-address refusal.
//
// Only the canonical SEP-23 base32 spelling is accepted, so a lower-cased (or
// padded, or whitespace-wrapped) address is refused even though it names the
// same key; an M… muxed address is refused rather than unwrapped, because a
// credential must name the account itself (CAP-46-11).
func ExampleParseAddress() {
	account, err := ParseAddress("GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX")
	if err != nil {
		fmt.Println("account:", err)
		return
	}
	contract, err := ParseAddress("CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O")
	if err != nil {
		fmt.Println("contract:", err)
		return
	}
	fmt.Println(account.Type == xdr.ScAddressTypeScAddressTypeAccount)
	fmt.Println(contract.Type == xdr.ScAddressTypeScAddressTypeContract)

	// Non-canonical spellings are refused, even though they name the same key.
	if _, err := ParseAddress("gaaacaqdaqcqmbyibefawdanbyhraeiscmkbkfqxdamrugy4dupb7jzx"); err != nil {
		fmt.Println("lower-cased refused")
	}

	// A muxed address is refused rather than unwrapped: a credential must name
	// the account itself.
	if _, err := ParseAddress("MAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6AAAAAAAAAAE2KZ3Q"); err != nil {
		fmt.Println("muxed refused")
	}

	// Output:
	// true
	// true
	// lower-cased refused
	// muxed refused
}

// ExampleFormatAddress is the inverse of ParseAddress: it renders each accepted
// address form and refuses the same arms ParseAddress refuses, so a caller is
// never shown an address this library would decline to sign for.
func ExampleFormatAddress() {
	address, err := ParseAddress("CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O")
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	formatted, err := FormatAddress(address)
	if err != nil {
		fmt.Println("format:", err)
		return
	}
	fmt.Println(formatted)

	// Output:
	// CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O
}

// ExampleDecodeAuthorizationEntry shows the entry point for a base64 entry that
// came from somewhere else. The limits it applies are documented on the
// function and on MaxDecodeDepth and MaxDecodeInputBytes.
func ExampleDecodeAuthorizationEntry() {
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	var key xdr.Uint256
	key[0] = 1
	accountID := xdr.AccountId{
		Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
		Ed25519: &key,
	}
	address := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accountID,
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     7,
				SignatureExpirationLedger: 100,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &contractID,
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		fmt.Println("encode:", err)
		return
	}

	decoded, err := DecodeAuthorizationEntry(encoded)
	if err != nil {
		fmt.Println("decode:", err)
		return
	}

	info, err := Inspect(decoded)
	if err != nil {
		fmt.Println("inspect:", err)
		return
	}
	fmt.Printf("%s nonce=%d expires=%d function=%s\n",
		info.CredentialType, info.Nonce, info.ValidUntilLedger, info.RootFunction)

	// Output: address_v2 nonce=7 expires=100 function=transfer
}

// ExampleNewPasskeySigner shows how to configure a passkey signer with required
// user presence (UP) and user verification (UV) flags to enforce hardware or biometric
// authorization constraints before signing a Soroban authorization entry.
func ExampleNewPasskeySigner() {
	// A dummy 37-byte authenticator data block where flag 0x01 (UP) and 0x04 (UV) are set.
	authData := make([]byte, 37)
	authData[32] = 0x05

	signer := NewPasskeySigner(
		"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		authData,
		func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return scBytes([]byte("mock-webauthn-signature")), nil
		},
		RequireUserPresence(true),
		RequireUserVerification(true),
	)

	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

// ExampleNewPasskeySigner_authorizeEndToEnd signs a passkey wallet's credential
// node: the entry a simulation returned goes in, the wallet's signature comes
// out on the node naming that wallet, and the result is the signed entry the
// transaction carries.
//
// ExampleNewPasskeySigner above configures the signer; this one uses it. Two
// facts about the passkey case are exercised below: a passkey wallet is a custom
// account, so the credential node names a C… contract address rather than a
// G… account; and the value the callback returns is the signature ScVal the
// wallet contract's own __check_auth decodes, a shape no protocol document
// defines. A backend that receives a real WebAuthn assertion from a browser
// should build the signer with NewPasskeySignerFromAssertion instead, which
// verifies the assertion's challenge binding and ES256 signature at Sign time;
// docs/passkeys.md walks that flow end to end.
//
// Every input is derived from a fixed label — the wallet's address, its P-256
// credential key, the authenticator data, the nonce and the expiration — so the
// payload and every printed line are identical on every run. The signature bytes
// are not, and cannot be: SignSecp256r1 signs through crypto/ecdsa with
// crypto/rand (secp256r1.go), which draws a fresh nonce per signature, so those
// 64 bytes differ each time. The example verifies them rather than printing
// them, which is the stronger claim anyway.
func ExampleNewPasskeySigner_authorizeEndToEnd() {
	// A passkey wallet's address, derived from a public test label; see
	// CONTRIBUTING.md#deterministic-test-keys.
	walletSeed := sha256.Sum256([]byte("soroauth-example-passkey-wallet"))
	walletStrkey, err := strkey.Encode(strkey.VersionByteContract, walletSeed[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	wallet, err := ParseAddress(walletStrkey)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// The credential key a wallet would have registered with its contract,
	// derived here because a failing run has to reproduce. A wallet's key comes
	// from the authenticator, not from a label: ScalarBaseMult takes the seed as
	// a scalar, so it is reduced into [1, n-1] first.
	credentialSeed := sha256.Sum256([]byte("soroauth-example-passkey-credential"))
	d := new(big.Int).SetBytes(credentialSeed[:])
	d.Mod(d, elliptic.P256().Params().N)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}

	// What the callback must return: the {public_key, signature} map the wallet
	// contract decodes — the 65-byte uncompressed SEC1 public key, and the
	// signature as fixed-width low-S r || s. SignSecp256r1 and
	// Secp256r1SignatureScVal build exactly that, and the verification below
	// reads it back off the signed entry to confirm it.
	walletSignature := func(_ context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		signature, err := SignSecp256r1(key, payload)
		if err != nil {
			return xdr.ScVal{}, err
		}
		return Secp256r1SignatureScVal(&key.PublicKey, signature)
	}

	// The flags byte of the authenticator data sits at index 32 (WebAuthn
	// Level 3, §6.1). 0x05 is user presence (bit 0) and user verification
	// (bit 2): the user proved themselves, not merely touched the device.
	authenticatorData := make([]byte, 37)
	authenticatorData[32] = 0x05

	signer := NewPasskeySigner(walletStrkey, authenticatorData, walletSignature,
		RequireUserPresence(true),
		RequireUserVerification(true),
	)

	// The entry simulateTransaction returned, unsigned: an address-bound
	// credential (CAP-71-01) naming the wallet contract, with a fixed nonce and
	// no signature yet.
	invoked := xdr.ContractId(walletSeed)
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   wallet,
				Nonce:     1,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &invoked,
					},
					FunctionName: xdr.ScSymbol("transfer"),
					Args:         []xdr.ScVal{},
				},
			},
		},
	}

	const validUntil = 1000
	passphrase := network.TestNetworkPassphrase

	// ForAddress is not decoration: AuthorizeEntry writes the signature only
	// onto a node whose address equals the target, and refuses with
	// ErrNoMatchingCredentialNode when none does, rather than signing
	// something the key holder did not intend.
	signed, err := AuthorizeEntry(context.Background(), entry, signer, validUntil,
		passphrase, ForAddress(walletStrkey))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := Inspect(signed)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%s wallet_signed=%t expires=%d\n",
		info.CredentialType, info.TopLevelSigned, info.ValidUntilLedger)

	// Read the value back the way the wallet contract does. An ScMap must be
	// sorted by key — the host rejects an unsorted one — so
	// Secp256r1SignatureScVal emits public_key before signature, and a
	// hand-built map that got the order wrong would be rejected on-chain.
	value := signed.Credentials.AddressV2.Signature
	if value.Type != xdr.ScValTypeScvMap || value.Map == nil {
		fmt.Println("signature is not a map:", value.Type)
		return
	}
	keys := []string{}
	values := map[string][]byte{}
	for _, element := range **value.Map {
		name := string(*element.Key.Sym)
		keys = append(keys, name)
		values[name] = []byte(*element.Val.Bytes)
	}
	fmt.Printf("signature map: keys=%s public_key=%d bytes signature=%d bytes\n",
		keys, len(values["public_key"]), len(values["signature"]))

	// The contract is handed the payload hash, not the preimage, so the only
	// way to check what was written is to rebuild the payload from the signed
	// entry — including the expiration it now carries, which is part of what
	// was signed over. Getting this wrong is what a mismatched expiration
	// looks like from the host's side.
	preimage, err := Preimage(signed, info.ValidUntilLedger, passphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	payload, err := Payload(preimage)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// elliptic.Unmarshal returns a nil key for a point that is not on the curve
	// rather than an error; VerifySecp256r1 refuses such a key, so the failure
	// is a verification failure and not a panic.
	walletPublicKeyX, walletPublicKeyY := elliptic.Unmarshal(elliptic.P256(), values["public_key"])
	walletPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     walletPublicKeyX,
		Y:     walletPublicKeyY,
	}
	fmt.Println("verifies over the entry's own payload:",
		VerifySecp256r1(walletPublicKey, payload, values["signature"]) == nil)

	// The guards are load-bearing, not decorative. A software authenticator can
	// produce an assertion with presence but no verification, and the same
	// configuration refuses it before the callback is ever reached.
	// AuthorizeEntry leaves its input untouched, so the unsigned entry above is
	// still unsigned and can be signed again.
	noVerification := make([]byte, 37)
	noVerification[32] = 0x01
	unverified := NewPasskeySigner(walletStrkey, noVerification, walletSignature,
		RequireUserPresence(true),
		RequireUserVerification(true),
	)
	_, err = AuthorizeEntry(context.Background(), entry, unverified, validUntil,
		passphrase, ForAddress(walletStrkey))
	fmt.Println("assertion without user verification refused:",
		errors.Is(err, ErrVerificationFailed))

	// Output:
	// address_v2 wallet_signed=true expires=1000
	// signature map: keys=[public_key signature] public_key=65 bytes signature=64 bytes
	// verifies over the entry's own payload: true
	// assertion without user verification refused: true
}

// ExampleVerifyAll shows how to verify a batch of authorization entries
// concurrently with custom configuration and per-entry reporting.
func ExampleVerifyAll() {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}

	results, err := VerifyAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, network.TestNetworkPassphrase, WithConcurrency(2))
	if err != nil {
		fmt.Println("verify error:", err)
		return
	}

	for _, res := range results {
		fmt.Printf("entry %d address=%q err=%v\n", res.Index, res.Address, res.Error)
		break
	}

	// Output: entry 0 address="" err=<nil>
}

// ExampleDescribeSignature shows how to use DescribeSignature to inspect
// an unknown or custom signature shape.
func ExampleDescribeSignature() {
	// A sample passkey signature shape (64 bytes)
	bytesVal := make([]byte, 64)
	sig := xdr.ScVal{
		Type:  xdr.ScValTypeScvBytes,
		Bytes: (*xdr.ScBytes)(&bytesVal),
	}

	shape := DescribeSignature(sig)
	fmt.Printf("shape type: %s, description: %s\n", shape.Type, shape.Description)

	// Output: shape type: passkey, description: 64-byte binary passkey signature
}

// ExampleSigner_cancellation shows how signers honour context cancellation
// to abort signing operations when a deadline expires or the caller cancels.
func ExampleSigner_cancellation() {
	kp, e := keypair.FromRawSeed(sha256.Sum256([]byte("example-key")))
	if e != nil {
		fmt.Println(false)
		return
	}
	signer := NewEd25519Signer(kp)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel context

	_, err := signer.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	if err != nil {
		fmt.Println(err == context.Canceled || err.Error() != "")
	}

	// Output: true
}

// ExampleWithRetry shows how to wrap a remote signer with jittered exponential
// backoff and a retry policy, ensuring transport errors are retried while
// signature rejections and cancellations fail fast.
func ExampleWithRetry() {
	// Create a base signer using SignerFunc (e.g. talking to a remote KMS/signer service)
	inner := SignerFunc("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		// Simulate a remote signer interaction
		return xdr.ScVal{}, fmt.Errorf("connection refused")
	})

	// Wrap with retry policy
	_ = WithRetry(inner, RetryConfig{
		Attempts:       3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})
	fmt.Println("retry signer configured")

	// Output: retry signer configured
}

// ExampleExpirationAfter turns a lifetime in ledgers into the absolute ledger
// number an entry must carry, and shows the two refusals that keep a long
// lifetime from turning into an expiration in the past.
//
// Everything here is fixed so the output is stable, which for this function is
// the whole input: ExpirationAfter takes two integers and touches no key, no
// nonce and no network, so there is nothing a deterministic-key scheme would
// apply to (the values a caller passes usually come from the network's latest
// ledger). The example deliberately uses small round numbers rather than a
// real network's, because the sum is network-independent — what the network
// constrains is the upper bound this function cannot know, documented on the
// function itself.
func ExampleExpirationAfter() {
	const latestLedger = 1_234_567

	for _, ledgers := range []uint32{1, 720} {
		expiration, err := ExpirationAfter(latestLedger, ledgers)
		if err != nil {
			// The only errors are refusals, so this cannot be a transport
			// failure or anything else worth retrying.
			fmt.Println("refused:", err)
			return
		}
		fmt.Printf("latest=%d +%d -> %d\n", latestLedger, ledgers, expiration)
	}

	// A zero lifetime would expire at the current ledger, which the host
	// treats as already expired, and a sum that overflows would wrap into the
	// past. Both are refused rather than quietly produced.
	if _, err := ExpirationAfter(latestLedger, 0); errors.Is(err, ErrInvalidExpiration) {
		fmt.Println("zero ledgers refused")
	}
	if _, err := ExpirationAfter(math.MaxUint32, 1); errors.Is(err, ErrInvalidExpiration) {
		fmt.Println("overflow refused")
	}

	// Output:
	// latest=1234567 +1 -> 1234568
	// latest=1234567 +720 -> 1235287
	// zero ledgers refused
	// overflow refused
}
