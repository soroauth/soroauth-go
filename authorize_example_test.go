package soroauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// authorizeExampleEntry builds the unsigned V2 entry a simulation would return
// for a transfer authorized by address, with a fixed nonce and contract so the
// authorize examples print the same thing on every run.
func authorizeExampleEntry(address string) (xdr.SorobanAuthorizationEntry, error) {
	credentialAddress, err := ParseAddress(address)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	contractSeed := sha256.Sum256([]byte("soroauth-example-contract"))
	contractStrkey, err := strkey.Encode(strkey.VersionByteContract, contractSeed[:])
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	contract, err := ParseAddress(contractStrkey)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   credentialAddress,
				Nonce:     42,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{},
				},
			},
		},
	}, nil
}

// ExampleAuthorizeEntry signs the entry a simulation returned for a classic
// account. The expiration is both signed over and written into the entry, so
// rebuilding the payload from the signed entry reproduces exactly what was
// signed. The caller's entry is left untouched.
//
// A signer whose address is not on the entry is refused with
// ErrNoMatchingCredentialNode rather than written onto the top-level node,
// which is where this library deliberately differs from the JS SDK.
func ExampleAuthorizeEntry() {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err := authorizeExampleEntry(account.Address())
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	const validUntilLedger = 1_234_567
	passphrase := network.TestNetworkPassphrase
	signed, err := AuthorizeEntry(context.Background(), entry, NewEd25519Signer(account),
		validUntilLedger, passphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := Inspect(signed)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%s signed=%t expires=%d\n", info.CredentialType, info.TopLevelSigned, info.ValidUntilLedger)

	// Rebuild the payload from what the entry now carries and check the
	// signature against it, as the host will.
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
	vec, _ := signed.Credentials.AddressV2.Signature.GetVec()
	m, _ := (*vec)[0].GetMap()
	fmt.Println("verifies:", account.Verify(payload[:], []byte(*(*m)[1].Val.Bytes)) == nil)

	original, err := Inspect(entry)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("input still unsigned:", !original.TopLevelSigned)

	stranger, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-stranger")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	_, err = AuthorizeEntry(context.Background(), entry, NewEd25519Signer(stranger),
		validUntilLedger, passphrase)
	fmt.Println("stranger refused:", errors.Is(err, ErrNoMatchingCredentialNode))

	// Output:
	// address_v2 signed=true expires=1234567
	// verifies: true
	// input still unsigned: true
	// stranger refused: true
}

// ExampleForAddress signs a classic account's node with a key that is one of
// its signers but not its master key, so the key's own address differs from
// the account's. Without ForAddress the target is the key's own address,
// which is not on the entry, and the call is refused rather than guessed.
// ForAddress names the account's node explicitly.
func ExampleForAddress() {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// A key the account has added as a signer (via set_options).
	cosigner, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-signer-1")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err := authorizeExampleEntry(account.Address())
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	signer := NewEd25519Signer(cosigner)

	_, err = AuthorizeEntry(context.Background(), entry, signer, 1_234_567,
		network.TestNetworkPassphrase)
	fmt.Println("without ForAddress refused:", errors.Is(err, ErrNoMatchingCredentialNode))

	signed, err := AuthorizeEntry(context.Background(), entry, signer, 1_234_567,
		network.TestNetworkPassphrase, ForAddress(account.Address()))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	info, err := Inspect(signed)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("account node signed:", info.Address == account.Address() && info.TopLevelSigned)

	// Output:
	// without ForAddress refused: true
	// account node signed: true
}

// phaseRecorder is a Hook that remembers the phases it saw.
type phaseRecorder struct {
	phases []HookPhase
}

func (r *phaseRecorder) Event(_ context.Context, e HookEvent) error {
	r.phases = append(r.phases, e.Phase)
	return nil
}

// ExampleWithHook observes the signing lifecycle, for metrics or tracing. A
// hook sees addresses, the credential type and the expiration, never key or
// payload material.
//
// The order printed is the order AuthorizeEntry emits today (authorize.go):
// preimage once the preimage is built, sign just before the signer is called,
// write just before the signature is written, and post_sign once it has been
// written and the signed entry is about to be returned.
func ExampleWithHook() {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err := authorizeExampleEntry(account.Address())
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	recorder := &phaseRecorder{}
	_, err = AuthorizeEntry(context.Background(), entry, NewEd25519Signer(account), 1_234_567,
		network.TestNetworkPassphrase, WithHook(recorder))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(recorder.phases)

	// Output:
	// [preimage sign write post_sign]
}
