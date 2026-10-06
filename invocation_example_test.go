package soroauth_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Fixed, derived from labels so the output is reproducible. These are public
// test values holding nothing. They are named for this file so each example
// file stays independent of the others.
const (
	invocationExampleWallet   = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	invocationExampleContract = "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA"
)

// invocationExampleTree is the call tree the examples below authorize.
func invocationExampleTree() xdr.SorobanAuthorizedInvocation {
	contract, err := soroauth.ParseAddress(invocationExampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contract,
				FunctionName:    xdr.ScSymbol("transfer"),
			},
		},
	}
}

// exampleSigner is a signer over a keypair derived from a fixed label, so the
// examples are reproducible. It is a public test key and holds nothing.
func invocationExampleSigner() soroauth.Signer {
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-wallet")))
	if err != nil {
		panic(err)
	}
	return soroauth.NewEd25519Signer(kp)
}

// ExampleAuthorizeInvocation builds and signs an entry from scratch.
//
// This is the path for an invocation a caller assembled themselves, rather than
// one simulation handed back. The nonce is read from crypto/rand, so the signed
// bytes differ on every run — hence the example prints the structure rather
// than the entry.
func ExampleAuthorizeInvocation() {
	entry, err := soroauth.AuthorizeInvocation(context.Background(), soroauth.AuthorizeInvocationParams{
		Signer:            invocationExampleSigner(),
		Invocation:        invocationExampleTree(),
		ValidUntilLedger:  5_000_000,
		NetworkPassphrase: network.TestNetworkPassphrase,
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := soroauth.Inspect(entry)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("arm:", info.CredentialType)
	fmt.Println("address-bound:", info.AddressBound)
	fmt.Println("address:", info.Address)
	fmt.Println("signed:", info.TopLevelSigned)
	fmt.Println("expires at ledger:", info.ValidUntilLedger)
	fmt.Println("function:", info.RootFunction)

	// Output:
	// arm: address_v2
	// address-bound: true
	// address: GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5
	// signed: true
	// expires at ledger: 5000000
	// function: transfer
}

// ExampleAuthorizeInvocation_legacy builds the CAP-46-11 address arm instead.
//
// The zero value of Legacy is false, so V2 is the default — matching
// @stellar/stellar-sdk, whose authorizeInvocation defaults authV2 to true. Set
// Legacy only for a counterparty that cannot read V2 yet.
//
// The difference is not cosmetic: V2 binds the signer's address into the signed
// payload, which closes a narrow replay case where a key is shared across
// accounts and the contract does not bind the address in its arguments.
func ExampleAuthorizeInvocation_legacy() {
	entry, err := soroauth.AuthorizeInvocation(context.Background(), soroauth.AuthorizeInvocationParams{
		Signer:            invocationExampleSigner(),
		Invocation:        invocationExampleTree(),
		ValidUntilLedger:  5_000_000,
		NetworkPassphrase: network.TestNetworkPassphrase,
		Legacy:            true,
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := soroauth.Inspect(entry)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("arm:", info.CredentialType)
	fmt.Println("address-bound:", info.AddressBound)

	// Output:
	// arm: address
	// address-bound: false
}

// ExampleAuthorizeInvocation_expirationRequired shows the refusal.
//
// An expiration of zero is rejected rather than treated as "no expiry". A
// signature valid forever is not something this library will produce by
// omission.
func ExampleAuthorizeInvocation_expirationRequired() {
	_, err := soroauth.AuthorizeInvocation(context.Background(), soroauth.AuthorizeInvocationParams{
		Signer:            invocationExampleSigner(),
		Invocation:        invocationExampleTree(),
		NetworkPassphrase: network.TestNetworkPassphrase,
		// ValidUntilLedger left at zero.
	})
	fmt.Println(err)

	// Output:
	// soroauth: authorize invocation: soroauth: authorize entry: expiration ledger is zero: invalid signature expiration ledger
}
