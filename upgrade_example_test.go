package soroauth_test

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Fixed, derived from labels so the output is reproducible. Public test values
// holding nothing, named for this file so each example file stays independent.
const (
	upgradeExampleWallet   = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	upgradeExampleContract = "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA"
)

// upgradeExampleLegacyEntry builds an unsigned legacy (CAP-46-11 address arm)
// entry, the shape simulation can hand back when it is not asked for V2.
func upgradeExampleLegacyEntry(signature xdr.ScVal) xdr.SorobanAuthorizationEntry {
	address, err := soroauth.ParseAddress(upgradeExampleWallet)
	if err != nil {
		panic(err)
	}
	contract, err := soroauth.ParseAddress(upgradeExampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     1234,
				Signature: signature,
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
}

// ExampleUpgradeToV2 converts an unsigned legacy entry to the V2 arm.
//
// Simulation may return either arm. The RPC's UseUpgradedAuth asks for V2 on a
// best-effort basis, so a caller who needs V2 has to check what arrived and
// upgrade it — which is what this is for.
//
// The nonce, address and invocation carry across unchanged. What changes is the
// payload the signature will be taken over: the V2 preimage includes the
// signer's address, so the entry becomes address-bound.
func ExampleUpgradeToV2() {
	legacy := upgradeExampleLegacyEntry(xdr.ScVal{Type: xdr.ScValTypeScvVoid})

	before, err := soroauth.Inspect(legacy)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("before: %s address-bound=%t nonce=%d\n",
		before.CredentialType, before.AddressBound, before.Nonce)

	upgraded, err := soroauth.UpgradeToV2(legacy)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	after, err := soroauth.Inspect(upgraded)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("after:  %s address-bound=%t nonce=%d\n",
		after.CredentialType, after.AddressBound, after.Nonce)

	// Output:
	// before: address address-bound=false nonce=1234
	// after:  address_v2 address-bound=true nonce=1234
}

// ExampleUpgradeToV2_alreadyV2 shows that a V2 entry passes through.
//
// So a caller can send everything simulation returned through UpgradeToV2
// without sorting the entries by arm first.
func ExampleUpgradeToV2_alreadyV2() {
	address, err := soroauth.ParseAddress(upgradeExampleWallet)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	contract, err := soroauth.ParseAddress(upgradeExampleContract)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	v2 := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     1234,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	upgraded, err := soroauth.UpgradeToV2(v2)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	info, err := soroauth.Inspect(upgraded)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("arm:", info.CredentialType)

	// Output:
	// arm: address_v2
}

// ExampleUpgradeToV2_alreadySigned shows the refusal, and it is the reason this
// function exists as a separate step rather than something AuthorizeEntry does
// silently.
//
// Upgrading changes the payload the signature is taken over, because the V2
// preimage binds the address. A signature made over the legacy payload would
// therefore stop verifying. Rather than hand back an entry carrying a signature
// that no longer means anything, UpgradeToV2 refuses.
//
// The Void and empty-vector placeholders simulation leaves behind are not
// signatures, so those upgrade fine — as ExampleUpgradeToV2 shows.
func ExampleUpgradeToV2_alreadySigned() {
	signature := xdr.ScVal{Type: xdr.ScValTypeScvBytes}
	raw := xdr.ScBytes([]byte("not a real signature, but not a placeholder either"))
	signature.Bytes = &raw

	_, err := soroauth.UpgradeToV2(upgradeExampleLegacyEntry(signature))
	fmt.Println(err)

	// Output:
	// soroauth: upgrade to v2: the upgrade changes the signing payload, invalidating the existing signature: credential node is already signed
}
