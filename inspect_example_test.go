package soroauth_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Fixed, derived from labels so the output is reproducible. Public test values
// holding nothing, named for this file so each example file stays independent.
const (
	inspectExampleWallet   = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	inspectExampleDelegate = "GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO"
	inspectExampleContract = "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA"
)

// inspectExampleInvocation builds a transfer call with one sub-invocation, so
// the recursive SubInvocations count has something to count.
func inspectExampleInvocation() xdr.SorobanAuthorizedInvocation {
	contract, err := soroauth.ParseAddress(inspectExampleContract)
	if err != nil {
		panic(err)
	}
	call := func(fn string) xdr.SorobanAuthorizedFunction {
		return xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contract,
				FunctionName:    xdr.ScSymbol(fn),
			},
		}
	}
	return xdr.SorobanAuthorizedInvocation{
		Function: call("transfer"),
		SubInvocations: []xdr.SorobanAuthorizedInvocation{{
			Function: call("burn"),
		}},
	}
}

func inspectExampleV2Entry() xdr.SorobanAuthorizationEntry {
	address, err := soroauth.ParseAddress(inspectExampleWallet)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     1234,
				SignatureExpirationLedger: 5_000_000,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: inspectExampleInvocation(),
	}
}

// ExampleInspect reports an entry's structure.
//
// Inspect answers what kind of entry this is, who it belongs to, and which
// parts are signed. It deliberately does not say what the call *does*: the
// arguments are not interpreted and no asset or amount is named. That is a
// separate concern, and reading it into this output is how a tool ends up
// telling a user something it cannot establish.
func ExampleInspect() {
	info, err := soroauth.Inspect(inspectExampleV2Entry())
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("arm:", info.CredentialType)
	fmt.Println("address-bound:", info.AddressBound)
	fmt.Println("address:", info.Address)
	fmt.Println("nonce:", info.Nonce)
	fmt.Println("expires at ledger:", info.ValidUntilLedger)
	fmt.Println("top-level signed:", info.TopLevelSigned)
	fmt.Println("root function:", info.RootFunction)
	fmt.Println("sub-invocations:", info.SubInvocations)

	// Output:
	// arm: address_v2
	// address-bound: true
	// address: GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5
	// nonce: 1234
	// expires at ledger: 5000000
	// top-level signed: false
	// root function: transfer
	// sub-invocations: 1
}

// ExampleInspect_json shows that EntryInfo is a wire shape as well as a Go
// struct. Its field names are what the CLI's inspect subcommand prints, so a
// script can read them.
func ExampleInspect_json() {
	info, err := soroauth.Inspect(inspectExampleV2Entry())
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(info); err != nil {
		fmt.Println("error:", err)
	}

	// Output:
	// {
	//   "credential_type": "address_v2",
	//   "address_bound": true,
	//   "address": "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5",
	//   "nonce": 1234,
	//   "valid_until_ledger": 5000000,
	//   "top_level_signed": false,
	//   "root_contract": "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA",
	//   "root_function": "transfer",
	//   "sub_invocations": 1
	// }
}

// ExampleInspect_delegates walks a delegate tree.
//
// The per-node Signed flags are the field to read before submitting. AuthorizeAll
// returning a nil error does not mean every node is signed — it cannot know an
// account's policy, so a delegate with no matching signer is left unsigned
// deliberately. These flags are how a caller checks.
func ExampleInspect_delegates() {
	wrapped, err := soroauth.WithDelegates(inspectExampleV2Entry(), 5_000_000,
		[]soroauth.Delegate{{Address: inspectExampleDelegate}}, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := soroauth.Inspect(wrapped)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("arm:", info.CredentialType)
	fmt.Println("top-level signed:", info.TopLevelSigned)
	for _, d := range info.Delegates {
		fmt.Printf("delegate %s signed=%t\n", d.Address, d.Signed)
	}

	// Output:
	// arm: address_with_delegates
	// top-level signed: false
	// delegate GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO signed=false
}

// ExampleInspect_sourceAccount shows the arm that carries no credential of its
// own: the transaction's envelope signature authorizes it, so there is no
// address, nonce or expiration to report.
func ExampleInspect_sourceAccount() {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
		RootInvocation: inspectExampleInvocation(),
	}

	info, err := soroauth.Inspect(entry)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("arm:", info.CredentialType)
	fmt.Println("address-bound:", info.AddressBound)
	fmt.Printf("address: %q\n", info.Address)
	fmt.Println("root function:", info.RootFunction)

	// Output:
	// arm: source_account
	// address-bound: false
	// address: ""
	// root function: transfer
}
