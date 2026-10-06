package soroauth_test

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Addresses used by the examples in this file. They are derived from fixed
// labels so the output is reproducible; they hold nothing and are not funded.
const (
	exampleWallet    = "GASI5PH5KDJFVFU4XGLLRGRNA426GVNZQCLA6PENWMAJRJ4JC3GC4CQ5"
	exampleDelegate1 = "GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO"
	exampleDelegate2 = "GDYJDW3KVAF2FQGR7L47ITRSQOTF2HRULE7KWTTXVOZFL36IIDTWOOWF"
	exampleContract  = "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA"
)

// exampleV2Entry builds an unsigned V2-arm entry for exampleWallet, calling
// transfer on exampleContract. The examples below start from this.
func exampleV2Entry() xdr.SorobanAuthorizationEntry {
	address, err := soroauth.ParseAddress(exampleWallet)
	if err != nil {
		panic(err)
	}
	contract, err := soroauth.ParseAddress(exampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizationEntry{
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
}

// ExampleWithDelegates wraps an entry in the CAP-71-01 delegates arm.
//
// The delegates are given in the order they came to hand. WithDelegates sorts
// them into the order the protocol requires — ascending by the XDR encoding of
// the address — so a caller never has to know that rule.
func ExampleWithDelegates() {
	// Deliberately not in protocol order: delegate 2 sorts before delegate 1.
	delegates := []soroauth.Delegate{
		{Address: exampleDelegate1},
		{Address: exampleDelegate2},
	}

	wrapped, err := soroauth.WithDelegates(exampleV2Entry(), 5_000_000, delegates, nil)
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
	for i, d := range info.Delegates {
		fmt.Printf("delegate %d: %s signed=%t\n", i, d.Address, d.Signed)
	}

	// Output:
	// arm: address_with_delegates
	// top-level signed: false
	// delegate 0: GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO signed=false
	// delegate 1: GDYJDW3KVAF2FQGR7L47ITRSQOTF2HRULE7KWTTXVOZFL36IIDTWOOWF signed=false
}

// ExampleWithDelegates_nested shows a delegate that has delegates of its own.
//
// Nesting is library-only: the CLI's delegates subcommand takes a flat list.
// Every level is sorted independently, and a Void top-level signature is
// permitted by CAP-71-01 when an account authenticates purely through its
// delegates.
func ExampleWithDelegates_nested() {
	delegates := []soroauth.Delegate{{
		Address: exampleDelegate1,
		Nested:  []soroauth.Delegate{{Address: exampleDelegate2}},
	}}

	wrapped, err := soroauth.WithDelegates(exampleV2Entry(), 5_000_000, delegates, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := soroauth.Inspect(wrapped)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("delegate: %s\n", info.Delegates[0].Address)
	fmt.Printf("  nested: %s\n", info.Delegates[0].Nested[0].Address)

	// Output:
	// delegate: GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO
	//   nested: GDYJDW3KVAF2FQGR7L47ITRSQOTF2HRULE7KWTTXVOZFL36IIDTWOOWF
}

// ExampleWithDelegates_duplicate shows the refusal.
//
// The same address twice at one level is rejected, because the host rejects it:
// it compares each adjacent pair and refuses a duplicate before the account
// contract ever runs. The same address at two *different* levels is allowed,
// which is what ExampleWithDelegates_nested relies on.
func ExampleWithDelegates_duplicate() {
	delegates := []soroauth.Delegate{
		{Address: exampleDelegate1},
		{Address: exampleDelegate1},
	}

	_, err := soroauth.WithDelegates(exampleV2Entry(), 5_000_000, delegates, nil)
	fmt.Println(err)

	// Output:
	// soroauth: with delegates: GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO: duplicate delegate address at the same level
}

// ExampleValidateDelegateOrder checks an entry that already carries delegates.
//
// AuthorizeEntry calls this itself before signing a delegates-arm entry, so a
// caller rarely needs it. It is exported for the case where an entry arrived
// from somewhere else and the ordering has not been established.
func ExampleValidateDelegateOrder() {
	wrapped, err := soroauth.WithDelegates(exampleV2Entry(), 5_000_000,
		[]soroauth.Delegate{{Address: exampleDelegate1}, {Address: exampleDelegate2}}, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// WithDelegates sorted them, so this passes.
	fmt.Println("as built:", soroauth.ValidateDelegateOrder(wrapped))

	// Swapping two delegates breaks the ordering the protocol requires.
	d := wrapped.Credentials.AddressWithDelegates.Delegates
	d[0], d[1] = d[1], d[0]
	fmt.Println("after swapping:", soroauth.ValidateDelegateOrder(wrapped))

	// Output:
	// as built: <nil>
	// after swapping: soroauth: validate delegate order: delegates are not in ascending address order at index 1 (GDLJL2KB4X4CF6T2J7XPJ76ISLVL7U6TGMZRXU474NSH7ITAXM23UUAO)
}
