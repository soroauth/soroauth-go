package soroauth_test

import (
	"bytes"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Unsigned entry from testdata/vectors/v2_empty_args.json.
const canonicalExampleUnsigned = "AAAAAgAAAAAAAAAAt7bYKS3hKDB7Aw8ykLPfkH7kJtcX2OWQMp2pPDOof8oRIhD0femBFQAAAAAAAAAQAAAAAQAAAAAAAAAAAAAAAWsigAe28NAI+AYqzjlUB0zlzb9U6kzFAwIvCJPm9Q6zAAAABG5vb3AAAAAAAAAAAA=="

// ExampleMarshalCanonicalJSON compares a decoded entry with a rebuilt entry.
func ExampleMarshalCanonicalJSON() {
	golden, err := soroauth.DecodeAuthorizationEntry(canonicalExampleUnsigned)
	if err != nil {
		panic(err)
	}
	rebuilt := xdr.SorobanAuthorizationEntry{
		Credentials: golden.Credentials,
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: golden.RootInvocation.Function.ContractFn.ContractAddress,
					FunctionName:    "noop",
				},
			},
		},
	}
	a, err := soroauth.MarshalCanonicalJSON(golden)
	if err != nil {
		panic(err)
	}
	b, err := soroauth.MarshalCanonicalJSON(rebuilt)
	if err != nil {
		panic(err)
	}

	fmt.Println("XDR entries equal:", soroauth.Equal(golden, rebuilt))
	fmt.Println("canonical JSON equal:", bytes.Equal(a, b))

	// Output:
	// XDR entries equal: true
	// canonical JSON equal: true
}

// ExampleUnmarshalCanonicalJSON reads an entry back from canonical JSON.
func ExampleUnmarshalCanonicalJSON() {
	entry, err := soroauth.DecodeAuthorizationEntry(canonicalExampleUnsigned)
	if err != nil {
		panic(err)
	}
	data, err := soroauth.MarshalCanonicalJSON(entry)
	if err != nil {
		panic(err)
	}
	restored, err := soroauth.UnmarshalCanonicalJSON(data)
	if err != nil {
		panic(err)
	}

	fmt.Println("function:", restored.RootInvocation.Function.ContractFn.FunctionName)
	fmt.Println("XDR round trip:", soroauth.Equal(entry, restored))

	// Output:
	// function: noop
	// XDR round trip: true
}
