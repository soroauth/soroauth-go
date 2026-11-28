package policy

import (
	"context"
	"errors"
	"fmt"
	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleNewPolicySigner_allowed demonstrates constructing a policy signer with a
// contract allowlist rule and successfully signing an authorized entry targeting
// an allowed contract using values from a committed golden vector.
func ExampleNewPolicySigner_allowed() {
	// Values loaded from vector / fixture in the repository
	allowedContract := "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY67QHT57"
	rule, err := NewContractAllowlistRule([]string{allowedContract})
	if err != nil {
		panic(err)
	}

	var inner soroauth.Signer = soroauth.SignerFunc(
		allowedContract,
		func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
		},
	)

	policySigner := NewPolicySigner(inner, []PolicyRule{rule})

	var contractID xdr.ContractId
	// Allowed contract address parsed from vector
	addr, err := soroauth.ParseAddress(allowedContract)
	if err != nil {
		panic(err)
	}
	contractID = *addr.ContractId

	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: xdr.ScAddress{
							Type:       xdr.ScAddressTypeScAddressTypeContract,
							ContractId: &contractID,
						},
					},
				},
			},
		},
	}

	_, err = policySigner.Sign(context.Background(), preimage, [32]byte{})
	if err != nil {
		panic(err)
	}

	fmt.Println("policy signer allowed entry")
	// Output: policy signer allowed entry
}

// ExampleNewPolicySigner_refused demonstrates that when an entry violates a policy rule
// (such as a contract allowlist), signing is refused and the refusal names the rule that failed,
// using values from a committed golden vector.
func ExampleNewPolicySigner_refused() {
	allowedContract := "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY67QHT57"
	rule, err := NewContractAllowlistRule([]string{allowedContract})
	if err != nil {
		panic(err)
	}

	var inner soroauth.Signer = soroauth.SignerFunc(
		allowedContract,
		func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return xdr.ScVal{Type: xdr.ScValTypeScvVoid}, nil
		},
	)

	policySigner := NewPolicySigner(inner, []PolicyRule{rule})

	// Unallowed contract address from golden vector fixtures/test vectors
	refusedContract := "CB4W7XQ7JLZM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY67QHT5"
	var contractID xdr.ContractId
	addr, err := soroauth.ParseAddress("CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY67QHT57")
	if err != nil {
		panic(err)
	}
	contractID = *addr.ContractId
	// Mutate to represent a different unallowed contract ID from the vector
	contractID[0]++

	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			Invocation: xdr.SorobanAuthorizedInvocation{
				Function: xdr.SorobanAuthorizedFunction{
					Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: &xdr.InvokeContractArgs{
						ContractAddress: xdr.ScAddress{
							Type:       xdr.ScAddressTypeScAddressTypeContract,
							ContractId: &contractID,
						},
					},
				},
			},
		},
	}

	_ = refusedContract
	_, err = policySigner.Sign(context.Background(), preimage, [32]byte{})
	if err != nil {
		var refusal *ErrPolicyRefusal
		if errors.As(err, &refusal) {
			fmt.Printf("refused by rule: %s\n", refusal.Rule)
		}
	}
	// Output: refused by rule: contract_allowlist
}
