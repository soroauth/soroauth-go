package soroauth_test

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// entryForFunction builds an entry whose root invocation uses the given
// function type, for exercising every arm of the correspondence check.
func entryForFunction(t *testing.T, fnType xdr.SorobanAuthorizedFunctionType) xdr.SorobanAuthorizationEntry {
	t.Helper()
	var accID xdr.AccountId
	_ = accID.SetAddress("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
	account := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accID,
	}
	contractID := xdr.ContractId{1, 2, 3}
	contract := xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &contractID,
	}

	root := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: fnType,
		},
	}
	switch fnType {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		root.Function.ContractFn = &xdr.InvokeContractArgs{
			ContractAddress: contract,
			FunctionName:    xdr.ScSymbol("transfer"),
			Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: func() *xdr.Int64 { v := xdr.Int64(1); return &v }()}},
		}
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		root.Function.CreateContractHostFn = &xdr.CreateContractArgs{
			ContractIdPreimage: xdr.ContractIdPreimage{
				Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
				FromAddress: &xdr.ContractIdPreimageFromAddress{
					Address: account,
				},
			},
		}
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		root.Function.CreateContractV2HostFn = &xdr.CreateContractArgsV2{
			ContractIdPreimage: xdr.ContractIdPreimage{
				Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
				FromAddress: &xdr.ContractIdPreimageFromAddress{
					Address: account,
				},
			},
			Executable: xdr.ContractExecutable{
				Type: xdr.ContractExecutableTypeContractExecutableWasm,
				WasmHash: &xdr.Hash{1, 2, 3},
			},
			ConstructorArgs: []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: func() *xdr.Int64 { v := xdr.Int64(1); return &v }()}},
		}
	}
	return xdr.SorobanAuthorizationEntry{RootInvocation: root}
}
