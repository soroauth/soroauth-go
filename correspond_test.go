package soroauth_test

import "github.com/stellar/go-stellar-sdk/xdr"

func init() {
	_ = xdr.Hash{}
}

// entryForFunction builds an entry whose root invocation uses the given
// function type, for exercising every arm of the correspondence check.
func entryForFunction(t *testing.T, fnType xdr.SorobanAuthorizedFunctionType) xdr.SorobanAuthorizationEntry {
	t.Helper()
	account := mustParse(t, testKeypair(t, "soroauth-correspond-account").Address())
	contract := mustParse(t, testContractAddress(t, "soroauth-correspond-contract"))

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
				WasmHash: &xdr.Hash{
					Hash: [32]byte{1, 2, 3},
				},
			},
			ConstructorArgs: []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: func() *xdr.Int64 { v := xdr.Int64(1); return &v }()}},
		}
	}
	return xdr.SorobanAuthorizationEntry{RootInvocation: root}
}
