package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// FunctionType identifies which kind of function an authorized invocation
// approves. It is the soroauth vocabulary for the SDK's
// xdr.SorobanAuthorizedFunctionType, exposed the way CredentialArm exposes the
// credentials arms, so a caller branching on the function type does not have
// to reach into the SDK's generated enum names.
type FunctionType string

// The three SorobanAuthorizedFunctionType values defined by the protocol, as
// enumerated in go-stellar-sdk v0.7.3 xdr/xdr_generated.go (enum
// SorobanAuthorizedFunctionType: SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
// SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_HOST_FN and
// SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN). The string
// values are the names the canonical JSON form and DiffEntries already use for
// these arms. They are stable: callers match on them.
const (
	FunctionContractFn             FunctionType = "contract_fn"
	FunctionCreateContractHostFn   FunctionType = "create_contract_host_fn"
	FunctionCreateContractV2HostFn FunctionType = "create_contract_v2_host_fn"
)

// FunctionTypeFromXDR converts the SDK's enum to a FunctionType. A value this
// library does not know returns ErrUnsupportedFunctionType and an empty
// FunctionType, never a zero value that reads as contract_fn.
func FunctionTypeFromXDR(t xdr.SorobanAuthorizedFunctionType) (FunctionType, error) {
	switch t {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn:
		return FunctionContractFn, nil
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn:
		return FunctionCreateContractHostFn, nil
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		return FunctionCreateContractV2HostFn, nil
	default:
		return "", fmt.Errorf("soroauth: function type %d: %w", int32(t), ErrUnsupportedFunctionType)
	}
}

// XDR converts a FunctionType back to the SDK's enum. A value that is not one
// of the three constants returns ErrUnsupportedFunctionType rather than
// SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN, the enum's zero value.
func (f FunctionType) XDR() (xdr.SorobanAuthorizedFunctionType, error) {
	switch f {
	case FunctionContractFn:
		return xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn, nil
	case FunctionCreateContractHostFn:
		return xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn, nil
	case FunctionCreateContractV2HostFn:
		return xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn, nil
	default:
		return 0, fmt.Errorf("soroauth: function type %q: %w", string(f), ErrUnsupportedFunctionType)
	}
}
