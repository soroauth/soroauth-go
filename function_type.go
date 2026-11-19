package soroauth

import (
	"github.com/stellar/go-stellar-sdk/xdr"
)

// AuthorizedFunctionType identifies the type of function a Soroban
// authorization invocation authorizes. This mirrors how CredentialArm exposes
// the credential arms: a typed vocabulary a caller can switch on without
// reaching into the SDK's doubled enum names.
type AuthorizedFunctionType string

// The three SorobanAuthorizedFunction types defined by the protocol. They are
// reported by FunctionTypeFromXDR and are the same stable strings the CLI
// and Inspect surface through the invocation tree.
//
// Source: CAP-46-11 (ContractFn and CreateContractHostFn) and CAP-71-01
// (CreateContractV2HostFn), xdr/Stellar-transaction.x.
const (
	FunctionTypeContractFn             AuthorizedFunctionType = "contract_fn"
	FunctionTypeCreateContractHostFn   AuthorizedFunctionType = "create_contract_host_fn"
	FunctionTypeCreateContractV2HostFn AuthorizedFunctionType = "create_contract_v2_host_fn"
)

// functionTypeToXDR maps each AuthorizedFunctionType to its XDR discriminant.
// It is the single source of truth; FunctionTypeFromXDR and ToXDR both derive
// from it, so the two cannot drift from each other.
var functionTypeToXDR = map[AuthorizedFunctionType]xdr.SorobanAuthorizedFunctionType{
	FunctionTypeContractFn:             xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
	FunctionTypeCreateContractHostFn:   xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
	FunctionTypeCreateContractV2HostFn: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn,
}

// FunctionTypeFromXDR converts an XDR SorobanAuthorizedFunctionType
// discriminant into the library's typed constant. It returns
// ErrUnsupportedFunctionType for any value this build does not know.
func FunctionTypeFromXDR(t xdr.SorobanAuthorizedFunctionType) (AuthorizedFunctionType, error) {
	for ft, xdrVal := range functionTypeToXDR {
		if xdrVal == t {
			return ft, nil
		}
	}
	return "", ErrUnsupportedFunctionType
}

// ToXDR returns the XDR discriminant for this function type. It panics for a
// value that was not produced by FunctionTypeFromXDR, since such a value is a
// programming error rather than untrusted input.
func (ft AuthorizedFunctionType) ToXDR() xdr.SorobanAuthorizedFunctionType {
	xdrVal, ok := functionTypeToXDR[ft]
	if !ok {
		panic("soroauth: ToXDR called on unknown AuthorizedFunctionType: " + string(ft))
	}
	return xdrVal
}
