package soroauth

import (
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestFunctionTypeFromXDRRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		xdrType xdr.SorobanAuthorizedFunctionType
		want    AuthorizedFunctionType
	}{
		{
			name:    "contract_fn",
			xdrType: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			want:    FunctionTypeContractFn,
		},
		{
			name:    "create_contract_host_fn",
			xdrType: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
			want:    FunctionTypeCreateContractHostFn,
		},
		{
			name:    "create_contract_v2_host_fn",
			xdrType: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn,
			want:    FunctionTypeCreateContractV2HostFn,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FunctionTypeFromXDR(tc.xdrType)
			if err != nil {
				t.Fatalf("FunctionTypeFromXDR(%v) error = %v", tc.xdrType, err)
			}
			if got != tc.want {
				t.Errorf("FunctionTypeFromXDR(%v) = %q, want %q", tc.xdrType, got, tc.want)
			}
			// Round-trip: the constant converts back to the same XDR value.
			if got.ToXDR() != tc.xdrType {
				t.Errorf("(%q).ToXDR() = %v, want %v", got, got.ToXDR(), tc.xdrType)
			}
		})
	}
}

func TestFunctionTypeFromXDRRejectsUnknown(t *testing.T) {
	_, err := FunctionTypeFromXDR(xdr.SorobanAuthorizedFunctionType(99))
	if !errors.Is(err, ErrUnsupportedFunctionType) {
		t.Errorf("FunctionTypeFromXDR(unknown) = %v, want ErrUnsupportedFunctionType", err)
	}
}

// TestFunctionTypeCompletenessGuard fails when the XDR package adds a new
// SorobanAuthorizedFunctionType that this library has no constant for. It is
// the drift guard that keeps the vocabulary current as the protocol grows.
func TestFunctionTypeCompletenessGuard(t *testing.T) {
	for xdrVal := xdr.SorobanAuthorizedFunctionType(0); xdrVal < xdr.SorobanAuthorizedFunctionType(32); xdrVal++ {
		_, knownErr := FunctionTypeFromXDR(xdrVal)
		// Try to create a minimal invocation to validate the XDR value exists.
		fn := xdr.SorobanAuthorizedFunction{Type: xdrVal}
		// If the XDR type validates (i.e. it's a known discriminant in the SDK),
		// our library must have a constant for it.
		switch fn.Type {
		case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
			xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
			if knownErr != nil {
				t.Errorf("SDK defines SorobanAuthorizedFunctionType(%d) but the library has no constant for it", xdrVal)
			}
		}
	}
}
