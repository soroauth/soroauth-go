package soroauth

import (
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestFunctionTypeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		sdk  xdr.SorobanAuthorizedFunctionType
		want FunctionType
	}{
		{"contract fn", xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn, FunctionContractFn},
		{"create contract host fn", xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn, FunctionCreateContractHostFn},
		{"create contract v2 host fn", xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn, FunctionCreateContractV2HostFn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FunctionTypeFromXDR(tt.sdk)
			if err != nil {
				t.Fatalf("FunctionTypeFromXDR(%v): %v", tt.sdk, err)
			}
			if got != tt.want {
				t.Errorf("FunctionTypeFromXDR(%v) = %q, want %q", tt.sdk, got, tt.want)
			}
			back, err := got.XDR()
			if err != nil {
				t.Fatalf("%q.XDR(): %v", got, err)
			}
			if back != tt.sdk {
				t.Errorf("%q.XDR() = %v, want %v", got, back, tt.sdk)
			}
		})
	}
}

func TestFunctionTypeRejectsUnknownValues(t *testing.T) {
	t.Run("from xdr", func(t *testing.T) {
		got, err := FunctionTypeFromXDR(xdr.SorobanAuthorizedFunctionType(99))
		if !errors.Is(err, ErrUnsupportedFunctionType) {
			t.Fatalf("FunctionTypeFromXDR(99) error = %v, want %v", err, ErrUnsupportedFunctionType)
		}
		if got != "" {
			t.Errorf("FunctionTypeFromXDR(99) = %q alongside an error, want empty", got)
		}
	})

	for _, value := range []FunctionType{"", "contract", "CONTRACT_FN"} {
		t.Run("to xdr "+string(value), func(t *testing.T) {
			got, err := value.XDR()
			if !errors.Is(err, ErrUnsupportedFunctionType) {
				t.Fatalf("%q.XDR() error = %v, want %v", value, err, ErrUnsupportedFunctionType)
			}
			if got != 0 {
				t.Errorf("%q.XDR() = %v alongside an error, want the zero value", value, got)
			}
		})
	}
}

// TestFunctionTypeCoversTheSDKEnum fails when the SDK's
// SorobanAuthorizedFunctionType gains a value that has no FunctionType here,
// which is what keeps the constants current as the protocol grows.
func TestFunctionTypeCoversTheSDKEnum(t *testing.T) {
	var sdkEnum xdr.SorobanAuthorizedFunctionType
	seen := map[FunctionType]bool{}
	for v := int32(-16); v < 1024; v++ {
		if !sdkEnum.ValidEnum(v) {
			continue
		}
		sdk := xdr.SorobanAuthorizedFunctionType(v)
		got, err := FunctionTypeFromXDR(sdk)
		if err != nil {
			t.Errorf("SDK function type %v (%d) has no FunctionType: %v", sdk, v, err)
			continue
		}
		if seen[got] {
			t.Errorf("FunctionType %q is returned for more than one SDK value", got)
		}
		seen[got] = true
	}
	if len(seen) != 3 {
		t.Errorf("the SDK enum mapped to %d FunctionTypes, want 3", len(seen))
	}
}
