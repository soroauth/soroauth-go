package soroauth

import (
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestCredentialArmString(t *testing.T) {
	tests := []struct {
		name string
		arm  CredentialArm
		want string
	}{
		{name: "source account", arm: ArmSourceAccount, want: CredentialTypeSourceAccount},
		{name: "legacy address", arm: ArmAddress, want: CredentialTypeAddress},
		{name: "address v2", arm: ArmAddressV2, want: CredentialTypeAddressV2},
		{name: "address with delegates", arm: ArmAddressWithDelegates, want: CredentialTypeAddressWithDelegates},
		{name: "empty", arm: CredentialArm(""), want: `unknown("")`},
		{name: "unrecognised", arm: CredentialArm("address_v3"), want: `unknown("address_v3")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.arm.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			// %v and %s go through String, which is the point of having it.
			if got := fmt.Sprintf("%v", tt.arm); got != tt.want {
				t.Errorf("%%v = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCredentialArmStringMatchesInspect ties String to Inspect: for every
// credentials type the SDK's enum accepts, the arm's String must equal the
// credential_type Inspect reports for an entry of that type. A new arm in the
// SDK without a matching arm here fails rather than printing as unknown.
func TestCredentialArmStringMatchesInspect(t *testing.T) {
	var credentialsType xdr.SorobanCredentialsType
	checked := 0
	for v := int32(-16); v < 1024; v++ {
		if !credentialsType.ValidEnum(v) {
			continue
		}
		armType := xdr.SorobanCredentialsType(v)
		t.Run(armType.String(), func(t *testing.T) {
			arm := credentialTypeToArm(armType)
			if arm == "" {
				t.Fatalf("credentials type %v has no CredentialArm", armType)
			}
			info, err := Inspect(entryForArm(t, armType, 42))
			if err != nil {
				t.Fatalf("Inspect returned an unexpected error: %v", err)
			}
			if got := arm.String(); got != info.CredentialType {
				t.Errorf("%v: String() = %q, Inspect reports %q", armType, got, info.CredentialType)
			}
		})
		checked++
	}
	if checked != len(armBehaviors) {
		t.Errorf("checked %d SDK credentials types, but %d arms are defined", checked, len(armBehaviors))
	}
}
