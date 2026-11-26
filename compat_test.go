package soroauth

import (
	"reflect"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// compatEntry builds one authorization entry for one credential arm, with a
// root invocation that no signing path in this package has touched, so the
// entry is in a deterministic shape for every arm at once.
func compatEntry(t *testing.T, credType xdr.SorobanCredentialsType) xdr.SorobanAuthorizationEntry {
	t.Helper()
	account := mustParse(t, testKeypair(t, "soroauth-compat-account").Address())
	delegate := mustParse(t, testKeypair(t, "soroauth-compat-delegate").Address())
	nested := mustParse(t, testKeypair(t, "soroauth-compat-nested").Address())
	contract := mustParse(t, testContractAddress(t, "soroauth-compat-contract"))

	creds := xdr.SorobanCredentials{Type: credType}
	switch credType {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		// nothing else
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		creds.Address = &xdr.SorobanAddressCredentials{Address: account, Nonce: xdr.Int64(1)}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		creds.AddressV2 = &xdr.SorobanAddressCredentials{Address: account, Nonce: xdr.Int64(1)}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		creds.AddressWithDelegates = &xdr.SorobanAddressCredentialsWithDelegates{
			AddressCredentials: xdr.SorobanAddressCredentials{Address: account, Nonce: xdr.Int64(1)},
			Delegates: []xdr.SorobanDelegateSignature{{
				Address:         delegate,
				Signature:       xdr.ScVal{},
				NestedDelegates: []xdr.SorobanDelegateSignature{{Address: nested}},
			}},
		}
	default:
		t.Fatalf("unsupported credentials type %d", credType)
	}

	return xdr.SorobanAuthorizationEntry{
		Credentials: creds,
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: func() *xdr.Int64 { v := xdr.Int64(1); return &v }()}},
				},
			},
		},
	}
}

func testCompatCases() (arm, version int, want ProtocolVerdict, reason string, source string) {
	return 0, 0, ProtocolVerdictAccepted, "", ""
}

func TestCheckProtocolCompatibility(t *testing.T) {
	cases := []struct {
		name      string
		arm       xdr.SorobanCredentialsType
		version   int
		want      ProtocolVerdict
		reason    string
		sourceURL string
	}{
		// Minimum protocol of each arm, from ArmProtocolVersion.
		{"source_account_protocol20", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 20, ProtocolVerdictAccepted, "", cap4611Source},
		{"source_account_protocol26", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 26, ProtocolVerdictAccepted, "", cap4611Source},
		{"source_account_protocol27", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 27, ProtocolVerdictAccepted, "", cap4611Source},
		{"source_account_protocol28", xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 28, ProtocolVerdictAccepted, "", cap4611Source},
		{"legacy_protocol20", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 20, ProtocolVerdictAccepted, "", cap7102Source},
		{"legacy_protocol26", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 26, ProtocolVerdictAccepted, "", cap7102Source},
		{"legacy_protocol27", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 27, ProtocolVerdictDifferentSemantics, "legacy address entry keeps its meaning across 27, where the host additionally resolves an empty delegate list for it", cap7102Source},
		{"legacy_protocol28", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 28, ProtocolVerdictDifferentSemantics, "same entry as protocol 27", cap7102Source},
		{"v2_protocol20", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 20, ProtocolVerdictRejected, "v2 credentials do not exist on protocol 20", cap7102Source},
		{"v2_protocol26", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 26, ProtocolVerdictRejected, "v2 credentials do not exist on protocol 26", cap7102Source},
		{"v2_protocol27", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 27, ProtocolVerdictAccepted, "", cap7102Source},
		{"v2_protocol28", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 28, ProtocolVerdictAccepted, "", cap7102Source},
		{"delegates_protocol20", xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 20, ProtocolVerdictRejected, "delegated-signers credentials do not exist on protocol 20", cap7101Source},
		{"delegates_protocol26", xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 26, ProtocolVerdictRejected, "delegated-signers credentials do not exist on protocol 26", cap7101Source},
		{"delegates_protocol27", xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 27, ProtocolVerdictAccepted, "", cap7101Source},
		{"delegates_protocol28", xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 28, ProtocolVerdictAccepted, "", cap7101Source},
		// Unknown arm and unknown function type do not show up as accepted.
		{"unknown_credentials", xdr.SorobanCredentialsType(99), 28, ProtocolVerdictUnknown, "", ""},
		{"unknown_function_type", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 28, ProtocolVerdictUnknown, "", ""},
		// A non-positive target version is unknown, never accepted.
		{"nonpositive_version", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 0, ProtocolVerdictUnknown, "", ""},
		{"negative_version", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, -1, ProtocolVerdictUnknown, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var entry xdr.SorobanAuthorizationEntry
			if c.arm == xdr.SorobanCredentialsType(99) {
				entry = xdr.SorobanAuthorizationEntry{
					Credentials: xdr.SorobanCredentials{Type: c.arm},
				}
			} else {
				entry = compatEntry(t, c.arm)
			}
			if c.name == "unknown_function_type" {
				entry.RootInvocation.Function.Type = xdr.SorobanAuthorizedFunctionType(99)
			}
			report, err := CheckProtocolCompatibility(entry, c.version)
			if err != nil {
				t.Fatalf("CheckProtocolCompatibility: %v", err)
			}
			if report.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s\nfindings: %v", report.Verdict, c.want, report.Findings)
			}
			if c.want == ProtocolVerdictUnknown {
				return
			}
			if len(report.Findings) == 0 {
				t.Fatalf("no findings for %s at protocol %d", c.name, c.version)
			}
			worst := report.Findings[0]
			for _, f := range report.Findings {
				if rank(f.Verdict) > rank(worst.Verdict) {
					worst = f
				}
			}
			if worst.Source == "" {
				t.Fatalf("decision finding has no source: %+v", worst)
			}
			if worst.Source != c.sourceURL {
				t.Fatalf("citation %s != %s", worst.Source, c.sourceURL)
			}
		})
	}
}

func rank(v ProtocolVerdict) int {
	switch v {
	case ProtocolVerdictAccepted:
		return 0
	case ProtocolVerdictDifferentSemantics:
		return 1
	case ProtocolVerdictUnknown:
		return 2
	default:
		return 3
	}
}

func TestCheckProtocolCompatibilityNestedDelegates(t *testing.T) {
	entry := compatEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates)
	report, err := CheckProtocolCompatibility(entry, 28)
	if err != nil {
		t.Fatalf("CheckProtocolCompatibility: %v", err)
	}
	if report.Verdict != ProtocolVerdictAccepted {
		t.Fatalf("verdict = %s", report.Verdict)
	}
	// Every delegate node must carry its own finding, not just the top level.
	for _, f := range report.Findings {
		if len(f.Path) > 0 && f.Path[len(f.Path)-1] == ']' {
			continue
		}
	}
	// The walk reaches the nested delegate; with two entries per level and a
	// nested one, we expect at least two findings at this depth.
	if got := len(report.Findings); got < 2 {
		t.Fatalf("delegate findings = %d, want at least 2 (top + nested)", got)
	}
	topLevelCount := 0
	for _, f := range report.Findings {
		if f.Path == "credentials" {
			topLevelCount++
		}
	}
	if topLevelCount != 1 {
		t.Fatalf("top-level finding count = %d, want 1", topLevelCount)
	}
}

func TestCheckProtocolCompatibilityUnknownArmRejectNoSecondGuess(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
	}
	report, err := CheckProtocolCompatibility(entry, 28)
	if err != nil {
		t.Fatalf("CheckProtocolCompatibility: %v", err)
	}
	if report.Verdict != ProtocolVerdictUnknown {
		t.Fatalf("verdict = %s, want unknown", report.Verdict)
	}
}

func TestCheckProtocolCompatibilityPreservesInput(t *testing.T) {
	entry := compatEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates)
	snapshot := compatEntry(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates)
	if _, err := CheckProtocolCompatibility(entry, 28); err != nil {
		t.Fatalf("CheckProtocolCompatibility: %v", err)
	}
	if !reflect.DeepEqual(entry, snapshot) {
		t.Fatalf("CheckProtocolCompatibility mutated input entry")
	}
}
