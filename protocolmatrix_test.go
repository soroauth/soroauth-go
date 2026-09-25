package soroauth

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// ExampleArmProtocolVersion shows checking an entry's arm against the
// protocol version it requires before relying on it against a possibly
// older network.
func ExampleArmProtocolVersion() {
	info := EntryInfo{CredentialType: CredentialTypeAddressV2}

	version, ok := ArmProtocolVersion[info.CredentialType]
	if !ok {
		fmt.Println("unknown arm")
		return
	}
	fmt.Printf("%s requires Protocol %d or later\n", info.CredentialType, version)
	// Output:
	// address_v2 requires Protocol 27 or later
}

// TestArmProtocolVersionMatchesTheCAPs pins ArmProtocolVersion to the exact
// values read from each CAP document's own preamble (see the doc comment on
// ArmProtocolVersion for the URLs), so a change here has to be a deliberate,
// sourced edit rather than a typo.
func TestArmProtocolVersionMatchesTheCAPs(t *testing.T) {
	want := map[string]int{
		CredentialTypeSourceAccount:        20,
		CredentialTypeAddress:              20,
		CredentialTypeAddressV2:            27,
		CredentialTypeAddressWithDelegates: 27,
	}

	if len(ArmProtocolVersion) != len(want) {
		t.Fatalf("ArmProtocolVersion has %d entries, want %d", len(ArmProtocolVersion), len(want))
	}
	for arm, version := range want {
		got, ok := ArmProtocolVersion[arm]
		if !ok {
			t.Errorf("ArmProtocolVersion is missing arm %q", arm)
			continue
		}
		if got != version {
			t.Errorf("ArmProtocolVersion[%q] = %d, want %d", arm, got, version)
		}
	}
}

// TestArmProtocolVersionCoversEveryKnownArm proves every credential type
// name Inspect can report (CredentialTypeSourceAccount, CredentialTypeAddress,
// CredentialTypeAddressV2, CredentialTypeAddressWithDelegates) has an entry,
// so a fifth arm added later without updating this matrix fails here instead
// of silently reporting nothing.
func TestArmProtocolVersionCoversEveryKnownArm(t *testing.T) {
	arms := []string{
		CredentialTypeSourceAccount,
		CredentialTypeAddress,
		CredentialTypeAddressV2,
		CredentialTypeAddressWithDelegates,
	}
	for _, arm := range arms {
		if _, ok := ArmProtocolVersion[arm]; !ok {
			t.Errorf("ArmProtocolVersion has no entry for arm %q", arm)
		}
	}
}

// readmeProtocolTableRow matches one data row of the README's "Protocol
// version support" table: the arm name in backticks, then "Protocol N".
var readmeProtocolTableRow = regexp.MustCompile("`([A-Z_0-9]+)` \\| Protocol (\\d+)")

// armNameByWireConstant maps the wire-format constant names the README
// table names (SOROBAN_CREDENTIALS_*) to the CredentialType* string this
// package's own API uses, since the two vocabularies differ deliberately
// (see inspect.go): the README documents the protocol wire type, while
// Inspect and ArmProtocolVersion key on the stable string Inspect reports.
var armNameByWireConstant = map[string]string{
	"SOROBAN_CREDENTIALS_SOURCE_ACCOUNT":         CredentialTypeSourceAccount,
	"SOROBAN_CREDENTIALS_ADDRESS":                CredentialTypeAddress,
	"SOROBAN_CREDENTIALS_ADDRESS_V2":             CredentialTypeAddressV2,
	"SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES": CredentialTypeAddressWithDelegates,
}

// TestArmProtocolVersionMatchesTheReadme is the regression fixture required
// by issue #92: it parses the "Protocol version support" table in README.md
// and fails if its numbers drift from ArmProtocolVersion, so a doc edit that
// gets a protocol number wrong (or a code change that forgets to update the
// README) fails the normal test suite instead of only being caught by
// review.
func TestArmProtocolVersionMatchesTheReadme(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	matches := readmeProtocolTableRow.FindAllStringSubmatch(string(readme), -1)
	if len(matches) != len(ArmProtocolVersion) {
		t.Fatalf("README.md's protocol version table has %d rows, but ArmProtocolVersion has %d entries — "+
			"keep the two in sync", len(matches), len(ArmProtocolVersion))
	}

	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		wireName, versionText := m[1], m[2]
		arm, ok := armNameByWireConstant[wireName]
		if !ok {
			t.Errorf("README.md names arm %q, which armNameByWireConstant (this file) does not recognize", wireName)
			continue
		}
		seen[arm] = true

		version, err := strconv.Atoi(versionText)
		if err != nil {
			t.Errorf("README.md's row for %q has a non-numeric protocol version %q", wireName, versionText)
			continue
		}

		want, ok := ArmProtocolVersion[arm]
		if !ok {
			t.Errorf("README.md documents arm %q, which ArmProtocolVersion has no entry for", arm)
			continue
		}
		if version != want {
			t.Errorf("README.md says %q is Protocol %d, but ArmProtocolVersion says %d", wireName, version, want)
		}
	}

	for arm := range ArmProtocolVersion {
		if !seen[arm] {
			t.Errorf("ArmProtocolVersion has arm %q, which README.md's protocol version table does not document", arm)
		}
	}
}
