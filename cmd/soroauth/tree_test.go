package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/soroauth/soroauth-go"
)

// TestTreeASCII_RendersTheDelegatesVector proves the default rendering
// against a real delegates-arm golden vector rather than a hand-built entry,
// so the CLI is checked against the same fixture the library's own golden
// test uses.
func TestTreeASCII_RendersTheDelegatesVector(t *testing.T) {
	v := loadVector(t, "delegates_same_address_two_levels")

	stdout, stderr, err := runCLI(t, "tree", "--entry", v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("tree returned an error: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "├── ") && !strings.Contains(stdout, "└── ") {
		t.Errorf("expected ASCII tree connectors in output:\n%s", stdout)
	}
}

// TestTreeASCII_RepeatedAddressNotMerged proves the CLI surfaces the library's
// "print once per occurrence" rule for an address that recurs at two nesting
// levels — the exact case issue #90 calls out as the one that must not be
// confusing.
func TestTreeASCII_RepeatedAddressNotMerged(t *testing.T) {
	v := loadVector(t, "delegates_same_address_two_levels")

	stdout, _, err := runCLI(t, "tree", "--entry", v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("tree returned an error: %v", err)
	}

	var repeated string
	seen := map[string]int{}
	for _, d := range v.Delegates {
		seen[d.Address]++
	}
	for addr, count := range seen {
		if count > 1 {
			repeated = addr
		}
	}
	if repeated == "" {
		t.Skip("vector has no repeated delegate address; nothing to assert")
	}
	if strings.Count(stdout, repeated) < 2 {
		t.Errorf("expected %s to appear at least twice (once per occurrence), got output:\n%s", repeated, stdout)
	}
}

func TestTreeDOT_RendersAValidDigraph(t *testing.T) {
	v := loadVector(t, "delegates_same_address_two_levels")

	stdout, stderr, err := runCLI(t, "tree", "--entry", v.UnsignedEntryXDR, "--format", "dot")
	if err != nil {
		t.Fatalf("tree returned an error: %v (stderr: %s)", err, stderr)
	}
	if !strings.HasPrefix(stdout, "digraph delegates {") {
		t.Errorf("expected a digraph header, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "->") {
		t.Errorf("expected at least one edge, got:\n%s", stdout)
	}
}

func TestTreeJSON_MatchesInspectShape(t *testing.T) {
	v := loadVector(t, "delegates_same_address_two_levels")

	stdout, stderr, err := runCLI(t, "tree", "--entry", v.UnsignedEntryXDR, "--json")
	if err != nil {
		t.Fatalf("tree returned an error: %v (stderr: %s)", err, stderr)
	}

	var info soroauth.EntryInfo
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		t.Fatalf("decoding --json output: %v\noutput:\n%s", err, stdout)
	}
	if info.CredentialType != soroauth.CredentialTypeAddressWithDelegates {
		t.Errorf("credential_type = %q, want %q", info.CredentialType, soroauth.CredentialTypeAddressWithDelegates)
	}
	if len(info.Delegates) == 0 {
		t.Error("expected at least one delegate in the JSON report")
	}
}

// TestTree_MissingEntryFailsWithUsageError proves the failure path: no
// partial output reaches stdout, the error names what's missing, and the
// exit code is the usage-error code.
func TestTree_MissingEntryFailsWithUsageError(t *testing.T) {
	stdout, _, err := runCLI(t, "tree")
	if err == nil {
		t.Fatal("expected an error for a missing --entry")
	}
	if ExitCode(err) != ExitUsageError {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitUsageError)
	}
	if !strings.Contains(err.Error(), "--entry is required") {
		t.Errorf("error %q does not mention the missing --entry", err)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty on failure, got %q", stdout)
	}
}

// TestTree_JSONErrorStaysOnStdoutOnly proves that with --json, the error goes
// to stdout as JSON and nothing is written to stderr, and that the JSON
// object decodes and carries the error field.
func TestTree_JSONErrorStaysOnStdoutOnly(t *testing.T) {
	stdout, stderr, err := runCLI(t, "tree", "--entry", "not-valid-base64", "--json")
	if err == nil {
		t.Fatal("expected an error for an invalid --entry")
	}
	if stderr != "" {
		t.Errorf("stderr must stay empty when --json handles the error, got %q", stderr)
	}
	var out struct {
		Error string `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(stdout), &out); jsonErr != nil {
		t.Fatalf("decoding stdout as JSON: %v\nstdout: %s", jsonErr, stdout)
	}
	if out.Error == "" {
		t.Error("expected a non-empty error field")
	}
}

// TestTree_UnknownFormatIsUsageError proves an unrecognized --format value is
// rejected before any entry decoding happens, rather than silently falling
// back to ascii.
func TestTree_UnknownFormatIsUsageError(t *testing.T) {
	v := loadVector(t, "delegates_same_address_two_levels")
	stdout, _, err := runCLI(t, "tree", "--entry", v.UnsignedEntryXDR, "--format", "svg")
	if err == nil {
		t.Fatal("expected an error for an unknown --format")
	}
	if ExitCode(err) != ExitUsageError {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitUsageError)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty on failure, got %q", stdout)
	}
}

func TestTree_HelpFlag(t *testing.T) {
	_, stderr, _ := runCLI(t, "tree", "--help")
	if !strings.Contains(stderr, "soroauth tree") {
		t.Errorf("expected usage text on stderr, got:\n%s", stderr)
	}
}
