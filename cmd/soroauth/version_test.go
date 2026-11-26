package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	soroauth "github.com/soroauth/soroauth-go"
)

// TestVersionFlagReportsBuildMetadata drives --version through the dispatcher
// the way a user does, and asserts each field the flag promises. The values
// themselves come from the build, so this asserts shape and presence rather
// than a pinned version: a test that hard-coded v0.3.0 would fail on every
// release.
func TestVersionFlagReportsBuildMetadata(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		t.Run(arg, func(t *testing.T) {
			stdout, stderr, err := runCLI(t, arg)
			if err != nil {
				t.Fatalf("%s failed: %v (stderr: %s)", arg, err, stderr)
			}
			if stderr != "" {
				t.Errorf("%s wrote to stderr: %q", arg, stderr)
			}

			lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
			if len(lines) != 4 {
				t.Fatalf("%s printed %d lines, want 4:\n%s", arg, len(lines), stdout)
			}
			if !strings.HasPrefix(lines[0], "soroauth ") {
				t.Errorf("first line %q does not name the program", lines[0])
			}
			if !strings.HasPrefix(lines[1], "commit: ") || strings.TrimSpace(strings.TrimPrefix(lines[1], "commit: ")) == "" {
				t.Errorf("second line %q does not report a commit", lines[1])
			}
			if !strings.HasPrefix(lines[2], "built: ") || strings.TrimSpace(strings.TrimPrefix(lines[2], "built: ")) == "" {
				t.Errorf("third line %q does not report a build time", lines[2])
			}
			if want := "go: " + runtime.Version(); lines[3] != want {
				t.Errorf("fourth line = %q, want %q", lines[3], want)
			}
		})
	}
}

// TestVersionTextRendersInjectedMetadata proves the ldflags-injected values are
// the ones that reach the output. The release workflow writes main.version,
// main.commit and main.date; this is the Go side of that contract.
func TestVersionTextRendersInjectedMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, date
	defer func() { version, commit, date = originalVersion, originalCommit, originalDate }()

	version, commit, date = "v9.9.9", "abc1234", "2026-09-28T00:00:00Z"

	got := versionText()
	for _, want := range []string{"soroauth v9.9.9", "commit: abc1234", "built: 2026-09-28T00:00:00Z", "go: " + runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Errorf("versionText() = %q, which does not contain %q", got, want)
		}
	}
}

// TestVersionDefaultsAreSelfDescribing pins the no-ldflags defaults. The
// version default is soroauth.Version (the library constant) so a dev build
// reports the same version as the library rather than the opaque string "dev".
// commit and date remain "unknown" for a source build.
func TestVersionDefaultsAreSelfDescribing(t *testing.T) {
	if version != soroauth.Version {
		t.Errorf("default CLI version = %q, want library Version %q", version, soroauth.Version)
	}
	if commit != "unknown" {
		t.Errorf("default commit = %q, want %q", commit, "unknown")
	}
	if date != "unknown" {
		t.Errorf("default date = %q, want %q", date, "unknown")
	}
}

// TestCLIVersionMatchesLibraryVersion asserts the CLI's version and the
// library's Version constant cannot disagree. The ldflags-stamped value
// overrides the default at release time; a test that checks the default
// against the constant catches a release that updates one but not the other.
func TestCLIVersionMatchesLibraryVersion(t *testing.T) {
	if version != soroauth.Version {
		t.Errorf("CLI default version %q != library soroauth.Version %q; update soroauth.Version or the CLI default to match",
			version, soroauth.Version)
	}
}

// TestReleaseWorkflowSetsBuildMetadata is the drift guard for the acceptance
// criterion "release workflow sets them": the fields --version reports are only
// populated if the workflow passes them to -ldflags, and a workflow edit that
// drops one would otherwise be invisible until a user asked for a version.
func TestReleaseWorkflowSetsBuildMetadata(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	workflow := string(raw)
	for _, field := range []string{"-X main.version=", "-X main.commit=", "-X main.date="} {
		if !strings.Contains(workflow, field) {
			t.Errorf("%s does not pass %q to the linker, so --version would report the default", path, field)
		}
	}
}
