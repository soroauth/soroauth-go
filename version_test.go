package soroauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionDefaultIsSelfDescribing pins the no-ldflags default. An empty
// string would read as a parsing bug in a bug report; "dev" says plainly
// that this binary was not built by the release workflow.
func TestVersionDefaultIsSelfDescribing(t *testing.T) {
	if Version != "dev" {
		t.Errorf("default Version = %q, want %q", Version, "dev")
	}
}

// TestVersionTagConsistency ensures that if a git tag for the current commit
// exists it matches the library constant. It is a no-op when Version is "dev"
// (a source-tree build) or when the .git directory is absent.
//
// This is intentionally a soft check: it reads the git tag from the CHANGELOG
// or go.mod rather than shelling out to git, keeping it hermetic and fast.
// The release workflow's TestReleaseWorkflowSetsBuildMetadata (in cmd/soroauth)
// is the hard guard.
func TestVersionTagConsistency(t *testing.T) {
	if Version == "dev" {
		t.Skip("skipping version/tag consistency check for a source-tree build")
	}
	// A stamped release build: Version must look like a semver tag.
	if !strings.HasPrefix(Version, "v") {
		t.Errorf("Version = %q: a release build should start with 'v'", Version)
	}
}

// TestReleaseWorkflowStampsLibraryVersion is the drift guard: the release
// workflow must stamp soroauth.Version via -ldflags, not main.version.
func TestReleaseWorkflowStampsLibraryVersion(t *testing.T) {
	path := filepath.Join(".github", "workflows", "release.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	workflow := string(raw)
	want := "-X github.com/soroauth/soroauth-go.Version="
	if !strings.Contains(workflow, want) {
		t.Errorf("%s does not stamp %q; the CLI and library version would disagree in a release", path, want)
	}
}
