package soroauth

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVersionConstantIsNonEmpty asserts that the exported Version constant is
// not an empty string.
func TestVersionConstantIsNonEmpty(t *testing.T) {
	if Version == "" {
		t.Error("soroauth.Version is empty; it must be set to the current release tag")
	}
}

// TestVersionConstantMatchesLatestTag asserts that soroauth.Version matches
// the most recent git tag so the two cannot silently diverge. The test is
// skipped when git is unavailable or the working tree has no tags (e.g. a
// shallow clone in a dependency fetch), so it does not break unrelated
// consumers — it fires in the development and release workflows where the tag
// is authoritative.
func TestVersionConstantMatchesLatestTag(t *testing.T) {
	out, err := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()
	if err != nil {
		t.Skipf("skipping: git describe failed (%v); likely no tags in this checkout", err)
	}
	tag := strings.TrimSpace(string(out))
	if tag == "" {
		t.Skip("skipping: no git tag found")
	}
	if Version != tag {
		t.Errorf("soroauth.Version = %q but the latest git tag is %q; update soroauth.Version to match", Version, tag)
	}
}
