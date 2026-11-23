package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// workflowDir is the repository's workflow directory, relative to this package.
const workflowDir = "../../.github/workflows"

// TestPathsFilteredWorkflowsIncludeThemselves enforces the rule that a
// workflow with a top-level `paths:` filter must list its own file.
//
// Why this is a test and not a convention: a `paths:`-filtered workflow
// produces no check row at all when it does not match — not a skipped one — so
// a change to a workflow that does not list itself cannot be validated by its
// own run, and nothing about that is visible on the pull request. #294 added a
// job to ci-adapters.yml and merged with that job never having executed once,
// because the filter did not name the file being edited.
//
// Every workflow complies today. This test is what keeps the next one honest.
func TestPathsFilteredWorkflowsIncludeThemselves(t *testing.T) {
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}

	// A scan that matched nothing would pass forever while enforcing nothing.
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		body := string(raw)
		if !regexp.MustCompile(`(?m)^\s+paths:`).MatchString(body) {
			continue
		}
		checked++
		if !strings.Contains(body, "workflows/"+name) {
			t.Errorf("%s has a paths: filter but does not list its own path.\n"+
				"Add `- '.github/workflows/%s'` to every paths: block in it, or an edit "+
				"to this workflow cannot run it and the change lands unvalidated.", name, name)
		}
	}

	if checked == 0 {
		t.Fatal("no paths-filtered workflow was examined; this test would pass vacuously")
	}
	t.Logf("%d paths-filtered workflows checked, all list their own path", checked)
}

// usesLine matches a step- or job-level `uses:` key, in either the plain
// `uses:` or list-item `- uses:` form, capturing the reference and anything
// after it on the line (the trailing comment, if any).
var usesLine = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(.*)$`)

// pinnedRef is a remote reference pinned to a full 40-character commit SHA.
var pinnedRef = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)

// dockerDigestRef is a docker:// reference pinned to an image digest, the
// container equivalent of a commit SHA.
var dockerDigestRef = regexp.MustCompile(`^docker://[^@\s]+@sha256:[0-9a-f]{64}$`)

// versionComment is the trailing `# vX[.Y.Z]` comment that keeps a SHA pin
// readable and lets a reviewer see which release the SHA claims to be.
var versionComment = regexp.MustCompile(`^#\s*v\d+(\.\d+)*\S*$`)

// checkUsesRef classifies one `uses:` value (everything after the key).
// It returns "" when the reference is acceptable, or the reason it is not.
//
// Local references (`./path`, including local reusable workflows under
// ./.github/workflows/) resolve to this repository's own checkout, so they
// cannot be retargeted by anyone else and carry no SHA. Every remote
// reference, whether an action or a reusable workflow, must name a full
// commit SHA followed by a version comment.
func checkUsesRef(value string) string {
	value = strings.TrimSpace(value)
	ref, comment := value, ""
	if i := strings.Index(value, "#"); i >= 0 {
		ref, comment = strings.TrimSpace(value[:i]), strings.TrimSpace(value[i:])
	}
	ref = strings.Trim(ref, `"'`)

	switch {
	case ref == "":
		return "empty uses: reference"
	case strings.HasPrefix(ref, "./"):
		return ""
	case strings.HasPrefix(ref, "docker://"):
		if !dockerDigestRef.MatchString(ref) {
			return "docker reference " + ref + " is not pinned to an @sha256: digest"
		}
		return ""
	case !strings.Contains(ref, "@"):
		return "reference " + ref + " names no version at all"
	case !pinnedRef.MatchString(ref):
		return "reference " + ref + " uses a mutable tag or branch, not a 40-character commit SHA"
	case comment == "":
		return "reference " + ref + " is SHA-pinned but has no trailing `# vX.Y.Z` version comment"
	case !versionComment.MatchString(comment):
		return "reference " + ref + " has trailing comment " + strconv.Quote(comment) + ", want `# vX.Y.Z`"
	}
	return ""
}

// TestCheckUsesRef proves the classifier both accepts what the policy allows
// and rejects what it forbids, so TestWorkflowActionsArePinnedBySHA cannot
// pass by a classifier that accepts everything.
func TestCheckUsesRef(t *testing.T) {
	const sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
	tests := []struct {
		name  string
		value string
		ok    bool
	}{
		{"sha with version comment", "actions/checkout@" + sha + " # v7", true},
		{"sha with full semver comment", "actions/upload-artifact@" + sha + " # v7.0.2", true},
		{"quoted sha with comment", `"actions/checkout@` + sha + `" # v7`, true},
		{"subdirectory action", "github/codeql-action/init@" + sha + " # v4", true},
		{"remote reusable workflow pinned", "org/repo/.github/workflows/build.yml@" + sha + " # v1.2.0", true},
		{"local action", "./integrations/action", true},
		{"local reusable workflow", "./.github/workflows/build.yml", true},
		{"docker digest", "docker://alpine@sha256:" + strings.Repeat("a", 64), true},

		{"major tag", "codecov/codecov-action@v7", false},
		{"semver tag", "actions/checkout@v4.2.1", false},
		{"branch", "actions/checkout@main", false},
		{"short sha", "actions/checkout@3d3c42e", false},
		{"uppercase sha", "actions/checkout@" + strings.ToUpper(sha) + " # v7", false},
		{"no ref", "actions/checkout", false},
		{"sha without comment", "actions/checkout@" + sha, false},
		{"sha with non-version comment", "actions/checkout@" + sha + " # pinned", false},
		{"remote reusable workflow on tag", "org/repo/.github/workflows/build.yml@v1", false},
		{"docker tag", "docker://alpine:3.20", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := checkUsesRef(tt.value)
			if tt.ok && reason != "" {
				t.Errorf("checkUsesRef(%q) rejected an allowed reference: %s", tt.value, reason)
			}
			if !tt.ok && reason == "" {
				t.Errorf("checkUsesRef(%q) accepted a reference the policy forbids", tt.value)
			}
		})
	}
}

// TestWorkflowActionsArePinnedBySHA enforces the repository's policy that
// every remote action or reusable workflow is referenced by a full commit SHA
// with a trailing version comment.
//
// Why this is a test and not a review convention: a tag or branch is mutable,
// so whoever controls the upstream repository decides what runs in this CI
// with this repository's token. The policy was kept by hand and two tag
// references had slipped through (#671); a test is what keeps it complete.
func TestWorkflowActionsArePinnedBySHA(t *testing.T) {
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			m := usesLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			checked++
			if reason := checkUsesRef(m[1]); reason != "" {
				t.Errorf(".github/workflows/%s:%d: %s\n"+
					"Pin it as `owner/repo@<40-char-sha> # vX.Y.Z`; resolve the SHA with "+
					"`gh api repos/<owner>/<repo>/commits/<tag> -q .sha`.", name, i+1, reason)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no uses: reference was examined; this test would pass vacuously")
	}
	t.Logf("%d uses: references checked across %s", checked, workflowDir)
}
