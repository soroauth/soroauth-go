package conformance_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/soroauth/soroauth-go/conformance"
)

// casesPath is the path from this file to the committed cases file.
const casesPath = "../testdata/conformance/cases.json"

// vectorsDir is the path from this file to the golden vectors directory.
const vectorsDir = "../testdata/vectors"

// TestCasesFileLoads is the smallest possible gate: the file is valid JSON,
// its schema_version matches, every id is unique, every op is known, every
// row has either a vector or an input. Without this, a typo in the file
// would only be caught by the per-binding CI jobs that run after this.
func TestCasesFileLoads(t *testing.T) {
	f, err := conformance.Load(casesPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("cases.json has no cases")
	}
}

// TestCaseIDsAreValid pins the id format the output NDJSON treats as a key.
// A whitespace or a surprise character in an id would make the diff output
// unreadable.
func TestCaseIDsAreValid(t *testing.T) {
	f, err := conformance.Load(casesPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	re := regexp.MustCompile(`^[a-z0-9_.-]+$`)
	for _, c := range f.Cases {
		if !re.MatchString(c.ID) {
			t.Errorf("case id %q does not match [a-z0-9_.-]+", c.ID)
		}
	}
}

// TestGoOracleMatchesVectors is the correctness gate: for every happy-path
// case the Go runner produces must match the golden vector it references.
// This is what makes the Go runner the baseline every other binding diffs
// against — a disagreement here is the Go library drifting from the
// committed vectors, which is a bug in either and this suite surfaces
// before a per-binding CI job sees it.
func TestGoOracleMatchesVectors(t *testing.T) {
	f, err := conformance.Load(casesPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	results, err := conformance.Run(f, vectorsDir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	fails, err := conformance.Diff(f, vectorsDir, results)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, line := range fails {
		t.Errorf("%s", line)
	}
}

// TestErrorCasesAreRejected proves every case marked ok:false in cases.json
// is in fact rejected by the Go runner, with a kind in the allowed set.
// This is the "error cases are included" criterion from issue #545.
func TestErrorCasesAreRejected(t *testing.T) {
	f, err := conformance.Load(casesPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	results, err := conformance.Run(f, vectorsDir)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	countedErrorCases := 0
	for i, c := range f.Cases {
		if c.Expect == nil || c.Expect.OK == nil || *c.Expect.OK {
			continue
		}
		countedErrorCases++
		got := results[i]
		if got.OK {
			t.Errorf("case %s: want ok:false, got ok:true", c.ID)
			continue
		}
		if len(c.Expect.KindIn) == 0 {
			continue
		}
		ok := false
		for _, k := range c.Expect.KindIn {
			if got.Kind == k {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("case %s: kind %q is not in %v", c.ID, got.Kind, c.Expect.KindIn)
		}
	}
	if countedErrorCases == 0 {
		t.Error("cases.json has no error cases; issue #545 requires at least one")
	}
}

// TestCasesFileIsRelativeToRepoRoot sanity-checks that the shipped cases
// file lives at the path the README and the per-binding runners document.
// A rename that leaves the runners pointing at a missing file would be
// a silent regression without this.
func TestCasesFileIsRelativeToRepoRoot(t *testing.T) {
	// From this test's working directory (./conformance/), walk up to the
	// module root and confirm the file is where the README says.
	want := filepath.Join("..", "testdata", "conformance", "cases.json")
	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("expected cases.json at %q (relative to %s): %v",
			want, mustGetwd(t), err)
	}
	if info.IsDir() {
		t.Fatalf("cases.json path is a directory: %s", want)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}
