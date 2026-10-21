package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var goDirective = regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)$`)

// goVersionOf returns the `go` directive of a go.mod, relative to the
// repository root.
func goVersionOf(t *testing.T, modPath string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../..", modPath))
	if err != nil {
		t.Fatalf("reading %s: %v", modPath, err)
	}
	m := goDirective.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s has no `go` directive", modPath)
	}
	return string(m[1])
}

// TestAdapterModulesMatchTheRootGoFloor asserts that every module under
// adapters/ declares the same Go version as the root module.
//
// An adapter has a `replace` back to the repository root, so Go refuses to
// build it when the root requires a newer version than the adapter declares:
//
//	go: module ../.. requires go >= 1.26.3 (running go 1.26.0)
//
// That has now broken `ci / adapters` three separate times, each after a
// dependency raised the root floor and the adapters were left behind — once by
// a Dependabot bump, once by a feature branch adding a dependency, and once
// when only two of the three were updated. The version is in four files and
// nothing coupled them, so the test does the coupling.
func TestAdapterModulesMatchTheRootGoFloor(t *testing.T) {
	root := goVersionOf(t, "go.mod")

	entries, err := os.ReadDir("../../adapters")
	if err != nil {
		t.Fatalf("reading adapters/: %v", err)
	}

	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mod := filepath.Join("adapters", e.Name(), "go.mod")
		if _, err := os.Stat(filepath.Join("../..", mod)); err != nil {
			continue
		}
		checked++
		if got := goVersionOf(t, mod); got != root {
			t.Errorf("%s declares go %s but the root module requires go %s.\n"+
				"An adapter replaces the root, so Go refuses to build it: "+
				"`go: module ../.. requires go >= %s`.\n"+
				"Move every adapter with the root, in the same commit.",
				mod, got, root, root)
		}
	}

	// A scan that found no adapter would pass forever while enforcing nothing.
	if checked == 0 {
		t.Fatal("no adapter module was examined; this test would pass vacuously")
	}
	t.Logf("%d adapter modules checked against the root floor go %s", checked, root)
}

// TestDocumentedGoFloorMatchesGoMod asserts the README names the version
// go.mod actually requires, since that is what a consumer reads before
// depending on the library.
func TestDocumentedGoFloorMatchesGoMod(t *testing.T) {
	root := goVersionOf(t, "go.mod")

	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	if !strings.Contains(string(raw), "Go "+root) {
		t.Errorf("README.md does not mention `Go %s`, which is what go.mod requires.\n"+
			"A floor that is only true in go.mod is a floor nobody can act on.", root)
	}
}
