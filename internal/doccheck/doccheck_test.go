package doccheck

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRoot_FindsUndocumentedIdentifier proves the checker actually fails on
// an undocumented exported symbol, rather than always reporting a clean tree.
// It writes a throwaway package to a temp directory rather than the module
// itself, so nothing on disk is left undocumented on purpose.
func TestRoot_FindsUndocumentedIdentifier(t *testing.T) {
	dir := t.TempDir()

	const src = `// Package fixture is a deliberately incomplete package for doccheck's own
// test, proving the checker fails when it should.
package fixture

// Documented is fine.
const Documented = 1

const Undocumented = 2

// DocumentedFunc is fine.
func DocumentedFunc() {}

func UndocumentedFunc() {}

// DocumentedType is fine.
type DocumentedType struct{}

// Method is fine.
func (DocumentedType) Method() {}

func (DocumentedType) UndocumentedMethod() {}

type UndocumentedType struct{}

func unexported() {}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	violations, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}

	want := map[string]string{
		"Undocumented":                      "const",
		"UndocumentedFunc":                  "func",
		"UndocumentedType":                  "type",
		"DocumentedType.UndocumentedMethod": "method",
	}
	got := make(map[string]string, len(violations))
	for _, v := range violations {
		got[v.Name] = v.Kind
	}

	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("expected a %s violation for %s, got %q", kind, name, got[name])
		}
	}
	for _, documented := range []string{"Documented", "DocumentedFunc", "DocumentedType", "DocumentedType.Method"} {
		if _, found := got[documented]; found {
			t.Errorf("%s is documented and should not be reported", documented)
		}
	}
	if _, found := got["unexported"]; found {
		t.Error("unexported identifiers must never be reported")
	}
}

// TestRoot_EmptyDirIsNotAnError proves a directory with no Go source (for
// example one holding only fixtures) does not make the walk fail: doccheck
// has to tolerate the module's non-package directories without a caller
// having to special-case them.
func TestRoot_EmptyDirIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not go"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	violations, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %v", violations)
	}
}

// TestRoot_SkipsNestedModule proves a directory holding its own go.mod is
// never descended into: it is a separate module with its own CI job, and
// doccheck reporting on it would duplicate that job and could report false
// positives against a different module's import graph.
func TestRoot_SkipsNestedModule(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "go.mod"), []byte("module nested\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "nested.go"), []byte("package nested\n\nfunc Undocumented() {}\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	violations, err := Root(dir)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected the nested module to be skipped, got %v", violations)
	}
}

// TestRoot_RepoIsClean is the enforcement itself: every exported identifier
// under the module root (excluding the nested adapter module, which is
// checked by its own CI job) must carry a doc comment. This is what makes a
// regression fail the normal `go test ./...` run rather than only a local,
// optional check.
func TestRoot_RepoIsClean(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locating module root: %v", err)
	}

	violations, err := Root(root)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	for _, v := range violations {
		t.Errorf("%s", v)
	}
}

// moduleRoot walks up from the current package directory to the directory
// holding go.mod, since tests run with their package directory as the
// working directory rather than the module root.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
