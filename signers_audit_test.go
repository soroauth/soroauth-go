package soroauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoKeyMaterialZeroingIsClaimed guards the audit in docs/signers.md.
//
// That document states plainly that this library zeroes nothing, and explains
// why for each place key material lives — most sharply for the CLI's
// --secret-env path, where os.Getenv returns an immutable Go string and there
// is no library-owned buffer to overwrite at all.
//
// A document like that rots the moment someone adds zeroing and does not
// update it, and it rots in the dangerous direction: a reader would be told
// less is done than is. So rather than asserting the absence of a feature,
// this test asserts the two stay in step — if zeroing appears, the audit has
// to be rewritten in the same change.
//
// This replaces a test that allocated its own buffer, zeroed it, and asserted
// it was zero. That version called no soroauth function and would have passed
// with the entire package deleted, while reading as evidence for a security
// property the library does not have.
func TestNoKeyMaterialZeroingIsClaimed(t *testing.T) {
	const auditDoc = "docs/signers.md"

	raw, err := os.ReadFile(auditDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", auditDoc, err)
	}
	const claim = "Nothing is zeroed today."
	if !strings.Contains(string(raw), claim) {
		t.Fatalf("%s no longer contains %q.\n"+
			"If zeroing was added, rewrite the audit to say what is now done and "+
			"update this test. If the sentence was merely reworded, restore it: "+
			"the audit's value is that it is exact.", auditDoc, claim)
	}

	// Look for the shape of a zeroing loop over a byte slice in the signing
	// path. This is a tripwire, not a proof: it catches the obvious form so
	// the audit and the code cannot drift silently apart.
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			rng, ok := n.(*ast.RangeStmt)
			if !ok || rng.Key == nil || rng.Body == nil || len(rng.Body.List) != 1 {
				return true
			}
			assign, ok := rng.Body.List[0].(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			lit, ok := assign.Rhs[0].(*ast.BasicLit)
			if !ok || lit.Value != "0" {
				return true
			}
			if _, ok := assign.Lhs[0].(*ast.IndexExpr); !ok {
				return true
			}
			t.Errorf("%s:%d looks like a zeroing loop, but %s says "+
				"%q.\nIf this zeroes key material, rewrite the audit to describe it. "+
				"If it zeroes something else, this tripwire needs narrowing.",
				name, fset.Position(rng.Pos()).Line, auditDoc, claim)
			return true
		})
	}

	// A scan that read nothing would pass forever while enforcing nothing.
	if scanned == 0 {
		t.Fatal("no package source file was scanned; this test would pass vacuously")
	}
	t.Logf("%d files scanned; audit and code agree that nothing is zeroed", scanned)
}
