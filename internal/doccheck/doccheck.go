// Package doccheck walks the module's first-party Go packages and reports
// exported identifiers that carry no doc comment.
//
// CLAUDE.md requires every exported identifier to explain, in its own doc
// comment, why it exists and which protocol rule it enforces. That rule only
// holds if something enforces it: this package is the enforcement, and
// doccheck_test.go at the repo root is what runs it in the normal suite.
//
// The check walks the AST directly rather than going through go/doc: go/doc
// merges a tightly packed const or var block (no blank line between entries)
// into a single doc.Value and only keeps that value's own leading comment,
// which drops individually documented entries like
//
//	const (
//		// A documents A.
//		A = iota
//		// B documents B.
//		B
//	)
//
// on the floor as false positives. The parser attaches each spec's own
// leading comment to that ast.ValueSpec.Doc regardless of blank-line
// separation, so reading Doc from the spec avoids the merge entirely.
package doccheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Violation names one exported identifier that has no doc comment.
type Violation struct {
	// Package is the directory the identifier was found in, relative to the
	// module root (e.g. "." for the root package, "cmd/soroauth").
	Package string
	// Kind classifies the identifier: "const", "var", "type", "func", or
	// "method".
	Kind string
	// Name is the identifier's name. A method is reported as
	// "Receiver.Method".
	Name string
	// Position is the file and line the declaration starts at, for a report
	// a contributor can jump to directly.
	Position string
}

// String renders a violation as a single line, in the same shape `go vet`
// and the compiler use, so an editor or terminal can jump straight to it.
func (v Violation) String() string {
	return fmt.Sprintf("%s: exported %s %s has no doc comment", v.Position, v.Kind, v.Name)
}

// skipDirNames are directories doccheck never descends into: they hold no
// first-party Go source, hold a nested module with its own doc-comment
// discipline enforced by its own CI job, or hold fixtures that are not meant
// to compile as part of this module's packages.
var skipDirNames = map[string]bool{
	".git":         true,
	"node_modules": true,
	"testdata":     true,
	"adapters":     true, // nested module; adapters/walletsdk has its own go.mod and its own CI job
	".github":      true,
	"e2e":          true, // build-tagged, and its contracts are Rust, not Go
	"docs":         true,
}

// Root walks every first-party package under dir and reports every exported
// const, var, type, func, and method (on an exported receiver type) that has
// no doc comment.
//
// It only descends into directories holding a go.mod belonging to this same
// module (or dir itself): a nested module such as adapters/walletsdk is
// skipped here because it is checked by its own CI job against its own
// module boundary, not this one.
func Root(dir string) ([]Violation, error) {
	var violations []Violation

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if path != dir && (skipDirNames[base] || strings.HasPrefix(base, ".")) {
			return filepath.SkipDir
		}
		if path != dir {
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
		}

		found, walkErr := checkDir(path, dir)
		if walkErr != nil {
			return walkErr
		}
		violations = append(violations, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("doccheck: walking %s: %w", dir, err)
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Package != violations[j].Package {
			return violations[i].Package < violations[j].Package
		}
		return violations[i].Name < violations[j].Name
	})
	return violations, nil
}

// checkDir inspects every non-test .go file directly in dir (parser.ParseDir
// does not recurse) and reports its exported identifiers with no doc
// comment. A directory with no .go files is skipped rather than reported as
// an error, since not every directory in a module holds importable package
// source.
func checkDir(dir, root string) ([]Violation, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("doccheck: reading %s: %w", dir, err)
	}

	rel, err := filepath.Rel(root, dir)
	if err != nil {
		rel = dir
	}

	fset := token.NewFileSet()
	var violations []Violation
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("doccheck: parsing %s: %w", filepath.Join(dir, name), err)
		}
		violations = append(violations, fromFile(rel, fset, file)...)
	}
	return violations, nil
}

// exportedReceiverTypes collects the names of every exported type declared
// in file, so a method's receiver can be checked against it: a method on an
// unexported type is not reachable through godoc even when its own name is
// capitalized, since nothing outside the package can name the type to call
// it directly.
func exportedReceiverTypes(file *ast.File) map[string]bool {
	types := make(map[string]bool)
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if ok && ast.IsExported(ts.Name.Name) {
				types[ts.Name.Name] = true
			}
		}
	}
	return types
}

// fromFile reports every exported, undocumented top-level identifier in one
// parsed file.
func fromFile(pkgLabel string, fset *token.FileSet, file *ast.File) []Violation {
	exportedTypes := exportedReceiverTypes(file)

	var out []Violation
	add := func(kind, name string, pos token.Pos) {
		out = append(out, Violation{
			Package:  pkgLabel,
			Kind:     kind,
			Name:     name,
			Position: position(fset, pos),
		})
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			kind := ""
			switch d.Tok {
			case token.CONST:
				kind = "const"
			case token.VAR:
				kind = "var"
			case token.TYPE:
				kind = "type"
			default:
				continue
			}
			// A spec's own leading comment wins when present (this is what
			// keeps HookPhase's per-entry comments recognized); otherwise
			// the block's own leading comment stands in for the whole
			// group, matching how godoc renders an undivided const or var
			// block and how the rest of this codebase documents one.
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					doc := s.Doc
					if doc == nil {
						doc = d.Doc
					}
					if doc != nil {
						continue
					}
					for _, ident := range s.Names {
						if ast.IsExported(ident.Name) {
							add(kind, ident.Name, ident.Pos())
						}
					}
				case *ast.TypeSpec:
					doc := s.Doc
					if doc == nil {
						doc = d.Doc
					}
					if doc == nil && ast.IsExported(s.Name.Name) {
						add(kind, s.Name.Name, s.Pos())
					}
				}
			}

		case *ast.FuncDecl:
			if d.Doc != nil {
				continue
			}
			if d.Recv == nil {
				if ast.IsExported(d.Name.Name) {
					add("func", d.Name.Name, d.Pos())
				}
				continue
			}
			recv := receiverTypeName(d.Recv)
			if exportedTypes[recv] && ast.IsExported(d.Name.Name) {
				add("method", recv+"."+d.Name.Name, d.Pos())
			}
		}
	}
	return out
}

// receiverTypeName extracts the bare type name from a method's receiver,
// stripping the pointer star and any generic type parameters.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.IndexListExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

func position(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}
