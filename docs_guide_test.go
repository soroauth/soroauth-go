package soroauth

import (
	"os"
	"path/filepath"
	"testing"
)

// guideSnippet names one fenced ```go block in a guide under docs/, in the
// order it appears, and the real source file its content must be extracted
// from. Blocks that are illustrative browser code (a ```js fence) are
// deliberately not registered: only blocks claiming to come from compiled Go
// sources in internal/readmesnippets are checked.
type guideSnippet struct {
	name       string
	sourceFile string
}

// guideDocs pairs each checked guide under docs/ with its snippets, in the
// order the blocks appear in the file. TestGuideSnippetsMatchTheirSource
// fails loudly on a count mismatch rather than silently skipping an
// unregistered block, so every checked guide and every Go block in it must be
// registered here.
var guideDocs = []struct {
	doc      string
	snippets []guideSnippet
}{
	{
		doc: "passkeys.md",
		snippets: []guideSnippet{
			{name: "passkey-parse", sourceFile: "passkey.go"},
			{name: "passkey-sign", sourceFile: "passkey.go"},
		},
	},
	{
		doc: "migrating.md",
		snippets: []guideSnippet{
			{name: "migrate-verify", sourceFile: "migrate.go"},
			{name: "migrate-inspect", sourceFile: "migrate.go"},
		},
	},
}

// TestGuideSnippetsMatchTheirSource does for the guides under docs/ what
// TestReadmeSnippetsMatchTheirSource does for README.md: every fenced ```go
// block that claims to come from internal/readmesnippets must be byte-identical
// (modulo the same normalisation) to its marked region, so a guide cannot
// drift from code that compiles.
func TestGuideSnippetsMatchTheirSource(t *testing.T) {
	for _, doc := range guideDocs {
		t.Run(doc.doc, func(t *testing.T) {
			path := filepath.Join("docs", doc.doc)
			guide, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}

			matches := goFencePattern.FindAllStringSubmatch(string(guide), -1)
			if len(matches) != len(doc.snippets) {
				t.Fatalf("%s has %d fenced ```go blocks, but guideDocs (this file) names %d — "+
					"keep the two in sync so every checked block is registered",
					path, len(matches), len(doc.snippets))
			}

			for i, snip := range doc.snippets {
				t.Run(snip.name, func(t *testing.T) {
					sourcePath := filepath.Join("internal", "readmesnippets", snip.sourceFile)
					source, err := os.ReadFile(sourcePath)
					if err != nil {
						t.Fatalf("reading %s: %v", sourcePath, err)
					}

					marked, err := extractMarkedRegion(string(source), snip.name)
					if err != nil {
						t.Fatalf("%s: %v", sourcePath, err)
					}

					want := normalizeSnippet(marked)
					got := normalizeSnippet(matches[i][1])
					if want != got {
						t.Errorf("%s's %q fenced ```go block has drifted from the marked region in %s.\n\n"+
							"--- %s (source of truth) ---\n%s\n\n--- %s ---\n%s",
							path, snip.name, sourcePath, sourcePath, want, path, got)
					}
				})
			}
		})
	}
}
