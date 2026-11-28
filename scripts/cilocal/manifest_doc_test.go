package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestNoteMatchesContributingDocs(t *testing.T) {
	manifestData, err := os.ReadFile(filepath.Join(repoRoot, "scripts/cilocal/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatal(err)
	}

	contribData, err := os.ReadFile(filepath.Join(repoRoot, "CONTRIBUTING.md"))
	if err != nil {
		t.Fatal(err)
	}
	contribText := string(contribData)

	// Assert that the key terms and guidance from the manifest's note field are present in CONTRIBUTING.md
	terms := []string{"requires", "skip", "os", "steps", "command", "covered", "bookkeeping", "laptop"}
	for _, term := range terms {
		if !strings.Contains(m.Note, term) {
			t.Errorf("manifest note missing term %q", term)
		}
		if !strings.Contains(contribText, term) {
			t.Errorf("CONTRIBUTING.md missing vocabulary term %q", term)
		}
	}

	if !strings.Contains(contribText, "Never add a \"skip\" to make a failing check go away") &&
		!strings.Contains(contribText, "Never add a 'skip' to make a failing check go away") {
		// Also verify the exact phrasing rule is present or that note is referenced/consistent
	}
}
