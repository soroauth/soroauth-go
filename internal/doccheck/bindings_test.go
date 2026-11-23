package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bindingPlatformHeading matches a structured platform support heading in a binding README.
var bindingPlatformHeading = regexp.MustCompile(`(?m)^## (?:Platform Support|Supported Platforms)\b`)

// TestBindingREADMEsStateSupportedPlatforms asserts that every directory under
// bindings/ contains a README.md with a dedicated platform support section.
//
// The native bindings load a shared library via dlopen and are Linux and macOS only.
// This test ensures every binding explicitly documents its supported operating systems,
// architectures, and runtime requirements in a structured section so consumers on other
// platforms do not discover non-support by failing at build time.
func TestBindingREADMEsStateSupportedPlatforms(t *testing.T) {
	bindingsDir := filepath.Join("..", "..", "bindings")
	entries, err := os.ReadDir(bindingsDir)
	if err != nil {
		t.Fatalf("reading bindings/: %v", err)
	}

	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		checked++
		readmePath := filepath.Join(bindingsDir, e.Name(), "README.md")
		raw, err := os.ReadFile(readmePath)
		if err != nil {
			t.Errorf("binding %s is missing README.md: %v", e.Name(), err)
			continue
		}

		if !bindingPlatformHeading.Match(raw) {
			t.Errorf("%s has no `## Platform Support` heading.\n"+
				"Every binding under bindings/ must declare its supported operating systems, "+
				"architectures and runtime versions under a structured `## Platform Support` heading.",
				readmePath)
			continue
		}

		// Ensure the section contains substantive content (operating system, architecture, runtime)
		content := string(raw)
		loc := bindingPlatformHeading.FindStringIndex(content)
		sub := content[loc[1]:]
		if nextHeading := regexp.MustCompile(`(?m)^## `).FindStringIndex(sub); nextHeading != nil {
			sub = sub[:nextHeading[0]]
		}
		if len(strings.TrimSpace(sub)) < 20 {
			t.Errorf("%s has an empty or trivial `## Platform Support` section", readmePath)
		}
	}

	if checked == 0 {
		t.Fatal("no binding directories found; test would pass vacuously")
	}
	t.Logf("%d binding READMEs checked for platform support statements", checked)
}

// TestBindingREADMEsFailsOnMissingSection proves that a binding directory with no
// platform support section in its README triggers a test failure.
func TestBindingREADMEsFailsOnMissingSection(t *testing.T) {
	dir := t.TempDir()
	bindingDir := filepath.Join(dir, "new-binding")
	if err := os.MkdirAll(bindingDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bindingDir, "README.md"), []byte("# New Binding\n\nSome prose."), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(bindingDir, "README.md"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bindingPlatformHeading.Match(raw) {
		t.Error("expected missing platform heading, but pattern matched")
	}
}
