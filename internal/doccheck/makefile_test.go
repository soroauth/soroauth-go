package doccheck

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	phonyDirective    = regexp.MustCompile(`(?m)^\.PHONY:\s*(.*)$`)
	helpTargetLine    = regexp.MustCompile(`@echo\s+"  make ([a-z0-9-]+)\b`)
	internalDirective = regexp.MustCompile(`(?m)^#\s*Internal targets:\s*(.*)$`)
)

// TestMakefilePhonyTargetsHaveHelpLines asserts that every public .PHONY target
// in Makefile has a corresponding help line in the help target, that every
// target documented in help exists in .PHONY, and that internal targets can be
// excluded by the "# Internal targets: ..." convention in the Makefile.
func TestMakefilePhonyTargetsHaveHelpLines(t *testing.T) {
	makefilePath := filepath.Join("..", "..", "Makefile")
	raw, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("reading Makefile: %v", err)
	}

	content := string(raw)

	// 1. Extract .PHONY targets
	var phonyTargets []string
	phonyMatches := phonyDirective.FindAllStringSubmatch(content, -1)
	for _, m := range phonyMatches {
		fields := strings.Fields(m[1])
		phonyTargets = append(phonyTargets, fields...)
	}
	if len(phonyTargets) == 0 {
		t.Fatal("no .PHONY targets found in Makefile")
	}

	// 2. Extract internal targets documented by convention
	internalMap := make(map[string]bool)
	internalMatches := internalDirective.FindAllStringSubmatch(content, -1)
	for _, m := range internalMatches {
		for _, target := range strings.Fields(m[1]) {
			internalMap[target] = true
		}
	}

	// 3. Extract help targets from the help: recipe
	helpTargets := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(content))
	inHelp := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "help:") {
			inHelp = true
			continue
		}
		if inHelp {
			// Recipes start with a tab
			if strings.HasPrefix(line, "\t") {
				if m := helpTargetLine.FindStringSubmatch(line); m != nil {
					helpTargets[m[1]] = true
				}
			} else if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
				// Reached end of help recipe
				inHelp = false
			}
		}
	}
	if len(helpTargets) == 0 {
		t.Fatal("no help targets found in help: recipe")
	}

	phonyMap := make(map[string]bool, len(phonyTargets))
	for _, pt := range phonyTargets {
		phonyMap[pt] = true
	}

	// 4. Verify every public .PHONY target has a help line
	var missingHelp []string
	for _, target := range phonyTargets {
		if internalMap[target] {
			continue
		}
		if !helpTargets[target] {
			missingHelp = append(missingHelp, target)
		}
	}
	if len(missingHelp) > 0 {
		sort.Strings(missingHelp)
		t.Errorf("public .PHONY targets missing from help: %v\n"+
			"Every public target must have a line in `make help`, or be listed under `# Internal targets:` in the Makefile.", missingHelp)
	}

	// 5. Verify every target in help actually exists in .PHONY
	var obsoleteHelp []string
	for target := range helpTargets {
		if !phonyMap[target] {
			obsoleteHelp = append(obsoleteHelp, target)
		}
	}
	if len(obsoleteHelp) > 0 {
		sort.Strings(obsoleteHelp)
		t.Errorf("targets documented in `help:` that are not .PHONY targets: %v", obsoleteHelp)
	}

	t.Logf("Makefile help check: %d phony targets, %d help targets, %d internal targets excluded",
		len(phonyTargets), len(helpTargets), len(internalMap))
}
