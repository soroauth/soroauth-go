package doccheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type runtimeBudget struct {
	BudgetSeconds int64             `json:"budget_seconds"`
	Included      []string          `json:"included"`
	Excluded      map[string]string `json:"excluded"`
}

func TestRuntimeBudgetClassifiesEveryWorkflow(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ci", "runtime-budget.json"))
	if err != nil {
		t.Fatalf("read runtime budget: %v", err)
	}
	var b runtimeBudget
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("parse runtime budget: %v", err)
	}
	if b.BudgetSeconds <= 0 {
		t.Fatal("budget_seconds must be positive")
	}
	classified := map[string]string{}
	for _, name := range b.Included {
		if _, ok := classified[name]; ok {
			t.Fatalf("%s classified twice", name)
		}
		classified[name] = "included"
	}
	for name, reason := range b.Excluded {
		if strings.TrimSpace(reason) == "" {
			t.Fatalf("%s excluded without reason", name)
		}
		if prev, ok := classified[name]; ok {
			t.Fatalf("%s classified as %s and excluded", name, prev)
		}
		classified[name] = "excluded"
	}

	entries, err := os.ReadDir(filepath.Join("..", "..", ".github", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yml") {
			continue
		}
		kind, ok := classified[name]
		if !ok {
			t.Fatalf("workflow %s is missing from testdata/ci/runtime-budget.json; classify it as included or explicitly excluded with a reason", name)
		}
		data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		if kind == "excluded" && hasPullRequestTrigger(data) && !hasPathFilter(data) && !isAdvisoryOrManualByName(name) {
			// Always-on PR workflows should be budgeted unless explicitly justified by policy.
			// This is a guardrail; names below are known always-on PR workflows.
			if name == "ci.yml" || name == "security.yml" || name == "spellcheck.yml" || name == "links.yml" {
				t.Fatalf("always-on PR workflow %s must not be excluded from runtime budget", name)
			}
		}
	}
	for name := range classified {
		if _, err := os.Stat(filepath.Join("..", "..", ".github", "workflows", name)); err != nil {
			t.Fatalf("runtime budget classifies %s but workflow file does not exist", name)
		}
	}
}

func hasPullRequestTrigger(data []byte) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return false
	}
	on := yamlMappingValue(doc.Content[0], "on")
	if on == nil {
		return false
	}
	if on.Kind == yaml.ScalarNode {
		return on.Value == "pull_request"
	}
	if on.Kind == yaml.SequenceNode {
		for _, n := range on.Content {
			if n.Value == "pull_request" {
				return true
			}
		}
	}
	if on.Kind == yaml.MappingNode {
		return yamlMappingValue(on, "pull_request") != nil
	}
	return false
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func hasPathFilter(data []byte) bool {
	// Conservative textual check: path-filtered PR workflows declare paths: under pull_request/push.
	return regexp.MustCompile(`(?m)^\s+paths:`).Match(data)
}

func isAdvisoryOrManualByName(name string) bool {
	switch name {
	case "cost-report.yml", "fuzz.yml", "e2e.yml", "reproducible.yml", "verify-release.yml", "release.yml", "release-python.yml", "release-jvm.yml", "ci-sdk-main.yml":
		return true
	default:
		return false
	}
}
