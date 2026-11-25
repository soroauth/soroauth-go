package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateBudget(t *testing.T) {
	tests := []struct {
		name    string
		budget  Budget
		wantErr string
	}{
		{name: "ok", budget: Budget{BudgetSeconds: 60, Included: []string{"ci.yml"}, Excluded: map[string]string{"fuzz.yml": "scheduled"}}},
		{name: "no budget", budget: Budget{BudgetSeconds: 0, Included: []string{"ci.yml"}}, wantErr: "budget_seconds must be positive"},
		{name: "no included", budget: Budget{BudgetSeconds: 60}, wantErr: "included must not be empty"},
		{name: "empty included", budget: Budget{BudgetSeconds: 60, Included: []string{""}}, wantErr: "included contains an empty name"},
		{name: "dup", budget: Budget{BudgetSeconds: 60, Included: []string{"ci.yml", "ci.yml"}}, wantErr: "classified as both"},
		{name: "excluded no reason", budget: Budget{BudgetSeconds: 60, Included: []string{"ci.yml"}, Excluded: map[string]string{"e2e.yml": ""}}, wantErr: "has no reason"},
		{name: "both", budget: Budget{BudgetSeconds: 60, Included: []string{"ci.yml"}, Excluded: map[string]string{"ci.yml": "x"}}, wantErr: "classified as both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBudget(tt.budget)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err=%v want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateCriticalPathAndBudget(t *testing.T) {
	b := Budget{
		BudgetSeconds: 600,
		Included:      []string{"ci.yml", "security.yml"},
		Excluded:      map[string]string{"fuzz.yml": "scheduled", "ci-go.yml": "path filtered advisory"},
	}
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	runs := []run{
		{Workflow: "ci.yml", Job: "build", StartedAt: now, EndedAt: now.Add(500 * time.Second), Conclusion: "success"},
		{Workflow: "ci.yml", Job: "contracts", StartedAt: now, EndedAt: now.Add(200 * time.Second), Conclusion: "success"},
		{Workflow: "security.yml", Job: "codeql", StartedAt: now, EndedAt: now.Add(400 * time.Second), Conclusion: "success"},
		{Workflow: "fuzz.yml", Job: "fuzz", StartedAt: now, EndedAt: now.Add(9000 * time.Second), Conclusion: "success"},
	}
	rep, err := evaluate(b, runs)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if rep.CriticalPathSec != 500 {
		t.Fatalf("critical=%d want 500", rep.CriticalPathSec)
	}
	if !rep.WithinBudget {
		t.Fatal("expected within budget")
	}
	if len(rep.Excluded) != 2 {
		t.Fatalf("excluded=%v", rep.Excluded)
	}
}

func TestEvaluateFailsOverBudget(t *testing.T) {
	b := Budget{BudgetSeconds: 100, Included: []string{"ci.yml"}, Excluded: map[string]string{}}
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	rep, err := evaluate(b, []run{{Workflow: "ci.yml", Job: "build", StartedAt: now, EndedAt: now.Add(101 * time.Second), Conclusion: "success"}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if rep.WithinBudget {
		t.Fatal("expected over budget")
	}
}

func TestEvaluateRejectsUnclassifiedWorkflow(t *testing.T) {
	b := Budget{BudgetSeconds: 100, Included: []string{"ci.yml"}, Excluded: map[string]string{}}
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	_, err := evaluate(b, []run{
		{Workflow: "ci.yml", Job: "build", StartedAt: now, EndedAt: now.Add(10 * time.Second), Conclusion: "success"},
		{Workflow: "mystery.yml", Job: "x", StartedAt: now, EndedAt: now.Add(1 * time.Second), Conclusion: "success"},
	})
	if err == nil || !strings.Contains(err.Error(), "neither included nor explicitly excluded") {
		t.Fatalf("err=%v", err)
	}
}

func TestEvaluateRequiresIncludedRunData(t *testing.T) {
	b := Budget{BudgetSeconds: 100, Included: []string{"ci.yml", "security.yml"}, Excluded: map[string]string{}}
	now := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	_, err := evaluate(b, []run{{Workflow: "ci.yml", Job: "build", StartedAt: now, EndedAt: now.Add(10 * time.Second), Conclusion: "success"}})
	if err == nil || !strings.Contains(err.Error(), "has no run data") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunCLIValidationOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "budget.json")
	if err := os.WriteFile(path, []byte(`{"budget_seconds":60,"included":["ci.yml"],"excluded":{"fuzz.yml":"scheduled"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := runCLI([]string{"-budget", path}, &out, &errBuf); code != 0 {
		t.Fatalf("code=%d err=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "valid") {
		t.Fatalf("out=%q", out.String())
	}
}

func TestRunCLIBudgetExceeded(t *testing.T) {
	dir := t.TempDir()
	budgetPath := filepath.Join(dir, "budget.json")
	reportPath := filepath.Join(dir, "report.json")
	os.WriteFile(budgetPath, []byte(`{"budget_seconds":10,"included":["ci.yml"],"excluded":{}}`), 0o644)
	os.WriteFile(reportPath, []byte(`[{"workflow":"ci.yml","job":"build","started_at":"2026-11-25T00:00:00Z","completed_at":"2026-11-25T00:00:20Z","conclusion":"success"}]`), 0o644)
	var out, errBuf bytes.Buffer
	if code := runCLI([]string{"-budget", budgetPath, "-report", reportPath}, &out, &errBuf); code != 1 {
		t.Fatalf("code=%d err=%s out=%s", code, errBuf.String(), out.String())
	}
	if !strings.Contains(errBuf.String(), "exceeds budget") {
		t.Fatalf("err=%q", errBuf.String())
	}
}
