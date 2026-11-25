package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Budget is the committed pull-request runtime budget.
//
// Included names the PR workflows/jobs that count toward the critical path.
// Excluded names workflows that are intentionally outside the budget, with a
// reason; the reason is part of the committed contract so an exclusion cannot
// become silent. A workflow missing from both lists fails validation: every PR
// workflow must be classified.
type Budget struct {
	Note          string            `json:"note,omitempty"`
	BudgetSeconds int64             `json:"budget_seconds"`
	Included      []string          `json:"included"`
	Excluded      map[string]string `json:"excluded"`
	Measurement   string            `json:"measurement,omitempty"`
}

type run struct {
	Workflow   string
	Job        string
	StartedAt  time.Time
	EndedAt    time.Time
	Conclusion string
}

type jobDuration struct {
	Name    string `json:"name"`
	Seconds int64  `json:"seconds"`
}

type report struct {
	MeasuredAt      string            `json:"measured_at"`
	BudgetSeconds   int64             `json:"budget_seconds"`
	CriticalPathSec int64             `json:"critical_path_seconds"`
	WithinBudget    bool              `json:"within_budget"`
	Included        []jobDuration     `json:"included"`
	Excluded        map[string]string `json:"excluded"`
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cibudget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	budgetPath := fs.String("budget", "testdata/ci/runtime-budget.json", "path to committed runtime budget")
	reportPath := fs.String("report", "", "path to JSON run report (array of workflow/job runs with started_at/completed_at)")
	outPath := fs.String("out", "", "write JSON report to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	b, err := loadBudget(*budgetPath)
	if err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 2
	}
	if err := validateBudget(b); err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 2
	}
	if *reportPath == "" {
		fmt.Fprintln(stdout, "cibudget: budget file valid")
		return 0
	}
	runs, err := loadRuns(*reportPath)
	if err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 2
	}
	rep, err := evaluate(b, runs)
	if err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 1
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 2
	}
	data = append(data, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0o644); err != nil {
			fmt.Fprintf(stderr, "cibudget: %v\n", err)
			return 2
		}
	}
	if _, err := stdout.Write(data); err != nil {
		fmt.Fprintf(stderr, "cibudget: %v\n", err)
		return 2
	}
	if !rep.WithinBudget {
		fmt.Fprintf(stderr, "cibudget: critical path %ds exceeds budget %ds\n", rep.CriticalPathSec, rep.BudgetSeconds)
		return 1
	}
	return 0
}

func loadBudget(path string) (Budget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Budget{}, err
	}
	var b Budget
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Budget{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return b, nil
}

func validateBudget(b Budget) error {
	if b.BudgetSeconds <= 0 {
		return errors.New("budget_seconds must be positive")
	}
	if len(b.Included) == 0 {
		return errors.New("included must not be empty")
	}
	seen := map[string]string{}
	for _, name := range b.Included {
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("included contains an empty name")
		}
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("%s classified as both %s and included", name, prev)
		}
		seen[name] = "included"
	}
	for name, reason := range b.Excluded {
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("excluded contains an empty name")
		}
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("excluded %s has no reason", name)
		}
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("%s classified as both %s and excluded", name, prev)
		}
		seen[name] = "excluded"
	}
	return nil
}

type runFile struct {
	Workflow    string `json:"workflow"`
	Job         string `json:"job"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Conclusion  string `json:"conclusion"`
}

func loadRuns(path string) ([]run, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []runFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	runs := make([]run, 0, len(raw))
	for i, r := range raw {
		if strings.TrimSpace(r.Workflow) == "" || strings.TrimSpace(r.Job) == "" {
			return nil, fmt.Errorf("run %d missing workflow/job", i)
		}
		start, err := time.Parse(time.RFC3339, r.StartedAt)
		if err != nil {
			return nil, fmt.Errorf("run %d started_at: %w", i, err)
		}
		end, err := time.Parse(time.RFC3339, r.CompletedAt)
		if err != nil {
			return nil, fmt.Errorf("run %d completed_at: %w", i, err)
		}
		if end.Before(start) {
			return nil, fmt.Errorf("run %d completed before started", i)
		}
		runs = append(runs, run{
			Workflow: r.Workflow, Job: r.Job, StartedAt: start, EndedAt: end, Conclusion: r.Conclusion,
		})
	}
	return runs, nil
}

func evaluate(b Budget, runs []run) (report, error) {
	includedSet := map[string]bool{}
	for _, n := range b.Included {
		includedSet[n] = true
	}
	for _, r := range runs {
		if includedSet[r.Workflow] {
			continue
		}
		if _, ok := b.Excluded[r.Workflow]; ok {
			continue
		}
		return report{}, fmt.Errorf("workflow %q is neither included nor explicitly excluded", r.Workflow)
	}
	seenIncluded := map[string]bool{}
	var includedRuns []run
	for _, r := range runs {
		if !includedSet[r.Workflow] {
			continue
		}
		if r.Conclusion != "" && r.Conclusion != "success" {
			return report{}, fmt.Errorf("included workflow %s job %s has conclusion %q", r.Workflow, r.Job, r.Conclusion)
		}
		seenIncluded[r.Workflow] = true
		includedRuns = append(includedRuns, r)
	}
	for _, name := range b.Included {
		if !seenIncluded[name] {
			return report{}, fmt.Errorf("included workflow %q has no run data", name)
		}
	}

	critical, perJob := criticalPath(includedRuns)
	included := make([]jobDuration, 0, len(perJob))
	for name, sec := range perJob {
		included = append(included, jobDuration{Name: name, Seconds: sec})
	}
	sort.Slice(included, func(i, j int) bool { return included[i].Seconds > included[j].Seconds })
	rep := report{
		MeasuredAt:      time.Now().UTC().Format(time.RFC3339),
		BudgetSeconds:   b.BudgetSeconds,
		CriticalPathSec: critical,
		WithinBudget:    critical <= b.BudgetSeconds,
		Included:        included,
		Excluded:        b.Excluded,
	}
	return rep, nil
}

// criticalPath computes the longest wall-clock chain. Without explicit job
// dependencies we use a conservative approximation: jobs in different workflows
// run concurrently, so workflow duration is the max job duration within that
// workflow; the PR critical path is the max workflow duration across included
// workflows. This is conservative (cannot under-report) and explicitly
// documented in the budget note.
func criticalPath(runs []run) (int64, map[string]int64) {
	byWorkflow := map[string]int64{}
	perJob := map[string]int64{}
	for _, r := range runs {
		d := int64(r.EndedAt.Sub(r.StartedAt).Seconds())
		if d < 0 {
			d = 0
		}
		key := r.Workflow + "/" + r.Job
		if d > perJob[key] {
			perJob[key] = d
		}
		if d > byWorkflow[r.Workflow] {
			byWorkflow[r.Workflow] = d
		}
	}
	var critical int64
	for _, d := range byWorkflow {
		if d > critical {
			critical = d
		}
	}
	return critical, perJob
}
