package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

// TestManifestAccountsForEveryWorkflow is the meta-check that keeps
// `make ci-local` from drifting away from CI: every workflow, job and step that
// cannot run as written must be classified, and nothing may be classified that
// no longer exists. It runs against the real workflows, so adding a job to a
// workflow without touching scripts/cilocal/manifest.json fails the build.
func TestManifestAccountsForEveryWorkflow(t *testing.T) {
	workflows, err := LoadWorkflows(filepath.Join(repoRoot, ".github/workflows"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(filepath.Join(repoRoot, "scripts/cilocal/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(workflows) == 0 {
		t.Fatal("no workflows were loaded, so the meta-check would pass vacuously")
	}
	for _, p := range Check(workflows, manifest) {
		t.Error(p)
	}
}

func TestTheTargetExistsAndIsDocumented(t *testing.T) {
	makefile := readFile(t, filepath.Join(repoRoot, "Makefile"))
	if !strings.Contains(makefile, "\nci-local:\n") {
		t.Error("the Makefile has no ci-local target")
	}
	if !strings.Contains(makefile, "run ./scripts/cilocal") {
		t.Error("the ci-local target does not run scripts/cilocal")
	}
	if !strings.Contains(makefile, "\nall: fmt vet test\n") {
		t.Error("plain `make` must stay fmt, vet and test: ci-local is the thorough target, not a replacement")
	}
	if !strings.Contains(readFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md")), "make ci-local") {
		t.Error("CONTRIBUTING.md does not document make ci-local")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func parse(t *testing.T, file, yaml string) Workflow {
	t.Helper()
	wf, err := ParseWorkflow(file, []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return wf
}

const sampleWorkflow = `
name: sample
on: push
env:
  WORKFLOW_LEVEL: wf
jobs:
  build:
    name: build and test
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: sub
    env:
      JOB_LEVEL: job
    steps:
      - uses: actions/checkout@v7
      - name: first
        run: echo first
        env:
          STEP_LEVEL: step
      - run: echo unnamed
        working-directory: other
        shell: bash
      - name: gated
        if: failure()
        run: echo gated
      - uses: some/action@v1
  deploy:
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    steps:
      - run: echo deploy
`

func TestParseWorkflowFoldsInDefaultsAndKeepsFileOrder(t *testing.T) {
	wf := parse(t, "sample.yml", sampleWorkflow)

	if len(wf.Jobs) != 2 || wf.Jobs[0].ID != "build" || wf.Jobs[1].ID != "deploy" {
		t.Fatalf("jobs = %+v, want build then deploy in file order", wf.Jobs)
	}
	build := wf.Jobs[0]
	if build.Key() != "sample.yml/build" || build.Name != "build and test" {
		t.Errorf("key/name = %q/%q", build.Key(), build.Name)
	}
	if wf.Jobs[1].Name != "deploy" || wf.Jobs[1].If == "" {
		t.Errorf("an unnamed job falls back to its id and keeps its if: %+v", wf.Jobs[1])
	}
	if got := len(build.Steps); got != 5 {
		t.Fatalf("got %d steps, want 5 (checkout, first, unnamed, gated, action)", got)
	}

	first := build.Steps[1]
	if first.Dir != "sub" || first.Shell != "" {
		t.Errorf("first: dir=%q shell=%q, want the job default directory and no shell", first.Dir, first.Shell)
	}
	for k, want := range map[string]string{"WORKFLOW_LEVEL": "wf", "JOB_LEVEL": "job", "STEP_LEVEL": "step"} {
		if first.Env[k] != want {
			t.Errorf("env %s = %q, want %q", k, first.Env[k], want)
		}
	}

	unnamed := build.Steps[2]
	if unnamed.Name != "step 3" || unnamed.Dir != "other" || unnamed.Shell != "bash" {
		t.Errorf("unnamed step = %+v", unnamed)
	}
	if !build.Steps[3].needsClassification() {
		t.Error("a step with an if: condition cannot be run unconditionally and must be classified")
	}
	if first.needsClassification() {
		t.Error("a plain step must run as written")
	}
	action := build.Steps[4]
	if action.Run != "" || action.Action() != "some/action" || action.Name != "some/action@v1" {
		t.Errorf("action step = %+v", action)
	}
}

func TestExpressionsNeedClassification(t *testing.T) {
	for name, step := range map[string]Step{
		"in the script":  {Run: "echo ${{ matrix.x }}"},
		"in the dir":     {Run: "true", Dir: "${{ matrix.d }}"},
		"in an env var":  {Run: "true", Env: map[string]string{"A": "${{ secrets.A }}"}},
		"in the shell":   {Run: "true", Shell: "${{ matrix.s }}"},
		"an if: on step": {Run: "true", If: "always()"},
	} {
		if !step.needsClassification() {
			t.Errorf("%s: want the step to need classification", name)
		}
	}
}

func baseManifest() Manifest {
	return Manifest{
		Workflows: []string{"sample.yml"},
		Plumbing:  []string{"actions/checkout"},
		Jobs: map[string]JobSpec{
			"sample.yml/build": {Steps: map[string]StepSpec{
				"gated":          {Skip: "only runs on failure"},
				"some/action@v1": {Skip: "an action"},
			}},
			"sample.yml/deploy": {Skip: "publishes"},
		},
	}
}

func problemsContain(problems []string, want string) bool {
	for _, p := range problems {
		if strings.Contains(p, want) {
			return true
		}
	}
	return false
}

func TestCheckAcceptsAFullyClassifiedWorkflow(t *testing.T) {
	wf := parse(t, "sample.yml", sampleWorkflow)
	if problems := Check([]Workflow{wf}, baseManifest()); len(problems) > 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
}

func TestCheckFailsWhenCIGainsSomethingTheManifestLacks(t *testing.T) {
	wf := parse(t, "sample.yml", sampleWorkflow)

	tests := []struct {
		name   string
		change func(*Manifest)
		extra  string // a second workflow appended to the parsed set
		want   string
	}{
		{
			name:   "a new workflow file",
			change: func(*Manifest) {},
			extra:  "name: new\non: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: true\n",
			want:   "workflow new.yml is not in the manifest",
		},
		{
			name:   "a new job",
			change: func(m *Manifest) { delete(m.Jobs, "sample.yml/deploy") },
			want:   "job sample.yml/deploy is not classified",
		},
		{
			name:   "a step that cannot run as written",
			change: func(m *Manifest) { delete(m.Jobs["sample.yml/build"].Steps, "gated") },
			want:   `step "gated" cannot run as written`,
		},
		{
			name:   "an action that is not plumbing",
			change: func(m *Manifest) { delete(m.Jobs["sample.yml/build"].Steps, "some/action@v1") },
			want:   "uses the action some/action",
		},
		{
			name: "a conditional job that is not skipped",
			change: func(m *Manifest) {
				m.Jobs["sample.yml/deploy"] = JobSpec{Requires: []string{"go"}}
			},
			want: "has an if: condition",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := baseManifest()
			tt.change(&m)
			workflows := []Workflow{wf}
			if tt.extra != "" {
				workflows = append(workflows, parse(t, "new.yml", tt.extra))
			}
			problems := Check(workflows, m)
			if !problemsContain(problems, tt.want) {
				t.Fatalf("want a problem containing %q, got %v", tt.want, problems)
			}
		})
	}
}

func TestCheckFailsOnStaleAndMalformedEntries(t *testing.T) {
	wf := parse(t, "sample.yml", sampleWorkflow)

	tests := []struct {
		name   string
		change func(*Manifest)
		want   string
	}{
		{"a job that no longer exists", func(m *Manifest) { m.Jobs["sample.yml/gone"] = JobSpec{Skip: "x"} }, "no such job exists"},
		{"a workflow that no longer exists", func(m *Manifest) { m.Workflows = append(m.Workflows, "gone.yml") }, "has no such file"},
		{"a workflow listed twice", func(m *Manifest) { m.Workflows = append(m.Workflows, "sample.yml") }, "listed twice"},
		{"a step that no longer exists", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["ghost"] = StepSpec{Skip: "x"}
		}, `step "ghost", which does not exist`},
		{"a step with no classification", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["gated"] = StepSpec{}
		}, "needs exactly one of"},
		{"a step with two classifications", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["gated"] = StepSpec{Skip: "a", Bookkeeping: "b"}
		}, "needs exactly one of"},
		{"a command without a reason", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["gated"] = StepSpec{Command: "true"}
		}, "does not say why"},
		{"covered by a step with no command", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["gated"] = StepSpec{Covered: "some/action@v1"}
		}, "must be a step of this job with a \"command\""},
		{"covered by itself", func(m *Manifest) {
			m.Jobs["sample.yml/build"].Steps["gated"] = StepSpec{Covered: "gated"}
		}, "cannot be covered by itself"},
		{"a skipped job that also lists steps", func(m *Manifest) {
			m.Jobs["sample.yml/deploy"] = JobSpec{Skip: "x", Requires: []string{"go"}}
		}, "must not also list requires or steps"},
		{"a versioned plumbing entry", func(m *Manifest) { m.Plumbing = append(m.Plumbing, "actions/cache@v4") }, "without a version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := baseManifest()
			// The maps are shared with baseManifest's literals only within one
			// call, so mutating them here cannot leak into another subtest.
			tt.change(&m)
			if problems := Check([]Workflow{wf}, m); !problemsContain(problems, tt.want) {
				t.Fatalf("want a problem containing %q, got %v", tt.want, problems)
			}
		})
	}
}

func TestCheckRejectsDuplicateStepNames(t *testing.T) {
	wf := parse(t, "dup.yml", `
on: push
jobs:
  j:
    runs-on: x
    steps:
      - name: same
        run: echo one
      - name: same
        run: echo two
`)
	m := Manifest{Workflows: []string{"dup.yml"}, Jobs: map[string]JobSpec{"dup.yml/j": {}}}
	if problems := Check([]Workflow{wf}, m); !problemsContain(problems, `step name "same" is used more than once`) {
		t.Fatalf("got %v", problems)
	}
}

func lookupOnly(tools ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, t := range tools {
			if t == name {
				return "/bin/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestBuildPlanOrdersByManifestAndReportsEverySkip(t *testing.T) {
	a := parse(t, "a.yml", "on: push\njobs:\n  one:\n    runs-on: x\n    steps:\n      - run: echo a1\n")
	b := parse(t, "b.yml", `
on: push
jobs:
  needs-tool:
    runs-on: x
    steps:
      - run: echo b1
  linux-only:
    runs-on: x
    steps:
      - run: echo b2
  mixed:
    runs-on: x
    steps:
      - uses: actions/checkout@v7
      - name: plain
        run: echo plain
      - name: stand in
        run: echo ${{ matrix.x }}
      - name: other
        run: echo other
      - name: mine
        run: echo mine
      - name: noise
        run: echo noise
`)
	m := Manifest{
		// b.yml first: the plan follows the manifest, not the file names.
		Workflows: []string{"b.yml", "a.yml"},
		Plumbing:  []string{"actions/checkout"},
		Jobs: map[string]JobSpec{
			"a.yml/one":        {},
			"b.yml/needs-tool": {Requires: []string{"go", "docker"}},
			"b.yml/linux-only": {OS: []string{"linux"}},
			"b.yml/mixed": {Steps: map[string]StepSpec{
				"stand in": {Command: "echo local", Why: "no matrix locally"},
				"other":    {Covered: "stand in"},
				"mine":     {Skip: "needs a secret"},
				"noise":    {Bookkeeping: "job summary"},
			}},
		},
	}

	old := hostOS
	hostOS = "windows"
	defer func() { hostOS = old }()

	plan := BuildPlan([]Workflow{a, b}, m, "", lookupOnly("go"))
	var keys []string
	for _, pj := range plan {
		keys = append(keys, pj.Job.Key())
	}
	if got := strings.Join(keys, ","); got != "b.yml/needs-tool,b.yml/linux-only,b.yml/mixed,a.yml/one" {
		t.Fatalf("plan order = %s", got)
	}

	if plan[0].Skip != "missing docker on PATH" {
		t.Errorf("a missing tool must be named in the skip reason, got %q", plan[0].Skip)
	}
	if !strings.Contains(plan[1].Skip, "linux only") || !strings.Contains(plan[1].Skip, "windows") {
		t.Errorf("an OS-limited job must say so, got %q", plan[1].Skip)
	}

	mixed := plan[2]
	if mixed.Skip != "" || len(mixed.Steps) != 5 {
		t.Fatalf("mixed: skip=%q steps=%d, want a runnable job with 5 steps (plumbing dropped)", mixed.Skip, len(mixed.Steps))
	}
	byName := map[string]PlannedStep{}
	for _, ps := range mixed.Steps {
		byName[ps.Step.Name] = ps
	}
	if byName["plain"].Command != "echo plain" {
		t.Errorf("an unlisted step runs exactly as written, got %q", byName["plain"].Command)
	}
	if ps := byName["stand in"]; ps.Command != "echo local" || ps.Note == "" {
		t.Errorf("stand-in = %+v", ps)
	}
	if ps := byName["other"]; ps.Command != "" || ps.Covered != "stand in" {
		t.Errorf("covered = %+v", ps)
	}
	if ps := byName["mine"]; ps.Command != "" || ps.Skip == "" {
		t.Errorf("skip = %+v", ps)
	}
	if ps := byName["noise"]; ps.Command != "" || ps.Book == "" {
		t.Errorf("bookkeeping = %+v", ps)
	}

	only := BuildPlan([]Workflow{a, b}, m, "a.yml", lookupOnly("go"))
	if len(only) != 1 || only[0].Job.Key() != "a.yml/one" {
		t.Errorf("-only a.yml kept %d jobs", len(only))
	}
}

func TestWindowsBashLookupPrefersGitBashOverTheWSLLauncher(t *testing.T) {
	// Built with filepath.Join so the test means the same on every host; the
	// lookup itself only ever runs on Windows.
	programFiles := filepath.Join("C:", "Program Files")
	env := map[string]string{"ProgramFiles": programFiles, "LocalAppData": filepath.Join("C:", "Users", "u", "AppData", "Local")}
	got := gitBashCandidates(filepath.Join(programFiles, "Git", "cmd", "git.exe"), func(k string) string { return env[k] })

	if len(got) == 0 || !strings.HasSuffix(filepath.ToSlash(got[0]), "/bin/bash.exe") || !strings.Contains(filepath.ToSlash(got[0]), "Git") {
		t.Fatalf("the bash beside git must be tried first, got %v", got)
	}
	joined := strings.Join(got, "|")
	for _, want := range []string{`Program Files`, `Programs`} {
		if !strings.Contains(joined, want) {
			t.Errorf("candidates %v lack the %s install location", got, want)
		}
	}
	if len(gitBashCandidates("", func(string) string { return "" })) != 0 {
		t.Error("with no git and no install directories there is nothing to try")
	}

	if !isWSLLauncher(`C:\Windows\System32\bash.exe`) || !isWSLLauncher(`c:\windows\system32\BASH.EXE`) {
		t.Error("System32's bash.exe is the WSL launcher and must never be used")
	}
	if isWSLLauncher(`C:\Program Files\Git\bin\bash.exe`) {
		t.Error("Git Bash is not the WSL launcher")
	}
}

func requireBash(t *testing.T) string {
	t.Helper()
	bash, err := findBash()
	if err != nil {
		t.Skipf("no usable bash: %v", err)
	}
	return bash
}

func runPlan(t *testing.T, workflow string, m Manifest, failFast bool) ([]JobResult, string) {
	t.Helper()
	bash := requireBash(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	wf := parse(t, "w.yml", workflow)
	plan := BuildPlan([]Workflow{wf}, m, "", lookupOnly("bash"))
	var out bytes.Buffer
	results := Execute(plan, executor{root: root, bash: bash, failFast: failFast, out: &out})
	return results, out.String()
}

func TestExecuteStopsAJobAtItsFirstFailureButRunsTheNextJob(t *testing.T) {
	results, out := runPlan(t, `
on: push
jobs:
  broken:
    runs-on: x
    steps:
      - name: ok
        run: echo ran-ok
      - name: bad
        run: exit 3
      - name: never
        run: echo should-not-run
  fine:
    runs-on: x
    steps:
      - run: echo ran-fine
`, Manifest{
		Workflows: []string{"w.yml"},
		Jobs:      map[string]JobSpec{"w.yml/broken": {}, "w.yml/fine": {}},
	}, false)

	if results[0].Status != Failed || results[0].FailedStep != "bad" {
		t.Errorf("broken = %+v, want it to fail at step bad", results[0])
	}
	if results[1].Status != Passed {
		t.Errorf("fine = %+v, want PASS: a failing job must not hide the next one", results[1])
	}
	if strings.Contains(out, "should-not-run") {
		t.Error("a step after the failing one ran, which CI would not do")
	}
	if !strings.Contains(out, "ran-ok") || !strings.Contains(out, "ran-fine") {
		t.Errorf("output missing the steps that should run:\n%s", out)
	}
}

func TestExecuteFailFastSkipsLaterJobsWithAReason(t *testing.T) {
	results, _ := runPlan(t, `
on: push
jobs:
  broken:
    runs-on: x
    steps:
      - run: exit 1
  later:
    runs-on: x
    steps:
      - run: echo later
`, Manifest{
		Workflows: []string{"w.yml"},
		Jobs:      map[string]JobSpec{"w.yml/broken": {}, "w.yml/later": {}},
	}, true)

	if results[1].Status != Skipped || !strings.Contains(results[1].Reason, "-fail-fast") {
		t.Errorf("later = %+v, want a skip that says why", results[1])
	}
}

func TestExecuteUsesTheWorkflowsShellDirectoryAndEnvironment(t *testing.T) {
	results, out := runPlan(t, `
on: push
env:
  FROM_WORKFLOW: wf-value
jobs:
  j:
    runs-on: x
    defaults:
      run:
        working-directory: sub
    steps:
      - name: env and dir
        run: |
          echo "env=$FROM_WORKFLOW ci=$CI"
          echo "dir=$(basename "$PWD")"
      - name: pipefail is on for an explicit bash shell
        shell: bash
        run: |
          false | cat
          echo "pipefail-not-honoured"
`, Manifest{Workflows: []string{"w.yml"}, Jobs: map[string]JobSpec{"w.yml/j": {}}}, false)

	if !strings.Contains(out, "env=wf-value ci=true") {
		t.Errorf("the workflow env and CI=true must reach the step:\n%s", out)
	}
	if !strings.Contains(out, "dir=sub") {
		t.Errorf("the step must run in its working directory:\n%s", out)
	}
	if results[0].Status != Failed || strings.Contains(out, "pipefail-not-honoured") {
		t.Errorf("`shell: bash` means -o pipefail, so the piped failure must stop the step: %+v", results[0])
	}
}

func TestExecuteCarriesGithubEnvAndPathToLaterSteps(t *testing.T) {
	results, out := runPlan(t, `
on: push
jobs:
  j:
    runs-on: x
    steps:
      - name: export
        run: |
          mkdir -p "$PWD/bin"
          printf '#!/bin/sh\necho from-tool\n' > "$PWD/bin/mytool"
          chmod +x "$PWD/bin/mytool"
          echo "$PWD/bin" >> "$GITHUB_PATH"
          echo "FROM_ENV_FILE=carried" >> "$GITHUB_ENV"
      - name: use
        run: |
          echo "env=$FROM_ENV_FILE"
          mytool
`, Manifest{Workflows: []string{"w.yml"}, Jobs: map[string]JobSpec{"w.yml/j": {}}}, false)

	if results[0].Status != Passed {
		t.Fatalf("result = %+v\n%s", results[0], out)
	}
	if !strings.Contains(out, "env=carried") || !strings.Contains(out, "from-tool") {
		t.Errorf("$GITHUB_ENV and $GITHUB_PATH must reach later steps:\n%s", out)
	}
}

func TestExecuteRejectsAShellItCannotRun(t *testing.T) {
	results, out := runPlan(t, `
on: push
jobs:
  j:
    runs-on: x
    steps:
      - name: powershell step
        shell: pwsh
        run: Write-Host hi
`, Manifest{Workflows: []string{"w.yml"}, Jobs: map[string]JobSpec{"w.yml/j": {}}}, false)

	if results[0].Status != Failed || !strings.Contains(out, "not supported") {
		t.Errorf("an unsupported shell must fail loudly, not pass: %+v\n%s", results[0], out)
	}
}

func TestDryRunPrintsCommandsAndRunsNothing(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "ran")
	wf := parse(t, "w.yml", "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: touch "+filepath.ToSlash(marker)+"\n")
	plan := BuildPlan([]Workflow{wf}, Manifest{Workflows: []string{"w.yml"}, Jobs: map[string]JobSpec{"w.yml/j": {}}}, "", lookupOnly())

	var out bytes.Buffer
	results := Execute(plan, executor{root: root, dryRun: true, out: &out})
	if results[0].Status != Passed || !strings.Contains(out.String(), "$ touch") {
		t.Errorf("dry run output:\n%s", out.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a dry run executed the command")
	}
}

func TestSummarizeNeverPassesASkipSilently(t *testing.T) {
	job := func(id string) Job { return Job{Workflow: "w.yml", ID: id} }
	passed := JobResult{Job: job("a"), Status: Passed}
	failed := JobResult{Job: job("b"), Status: Failed, Reason: `step "x" failed`}
	skipped := JobResult{Job: job("c"), Status: Skipped, Reason: "missing docker on PATH"}
	stepSkip := JobResult{Job: job("d"), Status: Passed, SkipSteps: []string{"analyze (hosted only)"}}
	bookkeeping := JobResult{Job: job("e"), Status: Passed, Bookkeeping: 2, Covered: 1}

	tests := []struct {
		name    string
		results []JobResult
		strict  bool
		want    int
		inText  []string
	}{
		{"all passed", []JobResult{passed, bookkeeping}, true, 0, []string{"OK: everything CI runs passed locally"}},
		{"a failure fails", []JobResult{passed, failed}, false, 1, []string{"FAIL", `step "x" failed`}},
		{"a skipped job is reported with its reason", []JobResult{passed, skipped}, false, 0, []string{"missing docker on PATH", "did NOT run"}},
		{"a skipped job fails under -strict", []JobResult{passed, skipped}, true, 1, []string{"-strict and something was skipped"}},
		{"a skipped step is listed and fails under -strict", []JobResult{stepSkip}, true, 1, []string{"skipped step: analyze (hosted only)"}},
		{"bookkeeping and covered steps are not skips", []JobResult{bookkeeping}, true, 0, []string{"2 CI bookkeeping", "1 covered"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if got := Summarize(&out, tt.results, tt.strict, false); got != tt.want {
				t.Errorf("exit = %d, want %d\n%s", got, tt.want, out.String())
			}
			for _, s := range tt.inText {
				if !strings.Contains(out.String(), s) {
					t.Errorf("summary lacks %q:\n%s", s, out.String())
				}
			}
		})
	}
}

func writeTree(t *testing.T, workflow, manifest string) options {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "w.yml"), []byte(workflow), 0o600); err != nil {
		t.Fatal(err)
	}
	mp := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mp, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return options{workflowDir: dir, manifest: mp}
}

func TestRunRefusesToRunWhenTheManifestHasDrifted(t *testing.T) {
	o := writeTree(t,
		"on: push\njobs:\n  new-job:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
		`{"workflows":["w.yml"],"plumbing":[],"jobs":{}}`)

	var stdout, stderr bytes.Buffer
	if got := run(o, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2 (a stale manifest must stop the run, not run a subset)", got)
	}
	if !strings.Contains(stderr.String(), "w.yml/new-job is not classified") {
		t.Errorf("stderr should name the missing job:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("nothing may run or print results after a drift:\n%s", stdout.String())
	}
}

func TestRunCheckAndListModes(t *testing.T) {
	o := writeTree(t,
		"on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo hi\n  p:\n    runs-on: x\n    steps:\n      - run: echo pub\n",
		`{"workflows":["w.yml"],"plumbing":[],"jobs":{"w.yml/j":{"requires":["definitely-not-installed-xyz"]},"w.yml/p":{"skip":"publishes"}}}`)

	var stdout, stderr bytes.Buffer
	o.check = true
	if got := run(o, &stdout, &stderr); got != 0 || !strings.Contains(stdout.String(), "every job and step is classified") {
		t.Fatalf("check: exit %d\n%s%s", got, stdout.String(), stderr.String())
	}

	stdout.Reset()
	o.check, o.list = false, true
	if got := run(o, &stdout, &stderr); got != 0 {
		t.Fatalf("list: exit %d\n%s", got, stderr.String())
	}
	for _, want := range []string{"missing definitely-not-installed-xyz on PATH", "publishes"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("-list should show the reason %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunStrictFailsWhenAPrerequisiteIsMissing(t *testing.T) {
	o := writeTree(t,
		"on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: echo hi\n",
		`{"workflows":["w.yml"],"plumbing":[],"jobs":{"w.yml/j":{"requires":["definitely-not-installed-xyz"]}}}`)
	o.dryRun = true

	var stdout, stderr bytes.Buffer
	if got := run(o, &stdout, &stderr); got != 0 {
		t.Fatalf("non-strict exit = %d\n%s", got, stdout.String())
	}
	o.strict = true
	stdout.Reset()
	if got := run(o, &stdout, &stderr); got != 1 {
		t.Fatalf("-strict exit = %d, want 1\n%s", got, stdout.String())
	}
}
