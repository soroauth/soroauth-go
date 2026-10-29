package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// findBash returns the bash the workflows' scripts should run under. On
// Windows, `bash` on PATH is usually System32's WSL launcher, which fails when
// no distribution is installed, so Git for Windows' bash (found beside git) is
// preferred and the launcher is never chosen.
func findBash() (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath("bash")
	}
	git, _ := exec.LookPath("git")
	for _, c := range gitBashCandidates(git, os.Getenv) {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath("bash"); err == nil && !isWSLLauncher(p) {
		return p, nil
	}
	return "", errors.New("Git Bash was not found (the bash on PATH is the WSL launcher)")
}

// gitBashCandidates lists where Git for Windows keeps bash.exe: beside the git
// that is on PATH, then the usual install directories.
func gitBashCandidates(gitPath string, getenv func(string) string) []string {
	var candidates []string
	if gitPath != "" {
		// <Git>\cmd\git.exe (or <Git>\bin\git.exe) sits beside <Git>\bin\bash.exe.
		candidates = append(candidates, filepath.Clean(filepath.Join(filepath.Dir(gitPath), "..", "bin", "bash.exe")))
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
		if dir := getenv(env); dir != "" {
			candidates = append(candidates,
				filepath.Join(dir, "Git", "bin", "bash.exe"),
				filepath.Join(dir, "Programs", "Git", "bin", "bash.exe"))
		}
	}
	return candidates
}

// isWSLLauncher reports whether a bash.exe path is the System32 launcher for
// WSL, which fails when no distribution is installed.
func isWSLLauncher(path string) bool {
	return strings.Contains(strings.ToLower(strings.ReplaceAll(path, `\`, "/")), "/system32/")
}

// Status is what happened to one job.
type Status string

// The possible job outcomes.
const (
	Passed  Status = "PASS"
	Failed  Status = "FAIL"
	Skipped Status = "SKIP"
)

// JobResult is the outcome of one planned job.
type JobResult struct {
	Job         Job
	Status      Status
	Reason      string // why the job was skipped or which step failed
	SkipSteps   []string
	Covered     int
	Bookkeeping int
	Duration    time.Duration
	FailedStep  string
}

type executor struct {
	root     string
	bash     string
	dryRun   bool
	failFast bool
	out      io.Writer
}

// Execute runs the plan in order. A job stops at its first failing step, as it
// does in CI; the next job still runs unless failFast is set.
func Execute(plan []PlannedJob, ex executor) []JobResult {
	var results []JobResult
	stopped := false
	for _, pj := range plan {
		res := JobResult{Job: pj.Job}
		switch {
		case pj.Skip != "":
			res.Status, res.Reason = Skipped, pj.Skip
			fmt.Fprintf(ex.out, "\n--- SKIP %s: %s\n", pj.Job.Key(), pj.Skip)
		case stopped:
			res.Status, res.Reason = Skipped, "not run: an earlier job failed and -fail-fast is set"
			fmt.Fprintf(ex.out, "\n--- SKIP %s: %s\n", pj.Job.Key(), res.Reason)
		default:
			start := time.Now()
			res = ex.runJob(pj)
			res.Duration = time.Since(start)
			if res.Status == Failed && ex.failFast {
				stopped = true
			}
		}
		results = append(results, res)
	}
	return results
}

// jobState is what a job's steps share, the way the Actions runner shares it:
// lines a step appends to $GITHUB_PATH and $GITHUB_ENV reach the steps after it.
type jobState struct {
	dir      string
	pathFile string
	envFile  string
	outFile  string
	sumFile  string
	path     []string
	env      map[string]string
}

func newJobState() (*jobState, error) {
	dir, err := os.MkdirTemp("", "cilocal-job-")
	if err != nil {
		return nil, err
	}
	js := &jobState{dir: dir, env: map[string]string{}}
	for _, f := range []*string{&js.pathFile, &js.envFile, &js.outFile, &js.sumFile} {
		file, err := os.CreateTemp(dir, "f-*")
		if err != nil {
			return nil, err
		}
		*f = file.Name()
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	return js, nil
}

// absorb reads what the step wrote to $GITHUB_PATH and $GITHUB_ENV.
func (js *jobState) absorb() {
	for _, line := range readLines(js.pathFile) {
		js.path = append(js.path, line)
	}
	truncate(js.pathFile)

	for _, line := range readLines(js.envFile) {
		if k, v, ok := strings.Cut(line, "="); ok {
			js.env[k] = v
		}
	}
	truncate(js.envFile)
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func truncate(path string) { _ = os.WriteFile(path, nil, 0o600) }

func (ex executor) runJob(pj PlannedJob) JobResult {
	res := JobResult{Job: pj.Job, Status: Passed}
	fmt.Fprintf(ex.out, "\n=== %s (%s)\n", pj.Job.Key(), pj.Job.Name)

	var js *jobState
	if !ex.dryRun {
		var err error
		if js, err = newJobState(); err != nil {
			res.Status, res.Reason = Failed, "could not create the job's scratch files: "+err.Error()
			return res
		}
		defer os.RemoveAll(js.dir)
	}

	for _, ps := range pj.Steps {
		switch {
		case ps.Skip != "":
			fmt.Fprintf(ex.out, "--- SKIP step %q: %s\n", ps.Step.Name, ps.Skip)
			res.SkipSteps = append(res.SkipSteps, fmt.Sprintf("%s (%s)", ps.Step.Name, ps.Skip))
			continue
		case ps.Covered != "":
			fmt.Fprintf(ex.out, "--- step %q is covered by step %q\n", ps.Step.Name, ps.Covered)
			res.Covered++
			continue
		case ps.Book != "":
			fmt.Fprintf(ex.out, "--- step %q is CI bookkeeping, not a check: %s\n", ps.Step.Name, ps.Book)
			res.Bookkeeping++
			continue
		case ps.Note != "":
			fmt.Fprintf(ex.out, "--- step %q uses a local stand-in: %s\n", ps.Step.Name, ps.Note)
		default:
			fmt.Fprintf(ex.out, "--- step %q\n", ps.Step.Name)
		}
		if ex.dryRun {
			for _, line := range strings.Split(strings.TrimRight(ps.Command, "\n"), "\n") {
				fmt.Fprintf(ex.out, "    $ %s\n", line)
			}
			continue
		}
		if err := ex.runStep(ps, pj.Job, js); err != nil {
			res.Status = Failed
			res.FailedStep = ps.Step.Name
			res.Reason = fmt.Sprintf("step %q failed: %v", ps.Step.Name, err)
			fmt.Fprintf(ex.out, "!!! %s\n", res.Reason)
			return res
		}
		js.absorb()
	}
	return res
}

// runStep executes one script the way the Actions runner does: through bash,
// from the step's working directory, with the workflow's env on top of the
// caller's and the runner's own variables set.
func (ex executor) runStep(ps PlannedStep, job Job, js *jobState) error {
	// GitHub runs an unspecified shell as `bash -e` and an explicit `shell:
	// bash` as `bash --noprofile --norc -eo pipefail`.
	args := []string{"-e"}
	switch ps.Step.Shell {
	case "":
	case "bash":
		args = []string{"--noprofile", "--norc", "-eo", "pipefail"}
	default:
		return fmt.Errorf("shell %q is not supported by cilocal: give the step a local \"command\" in the manifest", ps.Step.Shell)
	}

	script, err := os.CreateTemp(js.dir, "step-*.sh")
	if err != nil {
		return err
	}
	if _, err := script.WriteString(prelude(js) + ps.Command); err != nil {
		script.Close()
		return err
	}
	if err := script.Close(); err != nil {
		return err
	}

	cmd := exec.Command(ex.bash, append(args, filepath.ToSlash(script.Name()))...)
	cmd.Dir = filepath.Join(ex.root, filepath.FromSlash(ps.Step.Dir))
	cmd.Stdout, cmd.Stderr = ex.out, ex.out
	cmd.Env = runnerEnv(ex.root, job, js, ps.Step.Env)
	return cmd.Run()
}

// prelude carries the job's $GITHUB_PATH and $GITHUB_ENV additions into the
// step's shell, in the shell's own path syntax.
func prelude(js *jobState) string {
	var b strings.Builder
	if len(js.path) > 0 {
		fmt.Fprintf(&b, "export PATH=%s:\"$PATH\"\n", strings.Join(quoteAll(js.path), ":"))
	}
	keys := make([]string, 0, len(js.env))
	for k := range js.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(js.env[k]))
	}
	return b.String()
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = shellQuote(s)
	}
	return out
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runnerEnv is the environment of one step: the caller's, then the variables
// the Actions runner defines that workflow scripts read, then the workflow's.
func runnerEnv(root string, job Job, js *jobState, stepEnv map[string]string) []string {
	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) }

	set("CI", "true")
	set("GITHUB_ACTIONS", "false") // not Actions: scripts that branch on it should take the local path
	set("GITHUB_WORKSPACE", filepath.ToSlash(root))
	set("GITHUB_JOB", job.ID)
	set("GITHUB_PATH", filepath.ToSlash(js.pathFile))
	set("GITHUB_ENV", filepath.ToSlash(js.envFile))
	set("GITHUB_OUTPUT", filepath.ToSlash(js.outFile))
	set("GITHUB_STEP_SUMMARY", filepath.ToSlash(js.sumFile))
	set("RUNNER_OS", runnerOS())
	if sha, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err == nil {
		set("GITHUB_SHA", strings.TrimSpace(string(sha)))
	}
	for k, v := range stepEnv {
		if !usesExpression(v) {
			set(k, v)
		}
	}
	return env
}

func runnerOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return "Linux"
	}
}

// Summarize prints the outcome table and returns the exit status.
func Summarize(w io.Writer, results []JobResult, strict, dryRun bool) int {
	var passed, failed, skipped, skippedSteps, covered, bookkeeping int
	fmt.Fprintln(w, "\n=== summary")
	for _, r := range results {
		switch r.Status {
		case Passed:
			passed++
		case Failed:
			failed++
		case Skipped:
			skipped++
		}
		covered += r.Covered
		bookkeeping += r.Bookkeeping
		line := fmt.Sprintf("%-4s  %s", r.Status, r.Job.Key())
		if r.Reason != "" {
			line += "  " + r.Reason
		}
		fmt.Fprintln(w, line)
		for _, s := range r.SkipSteps {
			skippedSteps++
			fmt.Fprintf(w, "      skipped step: %s\n", s)
		}
	}
	verb := "passed"
	if dryRun {
		verb = "would run"
	}
	fmt.Fprintf(w, "\n%d jobs %s, %d failed, %d jobs skipped, %d steps skipped (%d covered by another step, %d CI bookkeeping)\n",
		passed, verb, failed, skipped, skippedSteps, covered, bookkeeping)

	switch {
	case failed > 0:
		fmt.Fprintln(w, "FAILED: fix the jobs above before pushing")
		return 1
	case skipped+skippedSteps > 0 && strict:
		fmt.Fprintln(w, "FAILED: -strict and something was skipped; every skip is listed above with its reason")
		return 1
	case skipped+skippedSteps > 0:
		fmt.Fprintln(w, "OK, but the skipped checks above did NOT run: CI will run them")
	default:
		fmt.Fprintln(w, "OK: everything CI runs passed locally")
	}
	return 0
}
