// Command cilocal runs, on a developer machine, the commands the CI workflows
// run, in CI's order.
//
// `make` runs fmt, vet and test. CI also runs the vector drift check, the
// adapter modules, the parity suites, the wasm replay, prettier, cspell and the
// link check, so a branch could be green locally and red on push. This command
// closes that gap without a second copy of the commands: it reads the `run:`
// steps from .github/workflows and executes them as written, so a step that
// changes in CI changes here with it.
//
// scripts/cilocal/manifest.json holds what a workflow file cannot say: which
// jobs are out of reach of a laptop (they publish, need secrets or a live
// network) and why, which tools each job needs, and a local stand-in for the
// few steps written against the Actions runtime. Before running anything the
// command checks that manifest against the workflows (the same check
// `go test ./scripts/cilocal` runs in CI), and stops if a job or a step exists
// in CI and is not classified, so the two cannot drift.
//
// Nothing is silently skipped. A job whose tool is missing, a job that cannot
// run locally and a step that is skipped are each printed with their reason and
// counted in the summary; -strict turns any skip into a failure.
//
// Usage:
//
//	go run ./scripts/cilocal [-list] [-dry-run] [-only text] [-strict] [-fail-fast] [-check]
//
// Exit status: 0 every check that ran passed, 1 a check failed (or -strict and
// something was skipped), 2 usage error or manifest/workflow disagreement.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	defaultWorkflowDir = ".github/workflows"
	defaultManifest    = "scripts/cilocal/manifest.json"
)

// hostOS is the machine the plan is built for; a variable so tests can vary it.
var hostOS = runtime.GOOS

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

type options struct {
	workflowDir string
	manifest    string
	list        bool
	dryRun      bool
	only        string
	strict      bool
	failFast    bool
	check       bool
}

func main() {
	var o options
	flag.StringVar(&o.workflowDir, "workflows", defaultWorkflowDir, "directory holding the CI workflow files")
	flag.StringVar(&o.manifest, "manifest", defaultManifest, "the manifest classifying every job")
	flag.BoolVar(&o.list, "list", false, "print every job and what would happen to it, then exit")
	flag.BoolVar(&o.dryRun, "dry-run", false, "print the commands that would run without running them")
	flag.StringVar(&o.only, "only", "", "run only jobs whose \"workflow/job\" key contains this text")
	flag.BoolVar(&o.strict, "strict", false, "fail when any job or step was skipped")
	flag.BoolVar(&o.failFast, "fail-fast", false, "stop at the first failing job instead of running the rest")
	flag.BoolVar(&o.check, "check", false, "only check that the manifest and the workflows agree")
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "cilocal: unexpected argument %q\n", flag.Arg(0))
		os.Exit(2)
	}
	os.Exit(run(o, os.Stdout, os.Stderr))
}

func run(o options, stdout, stderr io.Writer) int {
	workflows, err := LoadWorkflows(o.workflowDir)
	if err != nil {
		fmt.Fprintln(stderr, "cilocal:", err)
		return 2
	}
	manifest, err := LoadManifest(o.manifest)
	if err != nil {
		fmt.Fprintln(stderr, "cilocal:", err)
		return 2
	}

	if problems := Check(workflows, manifest); len(problems) > 0 {
		fmt.Fprintln(stderr, "cilocal: the manifest and the CI workflows disagree, so a check could be missing from this run:")
		for _, p := range problems {
			fmt.Fprintln(stderr, "  -", p)
		}
		fmt.Fprintf(stderr, "fix %s (see its \"note\")\n", o.manifest)
		return 2
	}
	if o.check {
		fmt.Fprintf(stdout, "cilocal: %d workflows, every job and step is classified\n", len(workflows))
		return 0
	}

	plan := BuildPlan(workflows, manifest, o.only, exec.LookPath)
	if o.list {
		PrintPlan(stdout, plan)
		return 0
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "cilocal:", err)
		return 2
	}
	bash, err := findBash()
	if err != nil && !o.dryRun {
		fmt.Fprintf(stderr, "cilocal: bash is required to run the workflows' commands: %v\n", err)
		return 2
	}

	results := Execute(plan, executor{root: root, bash: bash, dryRun: o.dryRun, failFast: o.failFast, out: stdout})
	return Summarize(stdout, results, o.strict, o.dryRun)
}

// PlannedStep is one step of a runnable job.
type PlannedStep struct {
	Step    Step
	Command string // what will run; empty when Skip or Covered is set
	Skip    string // why the step is not run; empty when it runs
	Covered string // the step whose command does this step's work
	Book    string // why the step is CI bookkeeping with no check in it
	Note    string // set when Command stands in for the workflow's script
}

// PlannedJob is the plan for one job.
type PlannedJob struct {
	Job    Job
	Skip   string // why the whole job is not run; empty when it runs
	Steps  []PlannedStep
	Missed []string // tools the job needs that are not installed
}

// BuildPlan turns the workflows and the manifest into an ordered plan.
// lookPath reports whether a tool is installed. only, when non-empty, keeps the
// jobs whose key contains it.
func BuildPlan(workflows []Workflow, m Manifest, only string, lookPath func(string) (string, error)) []PlannedJob {
	byFile := map[string]Workflow{}
	for _, wf := range workflows {
		byFile[wf.File] = wf
	}
	plumbing := map[string]bool{}
	for _, a := range m.Plumbing {
		plumbing[a] = true
	}

	var plan []PlannedJob
	for _, file := range m.Workflows {
		for _, job := range byFile[file].Jobs {
			if only != "" && !strings.Contains(job.Key(), only) {
				continue
			}
			spec := m.Jobs[job.Key()]
			pj := PlannedJob{Job: job}

			if spec.Skip != "" {
				pj.Skip = spec.Skip
				plan = append(plan, pj)
				continue
			}
			if len(spec.OS) > 0 && !contains(spec.OS, hostOS) {
				pj.Skip = fmt.Sprintf("CI runs it on %s only; this host is %s (try WSL or a Linux container)", strings.Join(spec.OS, "/"), hostOS)
				plan = append(plan, pj)
				continue
			}
			for _, tool := range spec.Requires {
				if _, err := lookPath(tool); err != nil {
					pj.Missed = append(pj.Missed, tool)
				}
			}
			if len(pj.Missed) > 0 {
				pj.Skip = "missing " + strings.Join(pj.Missed, ", ") + " on PATH"
				plan = append(plan, pj)
				continue
			}

			for _, s := range job.Steps {
				if s.Run == "" && plumbing[s.Action()] {
					continue // sets the runner up; there is nothing to run
				}
				ps := PlannedStep{Step: s, Command: s.Run}
				if ss, ok := spec.Steps[s.Name]; ok {
					switch {
					case ss.Skip != "":
						ps.Command, ps.Skip = "", ss.Skip
					case ss.Covered != "":
						ps.Command, ps.Covered = "", ss.Covered
					case ss.Bookkeeping != "":
						ps.Command, ps.Book = "", ss.Bookkeeping
					case ss.Command != "":
						ps.Command, ps.Note = ss.Command, ss.Why
					}
				}
				pj.Steps = append(pj.Steps, ps)
			}
			plan = append(plan, pj)
		}
	}
	return plan
}

// PrintPlan writes the plan without running anything.
func PrintPlan(w io.Writer, plan []PlannedJob) {
	for _, pj := range plan {
		if pj.Skip != "" {
			fmt.Fprintf(w, "SKIP  %-44s %s\n", pj.Job.Key(), pj.Skip)
			continue
		}
		fmt.Fprintf(w, "RUN   %-44s %d steps\n", pj.Job.Key(), len(pj.Steps))
		for _, ps := range pj.Steps {
			switch {
			case ps.Skip != "":
				fmt.Fprintf(w, "        skip     %s: %s\n", ps.Step.Name, ps.Skip)
			case ps.Covered != "":
				fmt.Fprintf(w, "        covered  %s (by %q)\n", ps.Step.Name, ps.Covered)
			case ps.Book != "":
				fmt.Fprintf(w, "        book     %s: %s\n", ps.Step.Name, ps.Book)
			case ps.Note != "":
				fmt.Fprintf(w, "        stand-in %s: %s\n", ps.Step.Name, ps.Note)
			default:
				fmt.Fprintf(w, "        run      %s\n", ps.Step.Name)
			}
		}
	}
}
