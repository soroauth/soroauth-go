package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Manifest classifies every job of every workflow so that nothing CI runs can
// be left out of `make ci-local` without a visible, reviewed decision.
//
// The runner reads the commands themselves from .github/workflows, so a step
// that exists in CI runs locally with the same text and cannot drift. What the
// manifest adds is the part a workflow file cannot say: which jobs are out of
// reach of a laptop and why, which tools a job needs, and what stands in for a
// step written against the Actions runtime.
type Manifest struct {
	// Note explains the file to a reader.
	Note string `json:"note,omitempty"`
	// Workflows lists the workflow files in the order CI's required checks come
	// first. A workflow file missing from here (or listed but absent) fails the
	// meta-check.
	Workflows []string `json:"workflows"`
	// Plumbing lists the actions that only set a runner up (checkout, toolchain
	// setup, caches, artifact transfer). Every other action a runnable job uses
	// is a check or a publish step and has to be classified, because the runner
	// cannot execute an action.
	Plumbing []string `json:"plumbing"`
	// Jobs classifies each job, keyed "workflow-file/job-id".
	Jobs map[string]JobSpec `json:"jobs"`
}

// JobSpec classifies one job.
type JobSpec struct {
	// Skip, when set, is the reason the whole job is not run locally.
	Skip string `json:"skip,omitempty"`
	// Requires lists executables the job's commands need. When one is not on
	// PATH the job is reported as skipped, naming the missing tool.
	Requires []string `json:"requires,omitempty"`
	// OS limits the job to the listed GOOS values (CI runs on Linux). On any
	// other host the job is reported as skipped with that reason.
	OS []string `json:"os,omitempty"`
	// Steps classifies the steps that cannot be run exactly as written (those
	// using an Actions expression or an if: condition, and every action that
	// is not plumbing) and those that only make sense on a CI runner. Keyed by
	// step name. A step not listed here runs exactly as the workflow writes it.
	Steps map[string]StepSpec `json:"steps,omitempty"`
}

// StepSpec classifies one step of a job. Exactly one of Skip, Command and
// Covered is set.
type StepSpec struct {
	// Skip is the reason the step is not run locally. It is reported, and
	// counted, as skipped.
	Skip string `json:"skip,omitempty"`
	// Command runs in place of the step when the step is written against the
	// Actions runtime (or is an action) but has a local equivalent.
	Command string `json:"command,omitempty"`
	// Why explains a Command override.
	Why string `json:"why,omitempty"`
	// Covered names another step of the same job whose Command also does this
	// step's work, so nothing is lost by not running it separately.
	Covered string `json:"covered,omitempty"`
	// Bookkeeping is the reason the step is CI bookkeeping with no check in
	// it (a job summary, an issue filed on failure, a coverage upload). It is
	// listed in the output but is not a skipped check, so -strict does not fail
	// on it.
	Bookkeeping string `json:"bookkeeping,omitempty"`
}

// LoadManifest reads and decodes the manifest at path.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Check is the meta-check: it returns one problem per way the manifest and the
// workflows disagree. An empty result means every step CI runs is either run
// by `make ci-local` or skipped for a stated reason.
func Check(workflows []Workflow, m Manifest) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	byFile := map[string]Workflow{}
	for _, wf := range workflows {
		byFile[wf.File] = wf
	}

	listed := map[string]bool{}
	for _, f := range m.Workflows {
		if listed[f] {
			add("workflow %s is listed twice in the manifest", f)
		}
		listed[f] = true
		if _, ok := byFile[f]; !ok {
			add("the manifest lists %s but .github/workflows has no such file", f)
		}
	}

	plumbing := map[string]bool{}
	for _, a := range m.Plumbing {
		if a == "" || strings.Contains(a, "@") {
			add("plumbing entry %q must be an action name without a version, like actions/checkout", a)
		}
		plumbing[a] = true
	}

	jobKeys := map[string]Job{}
	for _, wf := range workflows {
		if !listed[wf.File] {
			add("workflow %s is not in the manifest: add it to \"workflows\" and classify its jobs", wf.File)
		}
		for _, job := range wf.Jobs {
			jobKeys[job.Key()] = job
			spec, ok := m.Jobs[job.Key()]
			if !ok {
				add("job %s is not classified in the manifest: run it (list what it requires) or skip it with a reason", job.Key())
				continue
			}
			problems = append(problems, checkJob(job, spec, plumbing)...)
		}
	}

	for key := range m.Jobs {
		if _, ok := jobKeys[key]; !ok {
			add("the manifest classifies %s but no such job exists in .github/workflows", key)
		}
	}

	sort.Strings(problems)
	return problems
}

func checkJob(job Job, spec JobSpec, plumbing map[string]bool) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("job %s: ", job.Key())+fmt.Sprintf(format, args...))
	}

	if spec.Skip != "" {
		if len(spec.Requires) > 0 || len(spec.Steps) > 0 {
			add("is skipped as a whole, so it must not also list requires or steps")
		}
		return problems
	}
	if job.If != "" {
		add("has an if: condition (%q), which cannot be evaluated locally: skip the job with the reason, or remove the condition", job.If)
	}

	names := map[string]int{}
	for _, s := range job.Steps {
		names[s.Name]++
	}
	byName := map[string]Step{}
	for _, s := range job.Steps {
		byName[s.Name] = s
	}

	for _, s := range job.Steps {
		if names[s.Name] > 1 {
			add("step name %q is used more than once: give each step of a job its own name", s.Name)
			continue
		}
		_, classified := spec.Steps[s.Name]
		switch {
		case classified:
		case s.Run == "" && !plumbing[s.Action()]:
			add("step %q uses the action %s, which the runner cannot execute: give it a local \"command\", a \"skip\" reason, or list the action under \"plumbing\" if it only sets the runner up", s.Name, s.Action())
		case s.Run != "" && s.needsClassification():
			add("step %q cannot run as written (it uses an Actions expression or an if: condition): give it a \"skip\" reason or a local \"command\"", s.Name)
		}
	}

	for name, ss := range spec.Steps {
		if _, ok := byName[name]; !ok {
			add("classifies step %q, which does not exist", name)
			continue
		}
		set := 0
		for _, v := range []string{ss.Skip, ss.Command, ss.Covered, ss.Bookkeeping} {
			if strings.TrimSpace(v) != "" {
				set++
			}
		}
		switch {
		case set != 1:
			add("step %q needs exactly one of \"skip\", \"command\", \"covered\" and \"bookkeeping\"", name)
		case ss.Command != "" && ss.Why == "":
			add("step %q overrides the command but does not say why", name)
		case ss.Covered != "":
			target, exists := spec.Steps[ss.Covered]
			switch {
			case ss.Covered == name:
				add("step %q cannot be covered by itself", name)
			case !exists || target.Command == "":
				add("step %q is covered by %q, which must be a step of this job with a \"command\"", name, ss.Covered)
			}
		}
	}
	return problems
}
