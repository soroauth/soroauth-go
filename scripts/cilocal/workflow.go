package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Step is one step of a workflow job, with the job's defaults folded in so it
// can be executed (or described) on its own. A step either runs a script (Run)
// or uses an action (Uses). Actions that only set the runner up (checkout,
// setup-go, caches) are plumbing the manifest lists; any other action is a
// check or a publish step the manifest has to classify, because the runner
// cannot execute an action.
type Step struct {
	Workflow string // workflow file name, for example "ci.yml"
	Job      string // job id, for example "build"
	JobName  string // the job's display name, falling back to its id
	Name     string // the step name; the action, or "step N", when the workflow gives none
	Index    int    // 1-based position among all of the job's steps
	Run      string // the script, exactly as written in the workflow; empty for an action
	Uses     string // the action, for example "lycheeverse/lychee-action@v2"; empty for a script
	Shell    string // the step's (or job default) shell, "" for the default
	Dir      string // working directory relative to the repository root
	Env      map[string]string
	If       string // the step's if: condition, "" when unconditional
}

// Job is one job of a workflow, in file order.
type Job struct {
	Workflow string
	ID       string
	Name     string
	If       string
	Steps    []Step
}

// Key is the manifest key that classifies the job.
func (j Job) Key() string { return j.Workflow + "/" + j.ID }

// Workflow is a parsed workflow file.
type Workflow struct {
	File string // base name, for example "ci.yml"
	Jobs []Job
}

type workflowDoc struct {
	Env      map[string]string `yaml:"env"`
	Defaults defaultsDoc       `yaml:"defaults"`
	Jobs     yaml.Node         `yaml:"jobs"`
}

type defaultsDoc struct {
	Run struct {
		Shell            string `yaml:"shell"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type jobDoc struct {
	Name     string            `yaml:"name"`
	If       string            `yaml:"if"`
	Env      map[string]string `yaml:"env"`
	Defaults defaultsDoc       `yaml:"defaults"`
	Steps    []stepDoc         `yaml:"steps"`
}

type stepDoc struct {
	Name             string            `yaml:"name"`
	If               string            `yaml:"if"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	Env              map[string]string `yaml:"env"`
}

// ParseWorkflow decodes one workflow file. data is the file's content and file
// its base name.
func ParseWorkflow(file string, data []byte) (Workflow, error) {
	var doc workflowDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Workflow{}, fmt.Errorf("%s: %w", file, err)
	}
	wf := Workflow{File: file}
	if doc.Jobs.Kind != yaml.MappingNode {
		return wf, fmt.Errorf("%s: no jobs mapping", file)
	}
	// A mapping node keeps file order, which a map[string]jobDoc would lose,
	// and file order is the order CI reads top to bottom.
	for i := 0; i+1 < len(doc.Jobs.Content); i += 2 {
		id := doc.Jobs.Content[i].Value
		var jd jobDoc
		if err := doc.Jobs.Content[i+1].Decode(&jd); err != nil {
			return wf, fmt.Errorf("%s: job %s: %w", file, id, err)
		}
		job := Job{Workflow: file, ID: id, Name: jd.Name, If: jd.If}
		if job.Name == "" {
			job.Name = id
		}
		for n, sd := range jd.Steps {
			if sd.Run == "" && sd.Uses == "" {
				continue
			}
			step := Step{
				Workflow: file,
				Job:      id,
				JobName:  job.Name,
				Name:     sd.Name,
				Index:    n + 1,
				Run:      sd.Run,
				Uses:     sd.Uses,
				Shell:    firstNonEmpty(sd.Shell, jd.Defaults.Run.Shell, doc.Defaults.Run.Shell),
				Dir:      firstNonEmpty(sd.WorkingDirectory, jd.Defaults.Run.WorkingDirectory, doc.Defaults.Run.WorkingDirectory),
				If:       sd.If,
				Env:      mergeEnv(doc.Env, jd.Env, sd.Env),
			}
			if step.Name == "" {
				step.Name = firstNonEmpty(step.Uses, fmt.Sprintf("step %d", step.Index))
			}
			job.Steps = append(job.Steps, step)
		}
		wf.Jobs = append(wf.Jobs, job)
	}
	return wf, nil
}

// LoadWorkflows parses every workflow under dir, sorted by file name.
func LoadWorkflows(dir string) ([]Workflow, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && (strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")) {
			names = append(names, n)
		}
	}
	sort.Strings(names)

	var out []Workflow
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		wf, err := ParseWorkflow(n, data)
		if err != nil {
			return nil, err
		}
		out = append(out, wf)
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func mergeEnv(layers ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, layer := range layers {
		for k, v := range layer {
			out[k] = v
		}
	}
	return out
}

// usesExpression reports whether text contains a GitHub Actions expression.
// Such a step is written against the Actions runtime (matrix values, secrets,
// the event payload), so it cannot be run as written on a laptop.
func usesExpression(text string) bool { return strings.Contains(text, "${{") }

// Action returns the action's name without its version ("owner/repo" or
// "owner/repo/path"), or "" for a script step.
func (s Step) Action() string {
	name, _, _ := strings.Cut(s.Uses, "@")
	return name
}

// needsClassification reports whether a step cannot be run exactly as written
// and therefore has to be classified in the manifest by name: it uses an
// expression anywhere, or it only runs under some condition the runner cannot
// evaluate. Whether an action step needs one depends on the manifest's list of
// plumbing actions, so that is decided by Check.
func (s Step) needsClassification() bool {
	if s.If != "" || usesExpression(s.Run) || usesExpression(s.Dir) || usesExpression(s.Shell) {
		return true
	}
	for _, v := range s.Env {
		if usesExpression(v) {
			return true
		}
	}
	return false
}
