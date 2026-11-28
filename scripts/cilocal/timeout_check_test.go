package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowJobsHaveTimeoutMinutes(t *testing.T) {
	matches, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil {
		t.Fatalf("failed to glob workflow files: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("no workflow files found")
	}

	for _, path := range matches {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		lines := strings.Split(string(content), "\n")
		inJobs := false
		var currentJob string
		jobIndentation := -1

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " \t"))

			if line == "jobs:" {
				inJobs = true
				continue
			}

			if inJobs {
				if indent == 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
					inJobs = false
					currentJob = ""
					continue
				}

				if indent == 2 && strings.HasSuffix(trimmed, ":") {
					currentJob = strings.TrimSuffix(trimmed, ":")
					jobIndentation = indent
					continue
				}

				if currentJob != "" && indent > jobIndentation {
					if strings.HasPrefix(trimmed, "timeout-minutes:") {
						currentJob = ""
					}
				}

				if currentJob != "" && indent <= jobIndentation && !strings.HasPrefix(line, "#") {
					t.Errorf("job %q in workflow %s is missing timeout-minutes", currentJob, path)
					currentJob = ""
				}
			}
		}
		if currentJob != "" {
			t.Errorf("job %q in workflow %s is missing timeout-minutes", currentJob, path)
		}
	}
}
