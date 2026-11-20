// Command vulnreport turns scanner output into issue drafts for the scheduled
// published-artifact scan.
//
// It reads Trivy JSON reports for artifacts that have already been published
// (the container image by digest, the npm tarball by version, the Go module by
// tag), filters findings by severity, drops any that already have an open
// issue, and writes the drafts the workflow submits with `gh issue create`.
// Below-threshold findings are written to the job summary instead of opening
// an issue, so a medium finding is recorded and visible without becoming a
// weekly notification.
//
// The command does not call GitHub: drafting is pure and testable, and the
// workflow owns the side effect. A scanner failure is not a finding and never
// reaches this command; the workflow reports it as its own failure issue so a
// broken scanner cannot look like a clean run.
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
)

// severityRank orders Trivy's severity strings. Unknown values rank below LOW
// so a scanner that grows a new level cannot suppress a real one by sorting
// first.
var severityRank = map[string]int{
	"CRITICAL": 5,
	"HIGH":     4,
	"MEDIUM":   3,
	"LOW":      2,
	"UNKNOWN":  1,
}

// Finding is one vulnerability from one published artifact.
type Finding struct {
	Artifact  string
	Advisory  string
	Package   string
	Installed string
	Fixed     string
	Severity  string
	Title     string
	URL       string
}

// Issue is one draft for `gh issue create`.
type Issue struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// existingIssue is the subset of `gh issue list --json title` this command
// needs.
type existingIssue struct {
	Title string `json:"title"`
}

// trivyReport is the subset of Trivy's JSON report this command reads. The
// field names mirror the scanner's, so a report can be piped in unchanged.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Target          string          `json:"Target"`
		Class           string          `json:"Class"`
		Type            string          `json:"Type"`
		Vulnerabilities []vulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

type vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// scanFlag collects repeated `--scan artifact=path` values.
type scanFlag []scanSpec

type scanSpec struct {
	Artifact string
	Path     string
}

func (s *scanFlag) String() string { return fmt.Sprint(*s) }

func (s *scanFlag) Set(value string) error {
	artifact, path, ok := strings.Cut(value, "=")
	if !ok || artifact == "" || path == "" {
		return fmt.Errorf("scan %q must be artifact=path", value)
	}
	*s = append(*s, scanSpec{Artifact: artifact, Path: path})
	return nil
}

func main() {
	var scans scanFlag
	var threshold, existingPath, issuesPath, summaryPath string
	flag.Var(&scans, "scan", "artifact=trivy-json (repeatable); artifact carries its version or digest")
	flag.StringVar(&threshold, "threshold", "HIGH", "minimum severity that opens an issue")
	flag.StringVar(&existingPath, "existing", "", "JSON array of open issues, from gh issue list --json title")
	flag.StringVar(&issuesPath, "issues-out", "", "where to write the JSON array of issue drafts")
	flag.StringVar(&summaryPath, "summary", "", "where to append the Markdown summary")
	flag.Parse()

	if err := run(scans, threshold, existingPath, issuesPath, summaryPath); err != nil {
		fmt.Fprintln(os.Stderr, "vulnreport:", err)
		os.Exit(1)
	}
}

func run(scans []scanSpec, threshold, existingPath, issuesPath, summaryPath string) error {
	if len(scans) == 0 {
		return errors.New("at least one --scan is required")
	}
	threshold = strings.ToUpper(strings.TrimSpace(threshold))
	if _, ok := severityRank[threshold]; !ok {
		return fmt.Errorf("unknown severity threshold %q", threshold)
	}

	findings := make([]Finding, 0)
	for _, scan := range scans {
		parsed, err := readTrivy(scan.Path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", scan.Path, err)
		}
		for _, result := range parsed.Results {
			for _, v := range result.Vulnerabilities {
				findings = append(findings, Finding{
					Artifact:  scan.Artifact,
					Advisory:  v.VulnerabilityID,
					Package:   v.PkgName,
					Installed: v.InstalledVersion,
					Fixed:     v.FixedVersion,
					Severity:  normalizeSeverity(v.Severity),
					Title:     v.Title,
					URL:       v.PrimaryURL,
				})
			}
		}
	}

	existing := make(map[string]bool)
	if existingPath != "" {
		raw, err := os.ReadFile(existingPath)
		if err != nil {
			return fmt.Errorf("reading existing issues: %w", err)
		}
		var issues []existingIssue
		if err := json.Unmarshal(raw, &issues); err != nil {
			return fmt.Errorf("parsing existing issues: %w", err)
		}
		for _, issue := range issues {
			existing[issue.Title] = true
		}
	}

	issues, above, below, duplicates := draftIssues(findings, threshold, existing)
	sort.Slice(above, func(i, j int) bool {
		if above[i].Severity != above[j].Severity {
			return severityRank[above[i].Severity] > severityRank[above[j].Severity]
		}
		return issueTitle(above[i]) < issueTitle(above[j])
	})
	sort.Slice(below, func(i, j int) bool {
		if below[i].Severity != below[j].Severity {
			return severityRank[below[i].Severity] > severityRank[below[j].Severity]
		}
		return issueTitle(below[i]) < issueTitle(below[j])
	})

	if issuesPath != "" {
		encoded, err := json.MarshalIndent(issues, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding issue drafts: %w", err)
		}
		if err := os.WriteFile(issuesPath, append(encoded, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing issue drafts: %w", err)
		}
	}
	if summaryPath != "" {
		if err := appendSummary(summaryPath, threshold, findings, above, below); err != nil {
			return err
		}
	}

	fmt.Printf("vulnreport: %d finding(s): %d above threshold, %d below, %d already tracked\n",
		len(findings), len(above), len(below), duplicates)
	return nil
}

// draftIssues partitions findings and returns the drafts that do not already
// have an open issue. An issue is identified by its title, which carries the
// artifact, advisory and package — so a finding that persists does not reopen
// weekly, while a new package affected by the same advisory gets its own.
func draftIssues(findings []Finding, threshold string, existing map[string]bool) (issues []Issue, above, below []Finding, duplicates int) {
	issues = make([]Issue, 0)
	for _, finding := range findings {
		if severityRank[finding.Severity] < severityRank[threshold] {
			below = append(below, finding)
			continue
		}
		above = append(above, finding)
		title := issueTitle(finding)
		if existing[title] {
			duplicates++
			continue
		}
		issues = append(issues, Issue{Title: title, Body: issueBody(finding)})
	}
	return issues, above, below, duplicates
}

func issueTitle(f Finding) string {
	return fmt.Sprintf("[vuln] %s %s (%s)", f.Artifact, f.Advisory, f.Package)
}

func issueBody(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The scheduled scan of published artifacts found a vulnerability at or above the configured severity.\n\n")
	fmt.Fprintf(&b, "| field | value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| artifact | `%s` |\n", f.Artifact)
	fmt.Fprintf(&b, "| advisory | [%s](%s) |\n", f.Advisory, f.URL)
	fmt.Fprintf(&b, "| package | `%s` |\n", f.Package)
	fmt.Fprintf(&b, "| installed | `%s` |\n", f.Installed)
	if f.Fixed == "" {
		fmt.Fprintf(&b, "| fixed | none published yet |\n")
	} else {
		fmt.Fprintf(&b, "| fixed | `%s` |\n", f.Fixed)
	}
	fmt.Fprintf(&b, "| severity | %s |\n", f.Severity)
	if f.Title != "" {
		fmt.Fprintf(&b, "\n%s\n", f.Title)
	}
	fmt.Fprintf(&b, "\nThis issue is filed by the scheduled `vulnerability-scan` workflow. Close it when the artifact is rebuilt or the advisory no longer applies; it will not be reopened for the same artifact, advisory and package while it stays open.\n")
	return b.String()
}

func appendSummary(path, threshold string, findings, above, below []Finding) error {
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Published-artifact vulnerability scan\n\n")
	fmt.Fprintf(&b, "Threshold for opening an issue: **%s**. Findings below it are recorded here and no issue is opened.\n\n", threshold)
	fmt.Fprintf(&b, "| severity | artifact | advisory | package | action |\n| --- | --- | --- | --- | --- |\n")
	for _, f := range above {
		fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` | issue opened, or already open and deduplicated |\n", f.Severity, f.Artifact, f.Advisory, f.Package)
	}
	if len(below) > 0 {
		fmt.Fprintf(&b, "\n### Below threshold (recorded, no issue)\n\n")
		fmt.Fprintf(&b, "| severity | artifact | advisory | package |\n| --- | --- | --- | --- |\n")
		for _, f := range below {
			fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", f.Severity, f.Artifact, f.Advisory, f.Package)
		}
	}
	if len(findings) == 0 {
		fmt.Fprintf(&b, "No known vulnerabilities were reported for the scanned artifacts.\n")
	}
	fmt.Fprintf(&b, "\nA scanner error is reported as its own workflow failure and issue; it never appears as a clean result.\n")

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("opening the summary: %w", err)
	}
	defer file.Close()
	if _, err := io.WriteString(file, b.String()); err != nil {
		return fmt.Errorf("writing the summary: %w", err)
	}
	return nil
}

func readTrivy(path string) (trivyReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return trivyReport{}, err
	}
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return trivyReport{}, fmt.Errorf("parsing Trivy JSON: %w", err)
	}
	return report, nil
}

func normalizeSeverity(value string) string {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if _, ok := severityRank[normalized]; !ok {
		return "UNKNOWN"
	}
	return normalized
}
