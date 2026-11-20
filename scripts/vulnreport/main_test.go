package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func trivyJSON(entries string) string {
	return `{"ArtifactName":"ignored","Results":[{"Target":"x","Vulnerabilities":[` + entries + `]}]}`
}

func vulnEntry(id, pkg, severity string) string {
	return `{"VulnerabilityID":"` + id + `","PkgName":"` + pkg + `","InstalledVersion":"1.0.0","FixedVersion":"1.0.1","Severity":"` + severity + `","Title":"` + id + ` title","PrimaryURL":"https://example.test/` + id + `"}`
}

func readIssues(t *testing.T, path string) []Issue {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading issue drafts: %v", err)
	}
	var issues []Issue
	if err := json.Unmarshal(raw, &issues); err != nil {
		t.Fatalf("parsing issue drafts: %v", err)
	}
	return issues
}

func TestRunOpensIssuesAtOrAboveThreshold(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "scan.json")
	issuesPath := filepath.Join(dir, "issues.json")
	summary := filepath.Join(dir, "summary.md")
	writeFile(t, report, trivyJSON(vulnEntry("CVE-2026-1", "pkg-a", "HIGH")+","+vulnEntry("CVE-2026-2", "pkg-b", "LOW")))

	err := run([]scanSpec{{Artifact: "ghcr.io/soroauth/soroauth-go@sha256:abc", Path: report}},
		"HIGH", "", issuesPath, summary)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	issues := readIssues(t, issuesPath)
	if len(issues) != 1 {
		t.Fatalf("got %d issue drafts, want 1: %+v", len(issues), issues)
	}
	if !strings.Contains(issues[0].Title, "CVE-2026-1") {
		t.Errorf("issue title = %q, want the above-threshold advisory", issues[0].Title)
	}
	if !strings.Contains(issues[0].Body, "ghcr.io/soroauth/soroauth-go@sha256:abc") {
		t.Error("issue body does not name the published artifact")
	}
	if !strings.Contains(issues[0].Body, "1.0.1") {
		t.Error("issue body does not name the fixed version")
	}

	rawSummary, err := os.ReadFile(summary)
	if err != nil {
		t.Fatalf("reading the summary: %v", err)
	}
	if !strings.Contains(string(rawSummary), "CVE-2026-2") {
		t.Error("the below-threshold finding was not recorded in the summary")
	}
	if !strings.Contains(string(rawSummary), "Below threshold") {
		t.Error("the summary does not say below-threshold findings open no issue")
	}
}

func TestRunDeduplicatesAgainstOpenIssues(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "scan.json")
	issuesPath := filepath.Join(dir, "issues.json")
	existingPath := filepath.Join(dir, "existing.json")
	writeFile(t, report, trivyJSON(vulnEntry("CVE-2026-1", "pkg-a", "CRITICAL")))

	finding := Finding{Artifact: "@soroauth/wasm@1.2.3", Advisory: "CVE-2026-1", Package: "pkg-a"}
	existing, err := json.Marshal([]existingIssue{{Title: issueTitle(finding)}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, existingPath, string(existing))

	err = run([]scanSpec{{Artifact: "@soroauth/wasm@1.2.3", Path: report}},
		"HIGH", existingPath, issuesPath, "")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if issues := readIssues(t, issuesPath); len(issues) != 0 {
		t.Fatalf("got %d duplicate issue drafts, want 0: %+v", len(issues), issues)
	}
}

func TestRunRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "scan.json")
	writeFile(t, report, "not json")

	if err := run([]scanSpec{{Artifact: "a@1", Path: report}}, "HIGH", "", "", ""); err == nil {
		t.Fatal("run accepted a malformed scanner report")
	}
	if err := run([]scanSpec{{Artifact: "a@1", Path: report}}, "SEVERE", "", "", ""); err == nil {
		t.Fatal("run accepted an unknown threshold")
	}
	if err := run(nil, "HIGH", "", "", ""); err == nil {
		t.Fatal("run accepted no scans")
	}
}

func TestSeverityNormalization(t *testing.T) {
	cases := map[string]string{
		"critical": "CRITICAL",
		" High ":   "HIGH",
		"medium":   "MEDIUM",
		"weird":    "UNKNOWN",
		"":         "UNKNOWN",
	}
	for input, want := range cases {
		if got := normalizeSeverity(input); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIssueBodyNeverCarriesTheArtifactContents(t *testing.T) {
	finding := Finding{
		Artifact:  "ghcr.io/soroauth/soroauth-go@sha256:abc",
		Advisory:  "CVE-2026-1",
		Package:   "golang.org/x/net",
		Installed: "0.1.0",
		Fixed:     "0.2.0",
		Severity:  "HIGH",
		URL:       "https://example.test/CVE-2026-1",
	}
	body := issueBody(finding)
	if strings.Contains(body, "BEGIN") || strings.Contains(body, "signature") {
		t.Errorf("issue body looks like it carries artifact contents: %s", body)
	}
	for _, want := range []string{finding.Artifact, finding.Advisory, finding.Package, finding.Fixed} {
		if !strings.Contains(body, want) {
			t.Errorf("issue body is missing %q", want)
		}
	}
}
