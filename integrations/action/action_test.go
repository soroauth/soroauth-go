package action_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func findBash() (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath("bash")
	}
	git, _ := exec.LookPath("git")
	if git != "" {
		p := filepath.Clean(filepath.Join(filepath.Dir(git), "..", "bin", "bash.exe"))
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
		if dir := os.Getenv(env); dir != "" {
			for _, sub := range []string{filepath.Join("Git", "bin", "bash.exe"), filepath.Join("Programs", "Git", "bin", "bash.exe")} {
				p := filepath.Join(dir, sub)
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					return p, nil
				}
			}
		}
	}
	return exec.LookPath("bash")
}

// TestActionYmlDeclaresVersionOutput asserts that action.yml defines the version output.
func TestActionYmlDeclaresVersionOutput(t *testing.T) {
	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("reading action.yml: %v", err)
	}

	var actionDef struct {
		Outputs map[string]struct {
			Description string `yaml:"description"`
			Value       string `yaml:"value"`
		} `yaml:"outputs"`
	}

	if err := yaml.Unmarshal(data, &actionDef); err != nil {
		t.Fatalf("parsing action.yml: %v", err)
	}

	out, exists := actionDef.Outputs["version"]
	if !exists {
		t.Fatalf("action.yml does not declare output %q", "version")
	}

	if out.Value != "${{ steps.verify.outputs.version }}" {
		t.Errorf("outputs.version.value = %q, want ${{ steps.verify.outputs.version }}", out.Value)
	}
}

// TestReadmeDocumentsVersionOutputAndPinning asserts that README.md documents the
// version output and demonstrates pinning both the action ref and the image digest.
func TestReadmeDocumentsVersionOutputAndPinning(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	readme := string(data)

	if !strings.Contains(readme, "## Outputs") {
		t.Error("README.md has no `## Outputs` heading")
	}
	if !strings.Contains(readme, "`version`") {
		t.Error("README.md does not document the `version` output")
	}
	if !regexp.MustCompile(`integrations/action@[0-9a-f]{40}`).MatchString(readme) {
		t.Error("README.md must show pinning the action with a 40-character commit SHA")
	}
	if !regexp.MustCompile(`ghcr\.io/soroauth/soroauth-go@sha256:[0-9a-f]{64}`).MatchString(readme) {
		t.Error("README.md must show pinning the container image with a sha256 digest")
	}
}

// TestVerifyScriptReportsBuildVersionInSummaryAndOutput asserts that verify.sh
// identifies the exact build (not just a tag) and writes it to GITHUB_STEP_SUMMARY
// and GITHUB_OUTPUT.
func TestVerifyScriptReportsBuildVersionInSummaryAndOutput(t *testing.T) {
	bash, err := findBash()
	if err != nil {
		t.Skipf("bash is required for this test: %v", err)
	}

	tmpDir := t.TempDir()
	summaryFile := filepath.Join(tmpDir, "step_summary.md")
	outputFile := filepath.Join(tmpDir, "github_output.txt")

	// Create a mock CLI that mimics `soroauth --version` with full build identity.
	mockCLIScript := filepath.Join(tmpDir, "mock_soroauth.sh")
	mockScriptContent := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "soroauth v0.1.0"
  echo "commit: 7b312a0f8e4c"
  echo "built: 2026-11-20T19:00:00Z"
  echo "go: go1.24.2"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(mockCLIScript, []byte(mockScriptContent), 0o755); err != nil {
		t.Fatalf("writing mock CLI: %v", err)
	}

	// Also create a mock jq in case verify.sh proceeds further.
	mockJQSh := filepath.Join(tmpDir, "jq")
	_ = os.WriteFile(mockJQSh, []byte("#!/bin/sh\nexit 0\n"), 0o755)

	verifyScript, err := filepath.Abs("verify.sh")
	if err != nil {
		t.Fatalf("abs path of verify.sh: %v", err)
	}

	cmd := exec.Command(bash, verifyScript)
	cmd.Dir = tmpDir
	mockCLIForward := filepath.ToSlash(mockCLIScript)
	cmd.Env = append(os.Environ(),
		"SOROAUTH_INPUT_ENTRY=AAAA",
		"SOROAUTH_INPUT_NETWORK=testnet",
		"SOROAUTH_INPUT_IMAGE=soroauth-action:test",
		"SOROAUTH_CLI_OVERRIDE=bash "+mockCLIForward,
		"GITHUB_STEP_SUMMARY="+filepath.ToSlash(summaryFile),
		"GITHUB_OUTPUT="+filepath.ToSlash(outputFile),
		"PATH="+tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	_ = cmd.Run() // May exit non-zero later during inspect/verify, but version emission happens early

	// Check GITHUB_STEP_SUMMARY
	summaryBytes, err := os.ReadFile(summaryFile)
	if err != nil {
		t.Fatalf("reading GITHUB_STEP_SUMMARY: %v; combined output:\n%s", err, combined.String())
	}
	summary := string(summaryBytes)

	if !strings.Contains(summary, "### soroauth verify") {
		t.Errorf("summary missing header '### soroauth verify':\n%s", summary)
	}
	for _, want := range []string{"v0.1.0", "commit: 7b312a0f8e4c", "built: 2026-11-20T19:00:00Z", "go: go1.24.2"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing exact build field %q:\n%s", want, summary)
		}
	}

	// Check GITHUB_OUTPUT
	outputBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("reading GITHUB_OUTPUT: %v; combined output:\n%s", err, combined.String())
	}
	output := string(outputBytes)

	if !strings.Contains(output, "version=") {
		t.Fatalf("output missing 'version=':\n%s", output)
	}
	for _, want := range []string{"v0.1.0", "7b312a0f8e4c", "2026-11-20T19:00:00Z", "go1.24.2"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing exact build field %q:\n%s", want, output)
		}
	}
}
