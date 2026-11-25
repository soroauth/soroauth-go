package doccheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestSupplyChainScanEmitsSARIFAndUploads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "security.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	jobs := yamlMappingValue(doc.Content[0], "jobs")
	supply := yamlMappingValue(jobs, "supply-chain")
	if supply == nil {
		t.Fatal("missing supply-chain job")
	}
	perms := yamlMappingValue(supply, "permissions")
	if yamlMappingValue(perms, "security-events") == nil || yamlMappingValue(perms, "security-events").Value != "write" {
		t.Fatal("supply-chain job must have security-events: write for SARIF upload")
	}
	steps := yamlMappingValue(supply, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		t.Fatal("missing steps")
	}
	var sawScan, sawUpload, sawUploadFail bool
	for _, step := range steps.Content {
		name := yamlMappingValue(step, "name")
		if name == nil {
			continue
		}
		run := yamlMappingValue(step, "run")
		uses := yamlMappingValue(step, "uses")
		if name.Value == "scan the changed files" {
			if run == nil || !strings.Contains(run.Value, "--sarif supply-chain-scan.sarif") {
				t.Fatalf("scan step must emit SARIF: %#v", run)
			}
			sawScan = true
		}
		if name.Value == "upload SARIF to code scanning" {
			if uses == nil || !strings.Contains(uses.Value, "github/codeql-action/upload-sarif@") {
				t.Fatalf("upload step must use upload-sarif action: %#v", uses)
			}
			if cond := yamlMappingValue(step, "if"); cond == nil || !strings.Contains(cond.Value, "always()") {
				t.Fatalf("upload step must run with always() so findings upload on blocking scans: %#v", cond)
			}
			with := yamlMappingValue(step, "with")
			if yamlMappingValue(with, "sarif_file") == nil || yamlMappingValue(with, "sarif_file").Value != "supply-chain-scan.sarif" {
				t.Fatal("upload step must reference supply-chain-scan.sarif")
			}
			sawUpload = true
		}
		if name.Value == "report SARIF upload failure" {
			if cond := yamlMappingValue(step, "if"); cond == nil || !strings.Contains(cond.Value, "upload_sarif.outcome == 'failure'") {
				t.Fatalf("upload failure step must report upload failure: %#v", cond)
			}
			sawUploadFail = true
		}
	}
	if !sawScan || !sawUpload || !sawUploadFail {
		t.Fatalf("missing required SARIF steps: scan=%v upload=%v uploadFail=%v", sawScan, sawUpload, sawUploadFail)
	}
}

func TestSupplyChainScanScriptHasStableRuleIDs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "supply-chain-scan.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, id := range []string{"SCS001", "SCS002", "SCS003", "SCS004", "SCS005", "SCS006", "SCS007", "SCS008", "SCS009", "SCS010", "SCS011", "SCS012"} {
		if !strings.Contains(s, id) {
			t.Fatalf("script missing stable rule ID %s", id)
		}
	}
	for _, want := range []string{"--sarif", "version\":\"2.1.0\"", "soroauth-supply-chain-scan"} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing SARIF marker %q", want)
		}
	}
}
