package rpcflow

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRefusesMissingDir(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("Load returned nil error for a missing directory")
	}
}

func TestLoadSkipsNonJSONFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not json"), 0o644); err != nil {
		t.Fatalf("writing README: %v", err)
	}
	writeFixture(t, dir, "valid.json", `{
		"name": "test",
		"network_passphrase": "Test SDF Network ; September 2015",
		"signed_entry_xdr": "AAAA",
		"expected_outcome": "accepted"
	}`)
	fixtures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(fixtures) != 1 {
		t.Fatalf("got %d fixtures, want 1", len(fixtures))
	}
	if fixtures[0].Name != "test" {
		t.Errorf("got name %q, want %q", fixtures[0].Name, "test")
	}
}

func TestLoadRejectsFixtureWithNoName(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "bad.json", `{
		"name": "",
		"network_passphrase": "Test SDF Network ; September 2015",
		"signed_entry_xdr": "AAAA",
		"expected_outcome": "accepted"
	}`)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load returned nil error for a fixture with no name")
	}
}

func TestLoadRejectsFixtureWithNoXDR(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "bad.json", `{
		"name": "no-xdr",
		"network_passphrase": "Test SDF Network ; September 2015",
		"signed_entry_xdr": "",
		"expected_outcome": "accepted"
	}`)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load returned nil error for a fixture with no signed_entry_xdr")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	fixtures, err := Load(dir)
	if err != nil {
		t.Fatalf("Load of empty dir: %v", err)
	}
	if len(fixtures) != 0 {
		t.Fatalf("got %d fixtures from empty dir, want 0", len(fixtures))
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
}
