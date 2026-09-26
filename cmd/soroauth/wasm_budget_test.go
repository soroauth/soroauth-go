package main

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestWASMBudgetCommandJSON(t *testing.T) {
	tmpDir := t.TempDir()
	wasmFile := filepath.Join(tmpDir, "test.wasm")
	err := os.WriteFile(wasmFile, make([]byte, 1024), 0644)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	err = handleWASMBudget([]string{
		"--out", wasmFile,
		"--budget", "2048",
		"--json",
		"--prev-size", "512",
	}, &stdout, &stderr)
	assert.NoError(t, err)
}

func TestWASMBudgetCommandHuman(t *testing.T) {
	tmpDir := t.TempDir()
	wasmFile := filepath.Join(tmpDir, "test.wasm")
	err := os.WriteFile(wasmFile, make([]byte, 1024), 0644)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	err = handleWASMBudget([]string{
		"--out", wasmFile,
		"--budget", "2048",
		"--prev-size", "1024",
	}, &stdout, &stderr)
	assert.NoError(t, err)
}

func TestWASMBudgetCommandExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	wasmFile := filepath.Join(tmpDir, "test.wasm")
	err := os.WriteFile(wasmFile, make([]byte, 2048), 0644)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	err = handleWASMBudget([]string{
		"--out", wasmFile,
		"--budget", "1024",
	}, &stdout, &stderr)
	assert.Error(t, err)
}
