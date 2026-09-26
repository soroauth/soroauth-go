package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
)

func handleWASMBudget(args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("wasm-budget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "Output result in JSON format")
	wasmOut := fs.String("out", "soroauth.wasm", "Path to output wasm file")
	budgetBytes := fs.Int64("budget", 5*1024*1024, "Maximum allowed size in bytes (default 5MB)")
	prevSize := fs.Int64("prev-size", 0, "Previous release size for delta comparison")
	buildCmd := fs.String("build-cmd", "", "Optional command to build the wasm binary before measuring")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *buildCmd != "" {
		cmd := exec.Command("sh", "-c", *buildCmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("building wasm binary: %w, stderr: %s", err, string(output))
		}
	}

	fi, err := os.Stat(*wasmOut)
	if err != nil {
		return fmt.Errorf("stat wasm binary: %w", err)
	}

	wasmSize := fi.Size()
	exceeded := wasmSize > *budgetBytes
	var delta int64
	if *prevSize > 0 {
		delta = wasmSize - *prevSize
	}

	result := WASMBudgetResult{
		Size:         wasmSize,
		Budget:       *budgetBytes,
		Exceeded:     exceeded,
		PreviousSize: *prevSize,
		Delta:        delta,
	}

	if *jsonOutput {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "WASM Size: %d bytes (Budget: %d bytes)\n", wasmSize, *budgetBytes)
		if *prevSize > 0 {
			fmt.Fprintf(stdout, "Delta vs Previous: %+d bytes\n", delta)
		}
		if exceeded {
			fmt.Fprintln(stdout, "ERROR: WASM size budget exceeded!")
		} else {
			fmt.Fprintln(stdout, "SUCCESS: WASM size within budget.")
		}
	}

	if exceeded {
		return fmt.Errorf("wasm size %d exceeds budget %d", wasmSize, *budgetBytes)
	}

	return nil
}

// WASMBudget is the maximum allowed size in bytes for the compiled WASM artifact.
// Go WASM binaries grow quickly; this budget enforces a strict ceiling.
const WASMBudget = 3 * 1024 * 1024 // 3 MiB budget

// WASMReport represents the structured JSON output for the WASM size check.
type WASMReport struct {
	SizeInBytes     int64  `json:"size_in_bytes"`
	SizeFormatted   string `json:"size_formatted"`
	BudgetInBytes   int64  `json:"budget_in_bytes"`
	BudgetFormatted string `json:"budget_formatted"`
	PreviousRelease int64  `json:"previous_release_size_bytes"`
	DeltaBytes      int64  `json:"delta_bytes"`
	DeltaFormatted  string `json:"delta_formatted"`
	Passed          bool   `json:"passed"`
}

// formatBytes returns a human-readable string representation of a byte size.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// WASMBudgetResult represents the structured result of the WASM size budget check.
type WASMBudgetResult struct {
	Size         int64 `json:"size"`
	Budget       int64 `json:"budget"`
	Exceeded     bool  `json:"exceeded"`
	PreviousSize int64 `json:"previous_size,omitempty"`
	Delta        int64 `json:"delta,omitempty"`
}
