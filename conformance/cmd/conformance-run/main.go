// Command conformance-run is the Go runner for the cross-language
// conformance suite described in testdata/conformance/README.md.
//
// Usage:
//
//	conformance-run <cases.json> [vectors-dir]
//
// Reads the case list and writes one NDJSON row per case to stdout. The
// output shape is pinned by the suite's README; every other binding's thin
// runner emits the same shape, so a per-binding CI job can diff its output
// against this baseline.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/soroauth/soroauth-go/conformance"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: conformance-run <cases.json> [vectors-dir]")
		os.Exit(2)
	}
	casesPath := os.Args[1]
	vectorsDir := "testdata/vectors"
	if len(os.Args) == 3 {
		vectorsDir = os.Args[2]
	} else {
		// Default: resolve vectors-dir relative to the cases file's parent,
		// since the suite ships cases.json in testdata/conformance/.
		if rel := filepath.Join(filepath.Dir(casesPath), "..", "vectors"); rel != "" {
			if _, err := os.Stat(rel); err == nil {
				vectorsDir = rel
			}
		}
	}

	f, err := conformance.Load(casesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	results, err := conformance.Run(f, vectorsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, "writing NDJSON row:", err)
			os.Exit(1)
		}
	}
}
