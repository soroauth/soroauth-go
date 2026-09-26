package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type vectorData struct {
	PreWrapEntryXDR  string `json:"pre_wrap_entry_xdr"`
	UnsignedEntryXDR string `json:"unsigned_entry_xdr"`
}

func main() {
	vectorsDir := "testdata/vectors"
	corpusDir := "testdata/fuzz"

	if err := os.MkdirAll(corpusDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create corpus dir: %v\n", err)
		os.Exit(1)
	}

	files, err := os.ReadDir(vectorsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read vectors dir: %v\n", err)
		os.Exit(1)
	}

	count := 0
	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
			continue
		}

		path := filepath.Join(vectorsDir, f.Name())
		raw, _ := os.ReadFile(path)
		var v vectorData
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}

		var candidates []string
		if v.UnsignedEntryXDR != "" {
			candidates = append(candidates, v.UnsignedEntryXDR)
		}
		if v.PreWrapEntryXDR != "" {
			candidates = append(candidates, v.PreWrapEntryXDR)
		}

		for i, c := range candidates {
			outName := fmt.Sprintf("%s_%d.seed", f.Name()[:len(f.Name())-5], i)
			outPath := filepath.Join(corpusDir, outName)
			if err := os.WriteFile(outPath, []byte(c), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write seed %s: %v\n", outName, err)
				os.Exit(1)
			}
			count++
		}
	}

	fmt.Printf("Generated %d fuzz corpus seed files in %s\n", count, corpusDir)
}
