package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkVerifyHTTP measures the same handler and golden vectors used by the
// service. The library's BenchmarkVerifyEntry isolates the verification engine.
func BenchmarkVerifyHTTP(b *testing.B) {
	for _, name := range []string{
		"legacy_single_testnet",
		"delegates_from_legacy",
		"delegates_chain_depth_54",
	} {
		b.Run(name, func(b *testing.B) {
			raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name+".json"))
			if err != nil {
				b.Fatal(err)
			}
			var v struct {
				SignedEntry string `json:"signed_entry_xdr"`
				Network     string `json:"network_passphrase"`
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				b.Fatal(err)
			}
			payload, err := json.Marshal(verifyRequest{Entry: v.SignedEntry, Network: v.Network})
			if err != nil {
				b.Fatal(err)
			}
			cfg := defaultConfig()
			// Measure admitted traffic, with request size and concurrency enforced.
			cfg.RateLimitPerSecond = 1_000_000
			cfg.RateLimitBurst = cfg.RateLimitPerSecond
			handler := newServer(cfg).handler()
			b.ReportAllocs()
			for b.Loop() {
				req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("status = %d: %s", rec.Code, rec.Body)
				}
			}
		})
	}
}
