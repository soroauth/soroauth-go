package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateExampleScrape is a one-off generator, not a test. It writes the
// committed example scrape from a real run of the service's metrics handler:
// one signed address_v2 entry and one malformed request. It deliberately does
// not emit a hook event, because the verify-only service does not sign.
func TestGenerateExampleScrape(t *testing.T) {
	if os.Getenv("GEN_SCRAPE") == "" {
		t.Skip("set GEN_SCRAPE=1 to regenerate docs/dashboards/example-metrics.txt")
	}
	ts, _, srv := newTestServer(t, nil)
	entry := signedTestEntry(t)
	body, err := json.Marshal(map[string]string{"entry": entry, "network": "testnet"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if status, raw := postVerifyRaw(t, ts.URL, "", string(body)); status != 200 {
		t.Fatalf("verify status = %d, want 200: %s", status, raw)
	}
	if status, _ := postVerifyRaw(t, ts.URL, "", `{"network":"testnet"}`); status != 400 {
		t.Fatalf("malformed status = %d, want 400", status)
	}

	metrics := httptest.NewServer(srv.metricsHandler())
	defer metrics.Close()
	resp, err := http.Get(metrics.URL + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	header := "# Captured from a real run of the service's /metrics endpoint by\n" +
		"# `GEN_SCRAPE=1 go test ./server -run TestGenerateExampleScrape`.\n" +
		"# The run served one signed address_v2 entry and one malformed request.\n" +
		"# Lines beginning with # are Prometheus comment syntax, valid in a scrape.\n"
	dst := filepath.Join("..", "docs", "dashboards", "example-metrics.txt")
	if err := os.WriteFile(dst, append([]byte(header), out...), 0o644); err != nil {
		t.Fatalf("writing %s: %v", dst, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", dst, len(out))
}
