package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// envMap turns a map into the getenv function loadConfig takes, so the parsing
// is tested without touching the process environment.
func envMap(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(envMap(nil))
	if err != nil {
		t.Fatalf("loadConfig with an empty environment: %v", err)
	}
	if cfg.Addr != "127.0.0.1:8080" {
		t.Errorf("default Addr = %q, want the loopback default", cfg.Addr)
	}
	if cfg.MaxBodyBytes != maxRequestBodySize {
		t.Errorf("default MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, maxRequestBodySize)
	}
	if cfg.MaxConcurrentRequests != defaultMaxConcurrent {
		t.Errorf("default MaxConcurrentRequests = %d, want %d", cfg.MaxConcurrentRequests, defaultMaxConcurrent)
	}
	if cfg.ReadTimeout != defaultReadTimeout || cfg.WriteTimeout != defaultWriteTimeout {
		t.Errorf("default timeouts = %v/%v, want %v/%v",
			cfg.ReadTimeout, cfg.WriteTimeout, defaultReadTimeout, defaultWriteTimeout)
	}
	if cfg.MetricsAddr != defaultMetricsAddr {
		t.Errorf("default MetricsAddr = %q, want %q", cfg.MetricsAddr, defaultMetricsAddr)
	}
}

// The fail-closed rule: a non-loopback bind with no token is refused, and the
// same bind succeeds once a token is present. Breaking the rule is the one
// thing the service must not do silently, so this asserts the refusal names the
// offending address.
func TestLoadConfigRefusesNonLoopbackWithoutAuth(t *testing.T) {
	_, err := loadConfig(envMap(map[string]string{"ADDR": ":8080"}))
	if err == nil {
		t.Fatal("loadConfig accepted :8080 with no AUTH_TOKEN; it must fail closed")
	}
	if !strings.Contains(err.Error(), ":8080") || !strings.Contains(err.Error(), "AUTH_TOKEN") {
		t.Errorf("refusal error = %q, want it to name the address and AUTH_TOKEN", err)
	}

	if _, err := loadConfig(envMap(map[string]string{"ADDR": "0.0.0.0:8080"})); err == nil {
		t.Error("loadConfig accepted 0.0.0.0:8080 with no AUTH_TOKEN; it must fail closed")
	}

	cfg, err := loadConfig(envMap(map[string]string{"ADDR": ":8080", "AUTH_TOKEN": "tok"}))
	if err != nil {
		t.Fatalf("loadConfig with a token: %v", err)
	}
	if cfg.AuthToken != "tok" {
		t.Errorf("AuthToken = %q, want tok", cfg.AuthToken)
	}
}

func TestLoadConfigRejectsMalformedBounds(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"bad duration", map[string]string{"READ_TIMEOUT": "soon"}},
		{"bad body size", map[string]string{"MAX_BODY_BYTES": "lots"}},
		{"zero body size", map[string]string{"MAX_BODY_BYTES": "0"}},
		{"negative body size", map[string]string{"MAX_BODY_BYTES": "-1"}},
		{"zero concurrency", map[string]string{"MAX_CONCURRENT_REQUESTS": "0"}},
		{"bad concurrency", map[string]string{"MAX_CONCURRENT_REQUESTS": "many"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadConfig(envMap(tt.env)); err == nil {
				t.Errorf("loadConfig accepted %v; want an error", tt.env)
			}
		})
	}
}

func TestLoadConfigReadsEveryBound(t *testing.T) {
	cfg, err := loadConfig(envMap(map[string]string{
		"ADDR":                    "127.0.0.1:9999",
		"METRICS_ADDR":            "off",
		"READ_TIMEOUT":            "2s",
		"READ_HEADER_TIMEOUT":     "1s",
		"WRITE_TIMEOUT":           "3s",
		"IDLE_TIMEOUT":            "4s",
		"MAX_BODY_BYTES":          "4096",
		"MAX_CONCURRENT_REQUESTS": "7",
	}))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Addr != "127.0.0.1:9999" || cfg.MetricsAddr != "off" {
		t.Errorf("addresses = %q/%q", cfg.Addr, cfg.MetricsAddr)
	}
	if cfg.ReadTimeout != 2*time.Second || cfg.ReadHeaderTimeout != time.Second ||
		cfg.WriteTimeout != 3*time.Second || cfg.IdleTimeout != 4*time.Second {
		t.Errorf("timeouts = %v/%v/%v/%v", cfg.ReadTimeout, cfg.ReadHeaderTimeout, cfg.WriteTimeout, cfg.IdleTimeout)
	}
	if cfg.MaxBodyBytes != 4096 || cfg.MaxConcurrentRequests != 7 {
		t.Errorf("bounds = %d/%d", cfg.MaxBodyBytes, cfg.MaxConcurrentRequests)
	}
	if !metricsDisabled(cfg.MetricsAddr) {
		t.Error("METRICS_ADDR=off should disable the metrics endpoint")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"[::1]:8080":      true,
		":8080":           false,
		"0.0.0.0:8080":    false,
		"192.168.1.10:80": false,
		"127.0.0.1":       true,
	}
	for addr, want := range tests {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// newTestServer serves the production handler with a captured logger.
func newTestServer(t *testing.T, mutate func(*config)) (*httptest.Server, *bytes.Buffer, *server) {
	t.Helper()
	var logs bytes.Buffer
	cfg := defaultConfig()
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if mutate != nil {
		mutate(&cfg)
	}
	srv := newServer(cfg)
	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return ts, &logs, srv
}

func signedTestEntry(t *testing.T) string {
	t.Helper()
	v := loadVector(t, "v2_single_testnet")
	return signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)
}

func postVerifyRaw(t *testing.T, url, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/verify", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting to /verify: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestVerifyRequiresBearerToken(t *testing.T) {
	const token = "correct-horse-battery-staple"
	ts, _, _ := newTestServer(t, func(c *config) { c.AuthToken = token })
	entry := signedTestEntry(t)
	body, err := json.Marshal(map[string]string{"entry": entry, "network": "testnet"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	for _, tt := range []struct {
		name  string
		token string
		want  int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "nope", http.StatusUnauthorized},
		{"right token", token, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, raw := postVerifyRaw(t, ts.URL, tt.token, string(body))
			if status != tt.want {
				t.Fatalf("status = %d, want %d: %s", status, tt.want, raw)
			}
			if tt.want == http.StatusUnauthorized {
				var out errorOutput
				if err := json.Unmarshal([]byte(raw), &out); err != nil || out.Error == "" {
					t.Errorf("401 body = %q, want an {\"error\"} object", raw)
				}
			}
		})
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	ts, _, _ := newTestServer(t, func(c *config) { c.AuthToken = "tok" })
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200 even with auth configured", resp.StatusCode)
	}
}

func TestBodyLimitIsConfigurable(t *testing.T) {
	ts, _, _ := newTestServer(t, func(c *config) { c.MaxBodyBytes = 32 })
	big := `{"entry":"` + strings.Repeat("A", 100) + `","network":"testnet"}`
	status, raw := postVerifyRaw(t, ts.URL, "", big)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", status, raw)
	}
	if !strings.Contains(raw, "32") {
		t.Errorf("413 body = %q, want it to name the 32-byte limit", raw)
	}
}

// TestVerifyReturns503AtConcurrencyBound holds the single slot open with a
// request whose body has not been sent, then proves the next request is refused
// with 503 rather than queued. The slot is taken before the body is read, which
// is what makes the bound hold against a slow upload.
func TestVerifyReturns503AtConcurrencyBound(t *testing.T) {
	ts, logs, srv := newTestServer(t, func(c *config) { c.MaxConcurrentRequests = 1 })

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/verify", pr)
	if err != nil {
		t.Fatalf("building the first request: %v", err)
	}
	first := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			first <- -1
			return
		}
		resp.Body.Close()
		first <- resp.StatusCode
	}()

	// Wait until the first handler has taken the only slot.
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.sem) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first request never took the concurrency slot")
		}
		time.Sleep(5 * time.Millisecond)
	}

	status, raw := postVerifyRaw(t, ts.URL, "", `{"entry":"x","network":"testnet"}`)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 at the concurrency bound: %s", status, raw)
	}
	if !strings.Contains(raw, "concurrent-request limit") {
		t.Errorf("503 body = %q, want it to explain the bound", raw)
	}
	if got := logs.String(); !strings.Contains(got, `"status":503`) {
		t.Errorf("refusal was not logged with its status; logs:\n%s", got)
	}

	// Release the first request and let it finish so the test leaves nothing
	// blocked.
	_, _ = pw.Write([]byte(`{}`))
	_ = pw.Close()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("the first request did not finish after its body was released")
	}
}

func TestRequestLogCarriesNoEntryOrSecret(t *testing.T) {
	const token = "super-secret-bearer-token"
	ts, logs, _ := newTestServer(t, func(c *config) { c.AuthToken = token })
	entry := signedTestEntry(t)
	body, err := json.Marshal(map[string]string{"entry": entry, "network": "testnet"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	if status, _ := postVerifyRaw(t, ts.URL, token, string(body)); status != http.StatusOK {
		t.Fatalf("authenticated verify status = %d, want 200", status)
	}
	// One refused request too, so the unauthorized path is also checked.
	if status, _ := postVerifyRaw(t, ts.URL, "wrong-"+token, string(body)); status != http.StatusUnauthorized {
		t.Fatalf("unauthorized verify status = %d, want 401", status)
	}

	got := logs.String()
	if strings.Contains(got, entry) {
		t.Error("the request log contains the entry bytes")
	}
	if strings.Contains(got, token) {
		t.Error("the request log contains the bearer token")
	}
	// The entry begins with the base64 of the XDR union tag; assert the raw
	// body fragment is absent too.
	if strings.Contains(got, `"entry"`) {
		t.Error("the request log contains the request body")
	}
	if !strings.Contains(got, `"route":"/verify"`) {
		t.Errorf("the request log is missing the route; logs:\n%s", got)
	}
	if !strings.Contains(got, `"status":401`) {
		t.Errorf("the refused request was not logged; logs:\n%s", got)
	}
}

func TestRecoveryTurnsPanicIntoJSON500(t *testing.T) {
	var logs bytes.Buffer
	cfg := defaultConfig()
	cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	srv := newServer(cfg)

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom from a handler")
	})
	ts := httptest.NewServer(srv.withRecovery(panicking))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/verify")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	var out errorOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Error == "" {
		t.Errorf("panic response was not a JSON error object: %v", err)
	}
	if !strings.Contains(logs.String(), "boom from a handler") {
		t.Errorf("the panic was not logged; logs:\n%s", logs.String())
	}
}

func TestMetricsEndpointIsSeparableFromTheAPIPort(t *testing.T) {
	srv := newServer(defaultConfig())

	// The API port has no /metrics route: the endpoint lives on its own
	// listener so it need not be exposed publicly.
	api := httptest.NewServer(srv.handler())
	defer api.Close()
	resp, err := http.Get(api.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics on the API port: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("the API port serves /metrics; it must be separable")
	}

	metrics := httptest.NewServer(srv.metricsHandler())
	defer metrics.Close()
	resp, err = http.Get(metrics.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics on the metrics port: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), metricRequests) {
		t.Errorf("metrics exposition does not mention %s:\n%s", metricRequests, raw)
	}
}

func TestRouteLabelIsClosed(t *testing.T) {
	tests := map[string]string{
		"/verify":         routeVerify,
		"/healthz":        routeHealthz,
		"/":               routeUnmatched,
		"/verify/secret":  routeUnmatched,
		"/../../etc/pass": routeUnmatched,
	}
	for path, want := range tests {
		if got := routeLabel(path); got != want {
			t.Errorf("routeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}
