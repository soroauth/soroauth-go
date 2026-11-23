package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCallerLimiterRefillsOnTheInterval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newCallerLimiter(2, 3, time.Second)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, retry := l.allow("caller"); !ok {
			t.Fatalf("request %d refused with retry %v; the burst is 3", i+1, retry)
		}
	}
	ok, retry := l.allow("caller")
	if ok {
		t.Fatal("the fourth request was allowed; the burst is 3")
	}
	if retry != time.Second {
		t.Errorf("retry = %v, want one interval", retry)
	}

	// A different caller has its own bucket and is unaffected.
	if ok, _ := l.allow("other"); !ok {
		t.Error("a second caller was refused; buckets are not independent")
	}

	now = now.Add(time.Second)
	if ok, retry := l.allow("caller"); !ok {
		t.Fatalf("the caller was still refused after one interval: retry %v", retry)
	}
	// One refill adds rate tokens (2), capped by the burst (3). Two remain.
	if ok, _ := l.allow("caller"); !ok {
		t.Error("the second refilled token was not available")
	}
}

func TestCallerLimiterSweepsIdleBuckets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newCallerLimiter(1, 1, time.Second)
	l.now = func() time.Time { return now }
	l.idleFor = time.Second

	if ok, _ := l.allow("gone"); !ok {
		t.Fatal("the first request was refused")
	}
	if len(l.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(l.buckets))
	}

	now = now.Add(3 * time.Minute)
	if ok, _ := l.allow("fresh"); !ok {
		t.Fatal("the fresh request was refused")
	}
	if _, kept := l.buckets["gone"]; kept {
		t.Error("an idle bucket survived the sweep")
	}
	if _, kept := l.buckets["fresh"]; !kept {
		t.Error("the sweep removed an active bucket")
	}
}

func TestCallerIdentityNeverContainsTheToken(t *testing.T) {
	const token = "super-secret-bearer-token"
	r := httptest.NewRequest(http.MethodPost, "/verify", nil)
	r.RemoteAddr = "203.0.113.9:4321"

	if got := callerIdentity(r, ""); got != "addr:203.0.113.9" {
		t.Errorf("identity without a token = %q, want the peer host", got)
	}
	got := callerIdentity(r, token)
	if strings.Contains(got, token) {
		t.Errorf("identity %q contains the bearer token", got)
	}
	if got == callerIdentity(r, "another-token") {
		t.Error("two distinct tokens produced the same identity")
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	tests := []struct {
		wait time.Duration
		want int
	}{
		{0, 1},
		{time.Millisecond, 1},
		{999 * time.Millisecond, 1},
		{time.Second, 1},
		{time.Second + time.Millisecond, 2},
		{2500 * time.Millisecond, 3},
	}
	for _, tt := range tests {
		if got := retryAfterSeconds(tt.wait); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tt.wait, got, tt.want)
		}
	}
}

// TestRateLimitRefusesBeforeDecoding proves the refusal ordering the issue calls
// for: the second request is refused with 429 even though its body is a valid
// entry, because the limiter is consulted before the body is read. If the limit
// ran after decoding it would not protect the expensive part.
func TestRateLimitRefusesBeforeDecoding(t *testing.T) {
	ts, _, srv := newTestServer(t, func(c *config) {
		c.RateLimitPerSecond = 1
		c.RateLimitBurst = 1
	})
	entry := signedTestEntry(t)
	body, err := json.Marshal(map[string]string{"entry": entry, "network": "testnet"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	// The first request spends the only token. It is malformed so the handler
	// returns 400 without a successful verification.
	if status, raw := postVerifyRaw(t, ts.URL, "", `{"network":"testnet"}`); status != http.StatusBadRequest {
		t.Fatalf("first status = %d, want 400: %s", status, raw)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/verify", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building the refused request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting the refused request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Retry-After"); got == "" || got == "0" {
		t.Errorf("Retry-After = %q, want a positive hint", got)
	}
	if !strings.Contains(string(raw), "rate limit") {
		t.Errorf("429 body = %q, want it to name the rate limit", raw)
	}

	// The rejection is counted under both the limit metric and the refusal
	// reason, so the two dashboards agree.
	families := gatherFamilies(t, srv)
	if got := counterValue(t, families, metricLimitRejections, map[string]string{"limit": limitRate}); got != 1 {
		t.Errorf("rate limit rejections = %v, want 1", got)
	}
	if got := counterValue(t, families, metricRefusals, map[string]string{"reason": refusalRateLimited}); got != 1 {
		t.Errorf("rate_limited refusals = %v, want 1", got)
	}
	if got := counterValue(t, families, metricRequests, map[string]string{
		"route": routeVerify, "status": "429",
	}); got != 1 {
		t.Errorf("429 requests on /verify = %v, want 1", got)
	}

	// Health checks are outside the limit: a load balancer must still be able
	// to ask whether the process is alive while one caller is being shed.
	if status, raw := getHealthz(t, ts.URL); status != http.StatusOK {
		t.Errorf("healthz status = %d during a rate limit, want 200: %s", status, raw)
	}
}

// TestRateLimitIsPerCallerToken proves two configured bearer tokens are two
// identities: exhausting one does not spend the other's quota.
func TestRateLimitIsPerCallerToken(t *testing.T) {
	const alpha, beta = "alpha-token", "beta-token"
	ts, _, _ := newTestServer(t, func(c *config) {
		c.AuthTokens = []string{alpha, beta}
		c.RateLimitPerSecond = 1
		c.RateLimitBurst = 1
	})

	// Each caller's first request spends its token and gets 400 for the
	// malformed body; the second is shed.
	if status, raw := postVerifyRaw(t, ts.URL, alpha, `{"network":"testnet"}`); status != http.StatusBadRequest {
		t.Fatalf("alpha's first status = %d, want 400: %s", status, raw)
	}
	if status, raw := postVerifyRaw(t, ts.URL, alpha, `{"network":"testnet"}`); status != http.StatusTooManyRequests {
		t.Fatalf("alpha's second status = %d, want 429: %s", status, raw)
	}
	if status, raw := postVerifyRaw(t, ts.URL, beta, `{"network":"testnet"}`); status != http.StatusBadRequest {
		t.Fatalf("beta's first status = %d, want 400; alpha's limit leaked: %s", status, raw)
	}
}

// TestServiceStaysResponsivePastEveryLimit drives the service past the
// concurrency and rate bounds and then proves a fresh caller and /healthz still
// get timely answers. That is the acceptance criterion: the service sheds load
// rather than becoming unresponsive.
func TestServiceStaysResponsivePastEveryLimit(t *testing.T) {
	const blocked, fresh = "blocked-token", "fresh-token"
	ts, _, srv := newTestServer(t, func(c *config) {
		c.AuthTokens = []string{blocked, fresh}
		c.MaxConcurrentRequests = 1
		c.RateLimitPerSecond = 2
		c.RateLimitBurst = 2
	})

	// Hold the only concurrency slot with a request whose body never arrives.
	pr, pw := io.Pipe()
	hold, err := http.NewRequest(http.MethodPost, ts.URL+"/verify", pr)
	if err != nil {
		t.Fatalf("building the held request: %v", err)
	}
	hold.Header.Set("Authorization", "Bearer "+blocked)
	go func() {
		resp, err := http.DefaultClient.Do(hold)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for len(srv.sem) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(srv.sem) == 0 {
		t.Fatal("the held request never took the concurrency slot")
	}

	// Spend the blocked caller's rate budget and observe a 429, proving both
	// bounds are active at once.
	var sawRateLimit bool
	for i := 0; i < 5; i++ {
		status, _ := postVerifyRaw(t, ts.URL, blocked, `{"network":"testnet"}`)
		if status == http.StatusTooManyRequests {
			sawRateLimit = true
			break
		}
	}
	if !sawRateLimit {
		t.Error("never observed a 429 while the concurrency slot was held")
	}

	// The service answers health checks and a different caller promptly.
	start := time.Now()
	status, raw := getHealthz(t, ts.URL)
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200: %s", status, raw)
	}
	if status, raw := postVerifyRaw(t, ts.URL, fresh, `{"network":"testnet"}`); status != http.StatusServiceUnavailable {
		t.Fatalf("fresh caller status = %d, want 503 from the concurrency bound: %s", status, raw)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("responses took %v while shedding load; the service is not responsive", elapsed)
	}

	_ = pw.Close()
}

func getHealthz(t *testing.T, base string) (int, string) {
	t.Helper()
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}
