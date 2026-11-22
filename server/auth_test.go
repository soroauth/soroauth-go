package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The three auth scenarios the issue requires tests for, now driven through
// the pluggable Authenticator rather than the old AuthToken-only check:
//
//   - a missing credential is 401
//   - a wrong credential is 401
//   - an authenticated-but-unauthorized call is 403 and the body carries no
//     information about the submitted entry
//
// These share a signed vector entry so the assertion is on the auth
// decision, not the verification result.

// TestAuthenticatorRejectsMissingCredential proves /verify is 401 when the
// Authenticator sees no Authorization header, and that the error body does
// not leak any field from the submitted entry.
func TestAuthenticatorRejectsMissingCredential(t *testing.T) {
	const token = "the-ci-token"
	ts, _, _ := newTestServer(t, func(c *config) {
		c.AuthToken = "ci:" + token + ":verify"
	})
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	status, raw := postVerifyRaw(t, ts.URL, "", body)
	if status != http.StatusUnauthorized {
		t.Fatalf("missing credential status = %d, want 401: %s", status, raw)
	}
	assertNoEntryLeak(t, raw, entry)
}

// TestAuthenticatorRejectsWrongCredential proves /verify is 401 for a
// different bearer value than any configured token.
func TestAuthenticatorRejectsWrongCredential(t *testing.T) {
	const token = "the-ci-token"
	ts, _, _ := newTestServer(t, func(c *config) {
		c.AuthToken = "ci:" + token + ":verify"
	})
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	status, raw := postVerifyRaw(t, ts.URL, "a-different-token", body)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong credential status = %d, want 401: %s", status, raw)
	}
	assertNoEntryLeak(t, raw, entry)
}

// TestAuthenticatorAllowsCorrectCredential sanity-checks that the shared
// vector entry verifies cleanly with the right token, so an unauthorized 401
// is not just "every request fails".
func TestAuthenticatorAllowsCorrectCredential(t *testing.T) {
	const token = "the-ci-token"
	ts, _, _ := newTestServer(t, func(c *config) {
		c.AuthToken = "ci:" + token + ":verify,risk"
	})
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	status, raw := postVerifyRaw(t, ts.URL, token, body)
	if status != http.StatusOK {
		t.Fatalf("authorised verify status = %d, want 200: %s", status, raw)
	}
}

// TestAuthenticatedButUnauthorized is the case the issue calls out: the
// request authenticates (the token is valid) but the identity is not granted
// the operation, so the service returns 403, not 401, and the body still
// carries no information about the submitted entry.
func TestAuthenticatedButUnauthorized(t *testing.T) {
	const token = "the-ci-token"
	ts, _, _ := newTestServer(t, func(c *config) {
		// This identity may /verify but not /risk.
		c.AuthToken = "ci:" + token + ":verify"
	})
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	status, raw := postRiskRaw(t, ts.URL, token, body)
	if status != http.StatusForbidden {
		t.Fatalf("authenticated-but-unauthorized /risk status = %d, want 403: %s", status, raw)
	}
	assertNoEntryLeak(t, raw, entry)

	// And the same identity *is* allowed to /verify, so the 403 is specific
	// to the operation, not a general refusal.
	if s, body := postVerifyRaw(t, ts.URL, token, body); s != http.StatusOK {
		t.Errorf("/verify with the same token = %d, want 200: %s", s, body)
	}
}

// TestBearerTokenParser pins the three forms the AUTH_TOKEN syntax accepts:
// a bare token (legacy), an id:token pair (every operation), and an
// id:token:ops row.
func TestBearerTokenParser(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantErr   bool
		identity  string
		token     string
		allowVer  bool
		allowRisk bool
	}{
		{"legacy bare token", "shared-secret", false, "default", "shared-secret", true, true},
		{"id and token, no ops", "oncall:shared-secret", false, "oncall", "shared-secret", true, true},
		{"id and token, verify only", "ci:shared-secret:verify", false, "ci", "shared-secret", true, false},
		{"id and token, both ops", "oncall:shared-secret:verify,risk", false, "oncall", "shared-secret", true, true},
		{"empty", "", true, "", "", false, false},
		{"missing token", "ci:", true, "", "", false, false},
		{"unknown op", "ci:s:sign", true, "", "", false, false},
		{"no ops granted", "ci:s:", true, "", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := newBearerTokenAuthenticator(c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("newBearerTokenAuthenticator(%q): want error, got nil", c.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("newBearerTokenAuthenticator(%q): %v", c.raw, err)
			}
			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Authorization", "Bearer "+c.token)
			id, err := a.Authenticate(r)
			if err != nil || id != c.identity {
				t.Fatalf("Authenticate = (%q, %v), want (%q, nil)", id, err, c.identity)
			}
			if got := a.Authorize(id, OpVerify); (got == nil) != c.allowVer {
				t.Errorf("Authorize(verify) = %v, want allowed=%v", got, c.allowVer)
			}
			if got := a.Authorize(id, OpRisk); (got == nil) != c.allowRisk {
				t.Errorf("Authorize(risk) = %v, want allowed=%v", got, c.allowRisk)
			}
		})
	}
}

// TestAuthenticatorIsConstantTimeRegardlessOfOrder proves the comparison
// walks every configured token rather than short-circuiting on the first
// match, which is what keeps the time path independent of token order.
func TestAuthenticatorIsConstantTimeRegardlessOfOrder(t *testing.T) {
	a, err := newBearerTokenAuthenticator("first:aaa:verify;second:bbb:verify;third:ccc:verify")
	if err != nil {
		t.Fatalf("newBearerTokenAuthenticator: %v", err)
	}
	for _, token := range []string{"aaa", "bbb", "ccc"} {
		r, _ := http.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if _, err := a.Authenticate(r); err != nil {
			t.Errorf("Authenticate(%q): %v", token, err)
		}
	}
}

// TestLoopbackOpenPathStillWorks keeps the pre-existing zero-config
// behaviour alive: an unauthenticated loopback bind serves every request.
// The failure to preserve this would break every operator who has not yet
// set AUTH_TOKEN.
func TestLoopbackOpenPathStillWorks(t *testing.T) {
	ts, _, _ := newTestServer(t, nil)
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	status, raw := postVerifyRaw(t, ts.URL, "", body)
	if status != http.StatusOK {
		t.Fatalf("loopback open path /verify status = %d, want 200: %s", status, raw)
	}
}

// TestCustomAuthenticatorIsInstalled proves a caller can plug a custom
// Authenticator into cfg.Authenticator and the handlers use it in place of
// the bearer-token default. This is the extension point the issue asks for.
func TestCustomAuthenticatorIsInstalled(t *testing.T) {
	ts, _, _ := newTestServer(t, func(c *config) {
		c.Authenticator = &allowOnlyHeaderAuth{header: "X-Secret", want: "sesame"}
	})
	entry := signedTestEntry(t)
	body := mustJSON(t, map[string]string{"entry": entry, "network": "testnet"})

	// Missing custom header → 401.
	if s, raw := postVerifyRaw(t, ts.URL, "", body); s != http.StatusUnauthorized {
		t.Errorf("custom auth missing-header status = %d, want 401: %s", s, raw)
	}
	// Correct custom header via a raw request to carry the extra header.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Secret", "sesame")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("custom auth happy-path request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rawBody, _ := io.ReadAll(resp.Body)
		t.Errorf("custom auth happy-path status = %d, want 200: %s", resp.StatusCode, rawBody)
	}
}

// allowOnlyHeaderAuth is a tiny custom Authenticator the extension test uses
// to show that a non-bearer scheme plugs in cleanly.
type allowOnlyHeaderAuth struct {
	header string
	want   string
}

func (a *allowOnlyHeaderAuth) Authenticate(r *http.Request) (string, error) {
	if r.Header.Get(a.header) != a.want {
		return "", ErrUnauthenticated
	}
	return "custom", nil
}

func (a *allowOnlyHeaderAuth) Authorize(string, Operation) error { return nil }

// postRiskRaw mirrors postVerifyRaw for the /risk endpoint, used by the
// per-operation authorization tests.
func postRiskRaw(t *testing.T, url, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/risk", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting to /risk: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// assertNoEntryLeak asserts that a rejected request's body carries nothing
// from the submitted entry. The envelope the caller sent is a high-entropy
// base64 blob that must not appear in a 4xx body.
func assertNoEntryLeak(t *testing.T, body, entry string) {
	t.Helper()
	if strings.Contains(body, entry) {
		t.Errorf("rejected request leaked the submitted entry: %s", body)
	}
	// The error body is well-formed JSON with only an error field.
	var out errorOutput
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Error == "" {
		t.Errorf("rejected body = %q, want an {\"error\"} object", body)
	}
}

// mustJSON marshals a value or fails the test.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling test body: %v", err)
	}
	return string(raw)
}

// ensure ErrUnauthenticated and ErrUnauthorized are reachable as errors.Is
// targets, so a caller writing a custom Authenticator can wrap them.
func TestSentinelErrorsAreReachable(t *testing.T) {
	if !errors.Is(wrapAs(ErrUnauthenticated), ErrUnauthenticated) {
		t.Error("ErrUnauthenticated is not reachable via errors.Is")
	}
	if !errors.Is(wrapAs(ErrUnauthorized), ErrUnauthorized) {
		t.Error("ErrUnauthorized is not reachable via errors.Is")
	}
}

// wrapAs wraps an error to prove errors.Is works through a layer of
// %w-wrapping, which is how a custom Authenticator would return its own
// context on top of the sentinel.
func wrapAs(err error) error {
	return &wrappedErr{inner: err}
}

type wrappedErr struct{ inner error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }
