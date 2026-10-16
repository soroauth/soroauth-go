package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// verifyRequest is the JSON request body for POST /verify.
type verifyRequest struct {
	// Entry is the base64 authorization entry or transaction envelope.
	Entry string `json:"entry"`
	// Network is testnet, futurenet, public, or a literal network passphrase.
	Network string `json:"network"`
	// ValidUntilLedger is an optional assertion of the expiration the entry
	// carries. The payload is always rebuilt from the entry's own stored
	// expiration; a disagreement is an error, never an override.
	ValidUntilLedger uint32 `json:"valid_until_ledger,omitempty"`
}

// nodeOutput is one credential node's verdict in the JSON report. Its shape is
// deliberately identical to the CLI's verify output, so a client parses one
// schema for both.
type nodeOutput struct {
	Address string `json:"address"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// entryOutput is one entry's verification report in the JSON output,
// identical to the CLI's verify output.
type entryOutput struct {
	OperationIndex   int          `json:"operation_index,omitempty"`
	EntryIndex       int          `json:"entry_index,omitempty"`
	CredentialType   string       `json:"credential_type"`
	AddressBound     bool         `json:"address_bound"`
	Address          string       `json:"address,omitempty"`
	ValidUntilLedger uint32       `json:"valid_until_ledger,omitempty"`
	Verified         bool         `json:"verified"`
	Nodes            []nodeOutput `json:"nodes"`
	Note             string       `json:"note,omitempty"`
}

// errorOutput is the failure body. It matches the CLI's --json error object.
type errorOutput struct {
	Error string `json:"error"`
}

// server owns the routes, the concurrency bound and the metrics for one
// process. It is a struct rather than a set of package functions so a test can
// build one with a different configuration — an auth token, a smaller
// concurrency bound, a captured logger — and serve exactly the production
// handlers.
type server struct {
	cfg     config
	metrics *serviceMetrics
	// sem bounds in-flight /verify requests. A slot is taken before the body
	// is read, so a slow or stalled upload cannot pile up past the bound.
	sem chan struct{}
}

// newServer builds a server from a resolved configuration. Every dependency the
// handlers need is on the struct, so no handler reads the environment.
func newServer(cfg config) *server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &server{
		cfg:     cfg,
		metrics: newServiceMetrics(),
		sem:     make(chan struct{}, cfg.MaxConcurrentRequests),
	}
}

// handler wires the routes and the request-level middleware. It is a
// constructor rather than inline in main so the integration tests serve the
// exact same routes over httptest.
//
// Middleware order is recovery inside logging, so a recovered panic still
// produces one log line with the 500 it returned: logging( recovery( mux ) ).
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthzHandler)
	mux.HandleFunc("/verify", s.verifyHandler)

	var h http.Handler = mux
	h = s.withRecovery(h)
	h = s.withRequestLogging(h)
	return h
}

// newMux serves the default configuration. It is what the pre-existing
// integration tests call; production uses newServer(cfg).handler().
func newMux() http.Handler {
	return newServer(defaultConfig()).handler()
}

// metricsHandler serves the Prometheus exposition on its own listener. It is
// deliberately separable from the API so an operator can keep it on loopback
// or a private network rather than exposing it with /verify.
func (s *server) metricsHandler() http.Handler {
	return s.metrics.handler()
}

func (s *server) healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}

// verifyHandler answers one question about each entry it is handed: do the
// signatures already on it verify over the payload it commits to?
//
// The verdicts are the CLI's: verified, unsigned, invalid, cannot_check, one
// per credential node, in the CLI's JSON shape — a single object for one
// entry, an array carrying operation_index and entry_index for an envelope.
// A verification that completes is HTTP 200 whatever the verdicts say: the
// verdicts are the answer, and a body that says "invalid" is not a transport
// failure. That maps to the CLI's exit code 4, which likewise fires after the
// report is printed. Only a request the service cannot verify — malformed
// JSON, a missing field, an undecodable entry, an engine error, or a
// valid_until_ledger assertion the entry contradicts — is 4xx with an
// {"error"} body and no report.
//
// Before any of that, the request must clear authentication (when configured)
// and take one of the bounded concurrency slots. Either refusal is a transport
// failure with an {"error"} body, not a verdict.
func (s *server) verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.authorized(r) {
		s.writeError(w, r, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}

	// Bound concurrency fail-fast rather than queue: a request that would
	// exceed the bound is refused so the caller can retry, instead of every
	// in-flight request getting slower until the timeout.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		w.Header().Set("Retry-After", "1")
		s.writeError(w, r, http.StatusServiceUnavailable,
			"service is at its concurrent-request limit; retry shortly")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// An oversize body is reported as 413 rather than 400: the request
		// was well-formed but too large, so retrying it unchanged can never
		// succeed and the caller should know why at a glance.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, r, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body exceeds the %d-byte limit", s.cfg.MaxBodyBytes))
			return
		}
		s.writeError(w, r, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}

	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}
	if req.Entry == "" {
		s.writeError(w, r, http.StatusBadRequest, "entry is required")
		return
	}
	passphrase, err := resolveNetwork(req.Network)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	input, err := decodeEntryOrEnvelope(req.Entry)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())
		return
	}

	type located struct {
		entry          xdr.SorobanAuthorizationEntry
		operationIndex int
		entryIndex     int
	}
	var locatedEntries []located
	if input.isEnvelope {
		entries, err := soroauth.EnvelopeEntries(input.envelope)
		if err != nil {
			s.writeError(w, r, http.StatusBadRequest, "envelope has no authorization entries: "+err.Error())
			return
		}
		for _, e := range entries {
			locatedEntries = append(locatedEntries, located{entry: e.Entry, operationIndex: e.OperationIndex, entryIndex: e.EntryIndex})
		}
	} else {
		locatedEntries = append(locatedEntries, located{entry: input.entry})
	}

	outputs := make([]entryOutput, 0, len(locatedEntries))
	for _, item := range locatedEntries {
		report, err := soroauth.VerifyEntry(item.entry, passphrase)
		if err != nil {
			s.writeError(w, r, http.StatusBadRequest, "verification failed: "+err.Error())
			return
		}
		if req.ValidUntilLedger != 0 && report.ValidUntilLedger != req.ValidUntilLedger {
			s.metrics.recordRefusal(refusalExpirationMismatch)
			s.writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("entry carries expiration %d, but valid_until_ledger says %d",
					report.ValidUntilLedger, req.ValidUntilLedger))
			return
		}
		out := newEntryOutput(report)
		if input.isEnvelope {
			out.OperationIndex = item.operationIndex + 1
			out.EntryIndex = item.entryIndex + 1
		}
		s.recordVerdicts(report)
		outputs = append(outputs, out)
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if input.isEnvelope {
		_ = enc.Encode(outputs)
	} else {
		_ = enc.Encode(outputs[0])
	}
}

// recordVerdicts feeds the verdict and refusal counters from one report. A
// non-verified node is a refusal and is counted with the reason that names why,
// so the two series always agree.
func (s *server) recordVerdicts(report soroauth.VerificationReport) {
	for _, node := range report.Nodes {
		s.metrics.recordVerdict(report.CredentialType, string(node.Verdict))
		switch node.Verdict {
		case soroauth.VerdictVerified:
		case soroauth.VerdictInvalid:
			s.metrics.recordRefusal(refusalInvalid)
		case soroauth.VerdictCannotCheck:
			s.metrics.recordRefusal(refusalCannotCheck)
		case soroauth.VerdictUnsigned:
			s.metrics.recordRefusal(refusalUnsigned)
		}
	}
}

// authorized applies the bearer-token check. With no configured token the
// check is a no-op, which loadConfig only permits on a loopback bind.
func (s *server) authorized(r *http.Request) bool {
	if s.cfg.AuthToken == "" {
		return true
	}
	got := r.Header.Get("Authorization")
	want := "Bearer " + s.cfg.AuthToken
	// Constant time so a caller cannot recover the token by timing guesses.
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// writeError writes the JSON error body and counts it. The status is the only
// classification: the message never echoes request bytes.
func (s *server) writeError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.metrics.recordRefusalReason(status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorOutput{Error: msg})
}

// newEntryOutput converts a library report into the CLI's JSON shape.
func newEntryOutput(report soroauth.VerificationReport) entryOutput {
	out := entryOutput{
		CredentialType:   report.CredentialType,
		AddressBound:     report.AddressBound,
		Address:          report.Address,
		ValidUntilLedger: report.ValidUntilLedger,
		Verified:         report.Verified(),
		Note:             report.Note,
		Nodes:            make([]nodeOutput, 0, len(report.Nodes)),
	}
	for _, node := range report.Nodes {
		out.Nodes = append(out.Nodes, nodeOutput{
			Address: node.Address,
			Verdict: string(node.Verdict),
			Reason:  node.Reason,
		})
	}
	return out
}

// resolveNetwork turns the network field into a passphrase. The three named
// networks are shorthands resolved from the SDK's constants — the same source
// the CLI uses, so the two cannot drift; anything else is a literal
// passphrase, so a standalone network works without this service knowing
// about it.
func resolveNetwork(value string) (string, error) {
	switch value {
	case "":
		return "", errors.New("network is required (testnet, futurenet, public, or a literal passphrase)")
	case "testnet":
		return network.TestNetworkPassphrase, nil
	case "futurenet":
		return network.FutureNetworkPassphrase, nil
	case "public":
		return network.PublicNetworkPassphrase, nil
	default:
		return value, nil
	}
}

// decodedInput is a base64 blob that was either an authorization entry or a
// transaction envelope, together with which of the two it turned out to be.
type decodedInput struct {
	entry      xdr.SorobanAuthorizationEntry
	envelope   xdr.TransactionEnvelope
	isEnvelope bool
}

// decodeEntryOrEnvelope reads the entry field, which accepts either shape.
//
// Both are base64 XDR unions whose first bytes can overlap, so a blob is
// tried against both and judged on what it decodes to: an envelope only wins
// when it decodes and carries entries to authorize, which an authorization
// entry never looks like. Anything else that fails both readings gets the
// entry error, since the field has always meant an entry first. This mirrors
// the CLI's --entry handling, which is what keeps the verdicts identical.
func decodeEntryOrEnvelope(value string) (decodedInput, error) {
	var envelope xdr.TransactionEnvelope
	envelopeErr := xdr.SafeUnmarshalBase64(value, &envelope)

	var entry xdr.SorobanAuthorizationEntry
	entryErr := xdr.SafeUnmarshalBase64(value, &entry)

	if envelopeErr == nil {
		if entries, err := soroauth.EnvelopeEntries(envelope); err == nil && len(entries) > 0 {
			return decodedInput{envelope: envelope, isEnvelope: true}, nil
		} else if entryErr != nil {
			return decodedInput{}, fmt.Errorf("decoding entry as an envelope: %w", err)
		}
	}

	if entryErr != nil {
		return decodedInput{}, fmt.Errorf("decoding entry: %w", entryErr)
	}
	return decodedInput{entry: entry}, nil
}

// statusRecorder captures the status and byte count a handler produced so the
// request log line can report them without a second wrapper per route.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// withRequestLogging emits one structured line per request. It logs the method,
// the matched route, the status, the duration and the response size — never the
// request body, the entry, the Authorization header or the bearer token. The
// path is logged as the route template rather than the raw path, so a request
// to an unknown path cannot smuggle bytes into the log either.
func (s *server) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		s.metrics.recordRequest(r.Method, routeLabel(r.URL.Path), rec.status, time.Since(start))
		s.cfg.Logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
			slog.String("method", r.Method),
			slog.String("route", routeLabel(r.URL.Path)),
			slog.Int("status", rec.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.Int("bytes", rec.bytes),
			slog.String("remote_addr", r.RemoteAddr),
		)
	})
}

// withRecovery keeps a panic in one request from taking down the process: it
// is logged and turned into a JSON 500. The panic value is logged, not the
// request body.
func (s *server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.cfg.Logger.Error("panic recovered",
					"error", fmt.Sprint(v),
					"route", routeLabel(r.URL.Path),
					"method", r.Method,
					"stack", string(debug.Stack()))
				s.metrics.recordRefusal(refusalInternal)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(errorOutput{Error: "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// routeLabel maps a request path to the closed set of route labels the metrics
// and logs use. Anything else is "unmatched", which keeps an arbitrary path
// from becoming a high-cardinality label or a log-injection vector.
func routeLabel(path string) string {
	switch path {
	case "/verify":
		return routeVerify
	case "/healthz":
		return routeHealthz
	default:
		return routeUnmatched
	}
}

// routeVerify and friends are the closed route-label set. They are constants so
// a typo is a compile error rather than a new series.
const (
	routeVerify    = "/verify"
	routeHealthz   = "/healthz"
	routeUnmatched = "unmatched"
)
