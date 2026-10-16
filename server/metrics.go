package main

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/soroauth/soroauth-go"
)

// The metric names, documented here and in docs/verification-service.md. They
// are the contract a dashboard or alert reads; renaming one is a breaking
// change to an operator's monitoring, so the names live in one place.
const (
	metricRequests        = "soroauth_http_requests_total"
	metricRequestDuration = "soroauth_http_request_duration_seconds"
	metricVerdicts        = "soroauth_verify_verdicts_total"
	metricRefusals        = "soroauth_verify_refusals_total"
	metricSignerDuration  = "soroauth_signer_duration_seconds"
)

// Refusal reasons. The set is closed on purpose: a reason that is not listed is
// clamped to refusalOther rather than becoming a new label value. Verification
// refusals (invalid, cannot_check, unsigned, expiration_mismatch) and transport
// refusals (unauthorized, method_not_allowed, too_large, overloaded, internal,
// bad_request, not_found) share the metric so a single refusal rate is
// available, and the reason distinguishes them.
const (
	refusalInvalid            = "invalid"
	refusalCannotCheck        = "cannot_check"
	refusalUnsigned           = "unsigned"
	refusalExpirationMismatch = "expiration_mismatch"
	refusalUnauthorized       = "unauthorized"
	refusalMethodNotAllowed   = "method_not_allowed"
	refusalTooLarge           = "too_large"
	refusalOverloaded         = "overloaded"
	refusalInternal           = "internal"
	refusalBadRequest         = "bad_request"
	refusalNotFound           = "not_found"
	refusalOther              = "other"
)

// serviceMetrics holds one process's collectors. A private registry (rather
// than the default one) means a test can build many servers without a
// duplicate-registration panic, and the metrics endpoint serves exactly this
// registry.
type serviceMetrics struct {
	registry        *prometheus.Registry
	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	verdicts        *prometheus.CounterVec
	refusals        *prometheus.CounterVec
	signerDuration  *prometheus.HistogramVec
}

// newServiceMetrics builds the collectors and registers them. Every collector
// name and label is spelled out here, so the closed-label-set test can assert
// against the same tables the code uses.
func newServiceMetrics() *serviceMetrics {
	registry := prometheus.NewRegistry()
	m := &serviceMetrics{
		registry: registry,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRequests,
			Help: "HTTP requests handled, by method, route and response status.",
		}, []string{"method", "route", "status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    metricRequestDuration,
			Help:    "HTTP request latency in seconds, by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		verdicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricVerdicts,
			Help: "Credential-node verification verdicts, by credential type and verdict.",
		}, []string{"credential_type", "verdict"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricRefusals,
			Help: "Verification and request refusals, by reason.",
		}, []string{"reason"}),
		signerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    metricSignerDuration,
			Help:    "Signing phase latency in seconds, fed by soroauth.Hook events. Empty unless the service is used for signing.",
			Buckets: prometheus.DefBuckets,
		}, []string{"phase", "credential_type"}),
	}
	registry.MustRegister(m.requests, m.requestDuration, m.verdicts, m.refusals, m.signerDuration)
	return m
}

// handler serves the Prometheus exposition. It is mounted on its own listener
// so the API port does not have to expose it.
func (m *serviceMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *serviceMetrics) recordRequest(method, route string, status int, d time.Duration) {
	method = clamp(labelMethods, method, "other")
	route = clamp(labelRoutes, route, routeUnmatched)
	st := strconv.Itoa(status)
	st = clamp(labelStatuses, st, "other")
	m.requests.WithLabelValues(method, route, st).Inc()
	m.requestDuration.WithLabelValues(route).Observe(d.Seconds())
}

func (m *serviceMetrics) recordVerdict(credentialType, verdict string) {
	credentialType = clamp(labelCredentialTypes, credentialType, "unknown")
	verdict = clamp(labelVerdicts, verdict, "unknown")
	m.verdicts.WithLabelValues(credentialType, verdict).Inc()
}

func (m *serviceMetrics) recordRefusal(reason string) {
	m.refusals.WithLabelValues(clamp(labelRefusalReasons, reason, refusalOther)).Inc()
}

// recordRefusalReason classifies an error response by its status so every
// refusal is counted with a reason, without the handler passing a string at
// each call site.
func (m *serviceMetrics) recordRefusalReason(status int) {
	switch status {
	case http.StatusUnauthorized:
		m.recordRefusal(refusalUnauthorized)
	case http.StatusMethodNotAllowed:
		m.recordRefusal(refusalMethodNotAllowed)
	case http.StatusRequestEntityTooLarge:
		m.recordRefusal(refusalTooLarge)
	case http.StatusServiceUnavailable:
		m.recordRefusal(refusalOverloaded)
	case http.StatusInternalServerError:
		m.recordRefusal(refusalInternal)
	case http.StatusNotFound:
		m.recordRefusal(refusalNotFound)
	case http.StatusBadRequest:
		m.recordRefusal(refusalBadRequest)
	default:
		m.recordRefusal(refusalOther)
	}
}

// observeSigner records one signing phase's duration. Called from the Hook
// adapter, which is the only writer, so there is one event source.
func (m *serviceMetrics) observeSigner(phase, credentialType string, d time.Duration) {
	phase = clamp(labelPhases, phase, "unknown")
	credentialType = clamp(labelCredentialTypes, credentialType, "unknown")
	m.signerDuration.WithLabelValues(phase, credentialType).Observe(d.Seconds())
}

// hookMetrics adapts soroauth.Hook to the signer-latency metric. It is the
// bridge the metrics work asks for: metric values come from the hook event
// stream rather than from instrumenting a signing path separately. The
// verification service does not sign today, so the histogram stays empty until
// signing is added and this hook is passed to the signing call; the library
// itself gains no metrics dependency.
type hookMetrics struct {
	metrics *serviceMetrics
}

// Event implements soroauth.Hook.
func (h hookMetrics) Event(_ context.Context, e soroauth.HookEvent) error {
	switch e.Phase {
	case soroauth.HookPhaseSign, soroauth.HookPhasePostSign:
		if e.Duration > 0 {
			h.metrics.observeSigner(string(e.Phase), e.CredentialType, e.Duration)
		}
	}
	return nil
}

// hook returns the metrics Hook a signing deployment would pass to
// soroauth.AuthorizeEntry.
func (s *server) hook() soroauth.Hook {
	return hookMetrics{metrics: s.metrics}
}

// The closed label-value sets. clamp maps anything outside to a fallback, so a
// stray value can never create a new series. The tests assert against these
// same tables, which is what makes "the label sets are closed" a property of
// the code rather than a claim.
var (
	labelMethods         = setOf(http.MethodGet, http.MethodPost, "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
	labelRoutes          = setOf(routeVerify, routeHealthz, routeUnmatched)
	labelStatuses        = setOf("200", "400", "401", "404", "405", "413", "500", "503")
	labelCredentialTypes = setOf(
		soroauth.CredentialTypeSourceAccount,
		soroauth.CredentialTypeAddress,
		soroauth.CredentialTypeAddressV2,
		soroauth.CredentialTypeAddressWithDelegates,
		"unknown",
	)
	labelVerdicts = setOf(
		string(soroauth.VerdictVerified),
		string(soroauth.VerdictUnsigned),
		string(soroauth.VerdictInvalid),
		string(soroauth.VerdictCannotCheck),
		"unknown",
	)
	labelRefusalReasons = setOf(
		refusalInvalid, refusalCannotCheck, refusalUnsigned, refusalExpirationMismatch,
		refusalUnauthorized, refusalMethodNotAllowed, refusalTooLarge, refusalOverloaded,
		refusalInternal, refusalBadRequest, refusalNotFound, refusalOther,
	)
	labelPhases = setOf(
		string(soroauth.HookPhasePreimage),
		string(soroauth.HookPhaseSign),
		string(soroauth.HookPhasePostSign),
		string(soroauth.HookPhaseWrite),
		"unknown",
	)
)

func setOf(values ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return m
}

func clamp(allowed map[string]struct{}, value, fallback string) string {
	if _, ok := allowed[value]; ok {
		return value
	}
	return fallback
}
