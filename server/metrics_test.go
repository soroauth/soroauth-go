package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/soroauth/soroauth-go"
)

// knownMetrics is the closed set of metric families the service exposes.
var knownMetrics = map[string]struct{}{
	metricRequests:        {},
	metricRequestDuration: {},
	metricVerdicts:        {},
	metricRefusals:        {},
	metricSignerDuration:  {},
}

// allowedLabels maps every label name the service may emit to the closed set of
// values it may carry. A label that is not here, or a value outside its set,
// fails the test: that is the "label sets are closed" property, and it is what
// stops an address, a nonce or a reason string from becoming a Prometheus
// cardinality bomb.
var allowedLabels = map[string]map[string]struct{}{
	"method":          labelMethods,
	"route":           labelRoutes,
	"status":          labelStatuses,
	"credential_type": labelCredentialTypes,
	"verdict":         labelVerdicts,
	"reason":          labelRefusalReasons,
	"phase":           labelPhases,
}

// exerciseMetrics drives the service through the paths that emit every metric,
// so the gather below is not over an empty registry.
func exerciseMetrics(t *testing.T) *server {
	t.Helper()
	ts, _, srv := newTestServer(t, nil)

	entry := signedTestEntry(t)
	body, err := json.Marshal(map[string]string{"entry": entry, "network": "testnet"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if status, raw := postVerifyRaw(t, ts.URL, "", string(body)); status != 200 {
		t.Fatalf("verify status = %d, want 200: %s", status, raw)
	}
	// A refusal so the refusal metric has a sample.
	if status, _ := postVerifyRaw(t, ts.URL, "", `{"network":"testnet"}`); status != 400 {
		t.Fatalf("malformed request status = %d, want 400", status)
	}
	// A hook event so the signer histogram has an observation.
	hook := srv.hook()
	if err := hook.Event(context.Background(), soroauth.HookEvent{
		Phase:          soroauth.HookPhasePostSign,
		CredentialType: soroauth.CredentialTypeAddressV2,
		Duration:       3 * time.Millisecond,
	}); err != nil {
		t.Fatalf("hook event: %v", err)
	}
	return srv
}

func gatherFamilies(t *testing.T, srv *server) []*dto.MetricFamily {
	t.Helper()
	families, err := srv.metrics.registry.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	return families
}

// TestMetricLabelsAreClosed walks every gathered series and asserts each label
// name and value is in the closed set. This is the test the issue asks for: an
// unbounded label is the usual way a metrics change takes down a Prometheus.
func TestMetricLabelsAreClosed(t *testing.T) {
	srv := exerciseMetrics(t)
	families := gatherFamilies(t, srv)
	if len(families) == 0 {
		t.Fatal("no metric families after exercising the service")
	}

	for _, family := range families {
		if _, ok := knownMetrics[family.GetName()]; !ok {
			t.Errorf("unexpected metric family %q", family.GetName())
		}
		for _, metric := range family.GetMetric() {
			for _, pair := range metric.GetLabel() {
				values, ok := allowedLabels[pair.GetName()]
				if !ok {
					t.Errorf("%s carries an undeclared label %q", family.GetName(), pair.GetName())
					continue
				}
				if _, ok := values[pair.GetValue()]; !ok {
					t.Errorf("%s label %s = %q, which is outside the closed set",
						family.GetName(), pair.GetName(), pair.GetValue())
				}
			}
		}
	}
}

func counterValue(t *testing.T, families []*dto.MetricFamily, name string, want map[string]string) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			match := true
			for k, v := range want {
				if labels[k] != v {
					match = false
				}
			}
			if match {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestMetricsRecordVerdictsAndRefusals(t *testing.T) {
	srv := exerciseMetrics(t)
	families := gatherFamilies(t, srv)

	verified := counterValue(t, families, metricVerdicts, map[string]string{
		"credential_type": soroauth.CredentialTypeAddressV2,
		"verdict":         string(soroauth.VerdictVerified),
	})
	if verified != 1 {
		t.Errorf("verified verdicts for address_v2 = %v, want 1", verified)
	}
	badRequest := counterValue(t, families, metricRefusals, map[string]string{"reason": refusalBadRequest})
	if badRequest < 1 {
		t.Errorf("bad_request refusals = %v, want at least 1", badRequest)
	}
	requests := counterValue(t, families, metricRequests, map[string]string{
		"route": routeVerify, "status": "400",
	})
	if requests < 1 {
		t.Errorf("400 requests on /verify = %v, want at least 1", requests)
	}
}

func TestHookMetricsRecordsSignerLatency(t *testing.T) {
	m := newServiceMetrics()
	hook := hookMetrics{metrics: m}

	// A stray credential type must be clamped, not create a new series.
	if err := hook.Event(context.Background(), soroauth.HookEvent{
		Phase:          soroauth.HookPhasePostSign,
		CredentialType: "0xnot-a-credential-type",
		Duration:       2 * time.Millisecond,
	}); err != nil {
		t.Fatalf("hook event: %v", err)
	}
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}

	var found bool
	for _, family := range families {
		if family.GetName() != metricSignerDuration {
			continue
		}
		for _, metric := range family.GetMetric() {
			var credential string
			for _, pair := range metric.GetLabel() {
				if pair.GetName() == "credential_type" {
					credential = pair.GetValue()
				}
			}
			if credential == "unknown" && metric.GetHistogram().GetSampleCount() == 1 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("signer latency histogram did not record the hook event with a clamped label")
	}

	// A preimage event has no duration and must not be observed.
	if err := hook.Event(context.Background(), soroauth.HookEvent{
		Phase: soroauth.HookPhasePreimage,
	}); err != nil {
		t.Fatalf("hook event: %v", err)
	}
}

// dashboard is the part of a Grafana dashboard the test reads.
type dashboard struct {
	Panels []struct {
		Title   string `json:"title"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	} `json:"panels"`
}

var metricNamePattern = regexp.MustCompile(`\bsoroauth_[a-z_]+`)

func baseMetric(name string) string {
	for _, suffix := range []string{"_bucket", "_count", "_sum"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

// TestDashboardReferencesOnlyKnownMetrics proves the committed dashboard
// queries the metrics the service actually emits — so it renders against real
// data rather than against a typo that graphs nothing — and that no query
// names a metric the service does not export.
func TestDashboardReferencesOnlyKnownMetrics(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "dashboards", "soroauth-verification.json"))
	if err != nil {
		t.Fatalf("reading the dashboard: %v", err)
	}
	var dash dashboard
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("the dashboard is not valid JSON: %v", err)
	}
	if len(dash.Panels) == 0 {
		t.Fatal("the dashboard has no panels")
	}

	referenced := map[string]bool{}
	for _, panel := range dash.Panels {
		if len(panel.Targets) == 0 {
			t.Errorf("panel %q has no targets", panel.Title)
			continue
		}
		for _, target := range panel.Targets {
			for _, name := range metricNamePattern.FindAllString(target.Expr, -1) {
				referenced[baseMetric(name)] = true
				if _, ok := knownMetrics[baseMetric(name)]; !ok {
					t.Errorf("panel %q queries unknown metric %q", panel.Title, name)
				}
			}
		}
	}

	// Every metric the service exposes should be represented, so the dashboard
	// is not quietly missing a signal.
	for name := range knownMetrics {
		if !referenced[name] {
			t.Errorf("the dashboard does not query %s", name)
		}
	}
}

// TestExampleScrapeMatchesDashboard ties the committed export from a real run
// to the dashboard: every metric family a panel queries and the service emits
// appears in the scrape, so the queries are known to have data behind them.
//
// soroauth_signer_duration_seconds is the documented exception: the service
// verifies rather than signs today, so the histogram has no samples and does
// not appear in a scrape until signing is enabled. The dashboard says so in the
// panel title.
func TestExampleScrapeMatchesDashboard(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "dashboards", "example-metrics.txt"))
	if err != nil {
		t.Fatalf("reading the example scrape: %v", err)
	}
	scrape := string(raw)
	for _, name := range []string{
		metricRequests, metricRequestDuration, metricVerdicts, metricRefusals,
	} {
		if !strings.Contains(scrape, name) {
			t.Errorf("the example scrape does not mention %s", name)
		}
	}
	if strings.Contains(scrape, metricSignerDuration) {
		t.Errorf("the example scrape mentions %s, but a verify-only service observes no signing", metricSignerDuration)
	}
}
