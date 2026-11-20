package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// decodeAuditLines parses newline-delimited records from a sink buffer.
func decodeAuditLines(t *testing.T, raw string) []AuditRecord {
	t.Helper()
	var records []AuditRecord
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var record AuditRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("audit line is not valid JSON: %v (%q)", err, line)
		}
		records = append(records, record)
	}
	return records
}

func TestAuditRecordsAVerificationDecision(t *testing.T) {
	var sink bytes.Buffer
	ts, _, _ := newTestServer(t, func(cfg *config) {
		cfg.AuditSink = NewJSONAuditSink(&sink)
	})

	body := map[string]string{
		"entry":   signedTestEntry(t),
		"network": "testnet",
	}
	status, response := postVerify(t, ts.URL, body)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, response)
	}

	records := decodeAuditLines(t, sink.String())
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1: %+v", len(records), records)
	}
	record := records[0]
	if record.SchemaVersion != AuditSchemaVersion {
		t.Errorf("schema_version = %q, want %q", record.SchemaVersion, AuditSchemaVersion)
	}
	if record.Operation != routeVerify {
		t.Errorf("operation = %q, want %q", record.Operation, routeVerify)
	}
	if record.Decision != AuditDecisionVerified {
		t.Errorf("decision = %q, want %q", record.Decision, AuditDecisionVerified)
	}
	if len(record.EntryHash) != 64 {
		t.Errorf("entry_hash = %q, want 64 hex characters", record.EntryHash)
	}
	if record.RequestID == "" {
		t.Error("request_id is empty")
	}
	if record.Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
	if record.CredentialType == "" {
		t.Error("credential_type is empty")
	}

	// The record identifies the entry by hash; it never carries the entry,
	// its signature or anything else secret-shaped.
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshalling the record: %v", err)
	}
	if bytes.Contains(encoded, []byte(body["entry"])) {
		t.Error("audit record contains the entry itself")
	}
	if bytes.Contains(encoded, []byte("signature")) {
		t.Errorf("audit record mentions signature material: %s", encoded)
	}
}

func TestAuditWriteFailureFailsTheRequest(t *testing.T) {
	ts, _, _ := newTestServer(t, func(cfg *config) {
		cfg.AuditSink = AuditSinkFunc(func(context.Context, AuditRecord) error {
			return errors.New("disk full")
		})
	})

	status, response := postVerify(t, ts.URL, map[string]string{
		"entry":   signedTestEntry(t),
		"network": "testnet",
	})
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %v", status, response)
	}
	if got := response["error"]; got != "audit record could not be written" {
		t.Errorf("error = %v, want the audit failure", got)
	}
}

func TestAuditRecordsRejectedRequests(t *testing.T) {
	var sink bytes.Buffer
	ts, _, _ := newTestServer(t, func(cfg *config) {
		cfg.AuditSink = NewJSONAuditSink(&sink)
	})

	status, _ := postVerify(t, ts.URL, map[string]string{"entry": "!!!not-xdr!!!"})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}

	records := decodeAuditLines(t, sink.String())
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	if records[0].Decision != AuditDecisionError {
		t.Errorf("decision = %q, want %q", records[0].Decision, AuditDecisionError)
	}
	if records[0].Error == "" {
		t.Error("error decision carries no message")
	}
	if records[0].EntryHash == "" {
		t.Error("error decision carries no entry hash")
	}
}

func TestAuditRecordsRiskReports(t *testing.T) {
	var sink bytes.Buffer
	ts, _, _ := newTestServer(t, func(cfg *config) {
		cfg.AuditSink = NewJSONAuditSink(&sink)
	})

	status, _ := postRisk(t, ts.URL, map[string]string{
		"entry": loadVector(t, "legacy_single_testnet").UnsignedEntryXDR,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	records := decodeAuditLines(t, sink.String())
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	record := records[0]
	if record.Operation != routeRisk {
		t.Errorf("operation = %q, want %q", record.Operation, routeRisk)
	}
	if record.Decision != AuditDecisionReported {
		t.Errorf("decision = %q, want %q", record.Decision, AuditDecisionReported)
	}
	if record.Findings == 0 {
		t.Error("legacy entry should record at least one finding")
	}
}

func TestJSONAuditSinkReportsWriteErrors(t *testing.T) {
	sink := NewJSONAuditSink(failingWriter{})
	if err := sink.Record(context.Background(), AuditRecord{SchemaVersion: AuditSchemaVersion}); err == nil {
		t.Fatal("Record accepted a failing writer")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestLoadConfigReadsAuditLog(t *testing.T) {
	cfg, err := loadConfig(func(key string) string {
		if key == "AUDIT_LOG" {
			return "/var/log/soroauth-audit.jsonl"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.AuditLog != "/var/log/soroauth-audit.jsonl" {
		t.Errorf("AuditLog = %q", cfg.AuditLog)
	}
}
