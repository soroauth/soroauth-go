package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/soroauth/soroauth-go"
)

// AuditSchemaVersion is the version of the record shape below. It is written
// into every record so a consumer can tell records apart when the shape gains
// a field, rather than guessing from which fields are present.
const AuditSchemaVersion = "1.0"

// AuditDecision is the outcome the service reached for one request.
type AuditDecision string

const (
	// AuditDecisionVerified means the entry's signatures verified.
	AuditDecisionVerified AuditDecision = "verified"
	// AuditDecisionRejected means verification completed and did not verify
	// every node (unsigned, invalid or cannot-check).
	AuditDecisionRejected AuditDecision = "rejected"
	// AuditDecisionError means the request could not be evaluated.
	AuditDecisionError AuditDecision = "error"
	// AuditDecisionReported means a risk report was produced. A report is the
	// answer whatever its findings say, so it is not a rejection.
	AuditDecisionReported AuditDecision = "reported"
)

// AuditRecord is the append-only record of one decision. It identifies the
// entry by hash rather than carrying its contents: the record must be useful
// after the fact without becoming a copy of every entry the service has seen.
// It never carries a signature value, a secret seed, a bearer token or a
// request body.
type AuditRecord struct {
	// SchemaVersion is AuditSchemaVersion at the time the record was written.
	SchemaVersion string `json:"schema_version"`
	// Timestamp is when the decision was made, in UTC.
	Timestamp time.Time `json:"timestamp"`
	// RequestID identifies one request across all of its per-entry records.
	RequestID string `json:"request_id"`
	// Operation is the route that made the decision ("/verify" or "/risk").
	Operation string `json:"operation"`
	// Decision is verified, rejected or error.
	Decision AuditDecision `json:"decision"`
	// EntryHash is the hex SHA-256 of the base64-decoded entry, or of the raw
	// request value when it does not decode. It identifies the entry without
	// storing it.
	EntryHash string `json:"entry_hash"`
	// CredentialType, Address, ValidUntilLedger and NodeCount describe the
	// entry when it was decoded far enough to know.
	CredentialType   string `json:"credential_type,omitempty"`
	Address          string `json:"address,omitempty"`
	ValidUntilLedger uint32 `json:"valid_until_ledger,omitempty"`
	NodeCount        int    `json:"node_count,omitempty"`
	// Findings is the number of risk findings for a /risk decision.
	Findings int `json:"findings,omitempty"`
	// Error is the failure message for an error decision, empty otherwise.
	Error string `json:"error,omitempty"`
}

// AuditSink receives one record per decision. Implementations must be safe for
// concurrent use: the service handles requests concurrently.
type AuditSink interface {
	// Record writes one record. An error fails the request: an audit record
	// that cannot be persisted must not be silently dropped.
	Record(ctx context.Context, record AuditRecord) error
}

// AuditSinkFunc adapts a function to AuditSink.
type AuditSinkFunc func(ctx context.Context, record AuditRecord) error

// Record calls the wrapped function.
func (f AuditSinkFunc) Record(ctx context.Context, record AuditRecord) error {
	return f(ctx, record)
}

// JSONAuditSink appends one JSON object per line to a writer. The writer is
// expected to be an append-only file or another durable stream; the sink does
// not close it, because the process may share it with its owner.
//
// Retention is the operator's decision: a growing audit log that nobody prunes
// gets deleted in a hurry. docs/verification-service.md states the expectation
// for the shipped service.
type JSONAuditSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONAuditSink returns a sink that writes newline-delimited JSON records.
func NewJSONAuditSink(w io.Writer) *JSONAuditSink {
	return &JSONAuditSink{w: w}
}

// Record writes one record. A short write or an encoder error is returned so
// the request fails rather than the decision going unrecorded.
func (s *JSONAuditSink) Record(_ context.Context, record AuditRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("soroauth: audit: encoding record: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("soroauth: audit: writing record: %w", err)
	}
	return nil
}

// newRequestID returns a fresh, non-guessable identifier for one request.
func newRequestID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// A request id is only a correlation aid, never a security decision.
		// Falling back to the time still lets the records of one request be
		// grouped, which is the property that matters here.
		return fmt.Sprintf("t-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

// entryDigest identifies an entry by content. It hashes the decoded bytes when
// the value is valid base64, and the raw value otherwise, so a malformed
// request is still identifiable without the body being stored.
func entryDigest(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(decoded)
	return hex.EncodeToString(sum[:])
}

// countNodes counts a delegate tree, including every nested node.
func countNodes(nodes []soroauth.NodeInfo) int {
	total := 0
	for _, node := range nodes {
		total += 1 + countNodes(node.Nested)
	}
	return total
}

// emitAudit hands one record to the configured sink. A nil sink is a no-op,
// which is what an operator who has not configured AUDIT_LOG gets. A sink
// error is returned and the caller must fail the request.
func (s *server) emitAudit(ctx context.Context, record AuditRecord) error {
	if s.cfg.AuditSink == nil {
		return nil
	}
	if record.SchemaVersion == "" {
		record.SchemaVersion = AuditSchemaVersion
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}
	if err := s.cfg.AuditSink.Record(ctx, record); err != nil {
		return fmt.Errorf("soroauth: audit: %w", err)
	}
	return nil
}
