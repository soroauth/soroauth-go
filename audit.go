package soroauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// AuditDecision is the outcome of a signing decision.
type AuditDecision string

const (
	// AuditDecisionSigned means the entry was signed successfully.
	AuditDecisionSigned AuditDecision = "signed"
	// AuditDecisionRefused means the signer refused the entry.
	AuditDecisionRefused AuditDecision = "refused"
	// AuditDecisionError means an error occurred during signing.
	AuditDecisionError AuditDecision = "error"
)

// AuditRecord captures every preimage-derived field of one signing call,
// plus the decision taken, in a form suitable for an append-only log. It
// never carries a secret, seed or signature value — a test asserts this.
type AuditRecord struct {
	// Timestamp is when the signing decision was made, in UTC.
	Timestamp time.Time `json:"timestamp"`
	// CredentialArm is the credential arm name (address, address_v2,
	// address_with_delegates).
	CredentialArm string `json:"credential_arm"`
	// TargetAddress is the G… or C… address the signature is written onto.
	TargetAddress string `json:"target_address"`
	// Nonce is the nonce from the entry's credentials.
	Nonce int64 `json:"nonce"`
	// ValidUntilLedger is the expiration ledger the signature commits to.
	ValidUntilLedger uint32 `json:"valid_until_ledger"`
	// NetworkPassphrase is the network the entry is for.
	NetworkPassphrase string `json:"network_passphrase"`
	// PayloadHash is the hex-encoded SHA-256 of the preimage.
	PayloadHash string `json:"payload_hash"`
	// RootInvocationHash is the hex-encoded SHA-256 of the XDR-encoded
	// root invocation tree.
	RootInvocationHash string `json:"root_invocation_hash"`
	// NodeCount is the number of credential nodes in the entry (1 for
	// non-delegates, 1 + delegates for the delegates arm).
	NodeCount int `json:"node_count"`
	// Decision is the outcome: signed, refused or error.
	Decision AuditDecision `json:"decision"`
	// Error is the error message when Decision is refused or error, empty
	// otherwise.
	Error string `json:"error,omitempty"`
}

// MarshalJSON produces the stable JSON serialisation of an audit record.
func (r AuditRecord) MarshalJSON() ([]byte, error) {
	type alias AuditRecord
	return json.Marshal(alias(r))
}

// AuditSink receives audit records. Implementations must be safe for
// concurrent use if the same sink is shared across goroutines. The library
// does no logging — this hands records to a caller-supplied sink.
type AuditSink interface {
	// Record receives one audit record. An error from Record fails the
	// signing call: a record that cannot be persisted must not be silently
	// dropped. Implementations that prefer best-effort delivery should
	// return nil and handle failures internally.
	Record(ctx context.Context, r AuditRecord) error
}

// AuditSinkFunc adapts a function to the AuditSink interface.
type AuditSinkFunc func(ctx context.Context, r AuditRecord) error

// Record calls the wrapped function.
func (f AuditSinkFunc) Record(ctx context.Context, r AuditRecord) error {
	return f(ctx, r)
}

// WithAudit registers an audit sink for the signing operation. When set,
// an AuditRecord is produced for every signing call — including refusals
// and errors — and handed to the sink before the result is returned.
//
// If the sink returns an error, the signing call fails with that error,
// even if the signature itself succeeded. This is deliberate: a record
// that cannot be persisted must not be silently dropped. Sinks that
// prefer best-effort delivery should return nil and handle failures
// internally.
//
// No secret, seed or signature value ever reaches the sink. A test
// asserts this property.
func WithAudit(sink AuditSink) AuthorizeOption {
	return func(c *authorizeConfig) {
		c.auditSink = sink
	}
}

// emitAuditRecord builds and emits an audit record for a signing call.
func emitAuditRecord(
	ctx context.Context,
	sink AuditSink,
	entry xdr.SorobanAuthorizationEntry,
	target string,
	validUntilLedger uint32,
	networkPassphrase string,
	payloadHash [32]byte,
	nodeCount int,
	decision AuditDecision,
	signErr error,
) error {
	if sink == nil {
		return nil
	}

	record, err := newAuditRecord(entry, target, validUntilLedger, networkPassphrase, payloadHash, nodeCount, decision, signErr)
	if err != nil {
		return nil
	}
	return sink.Record(ctx, record)
}

// newAuditRecord builds the record emitAuditRecord hands to a sink. It is also
// what a session transcript reuses, so both carry the same vocabulary.
func newAuditRecord(
	entry xdr.SorobanAuthorizationEntry,
	target string,
	validUntilLedger uint32,
	networkPassphrase string,
	payloadHash [32]byte,
	nodeCount int,
	decision AuditDecision,
	signErr error,
) (AuditRecord, error) {
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return AuditRecord{}, err
	}

	invocationBytes, err := entry.RootInvocation.MarshalBinary()
	if err != nil {
		invocationBytes = nil
	}
	invocationHash := sha256.Sum256(invocationBytes)

	record := AuditRecord{
		Timestamp:          time.Now().UTC(),
		CredentialArm:      credentialTypeName(entry.Credentials.Type),
		TargetAddress:      target,
		Nonce:              int64(credentials.Nonce),
		ValidUntilLedger:   validUntilLedger,
		NetworkPassphrase:  networkPassphrase,
		PayloadHash:        hex.EncodeToString(payloadHash[:]),
		RootInvocationHash: hex.EncodeToString(invocationHash[:]),
		NodeCount:          nodeCount,
		Decision:           decision,
	}
	if signErr != nil {
		record.Error = signErr.Error()
	}
	return record, nil
}

// auditNodeCount returns the number of credential nodes in the entry.
func auditNodeCount(entry xdr.SorobanAuthorizationEntry) int {
	nodes, err := credentialNodes(&entry)
	if err != nil {
		return 1
	}
	return len(nodes)
}

// formatPayloadHash returns the hex-encoded payload hash string.
func formatPayloadHash(payload [32]byte) string {
	return hex.EncodeToString(payload[:])
}
