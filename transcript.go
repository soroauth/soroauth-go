package soroauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// SessionOutcome is the final state of a signing session recorded in a
// transcript.
type SessionOutcome string

const (
	// SessionOutcomeComplete means every expected node was signed.
	SessionOutcomeComplete SessionOutcome = "complete"
	// SessionOutcomeFailed means the session stopped because of an error. The
	// reason is in the transcript.
	SessionOutcomeFailed SessionOutcome = "failed"
	// SessionOutcomeAborted means a caller stopped the session deliberately.
	// The reason is in the transcript.
	SessionOutcomeAborted SessionOutcome = "aborted"
)

// ErrTranscriptVerification reports a transcript whose signature does not
// verify, or one whose canonical bytes cannot be rebuilt. A transcript that
// does not verify is not evidence of anything.
var ErrTranscriptVerification = errors.New("soroauth: transcript verification failed")

// TranscriptVersion is the format version of a signed session transcript.
const TranscriptVersion = "soroauth.session-transcript.v1"

// TranscriptRound is one recorded signing round. Signers lists the addresses
// whose shares were applied in the round; SignedNodes and TotalNodes record
// progress through a delegate tree.
type TranscriptRound struct {
	Round       int      `json:"round"`
	Signers     []string `json:"signers"`
	SignedNodes int      `json:"signed_nodes"`
	TotalNodes  int      `json:"total_nodes"`
}

// SessionTranscript is the durable, signed record of one multi-party signing
// session: who participated, what payload was approved, what happened in each
// round, and how the session ended.
//
// It deliberately contains no key share, seed, nonce or signature share. Only
// the payload hash is recorded, never the payload itself, so a transcript does
// not become a copy of every entry a group signs. The AuditRecords field reuses
// the AuditRecord shape from the signing audit trail (#319), so a consumer
// parses one vocabulary for both.
//
// VerifyTranscript checks it using only the transcript: the coordinator's
// public key travels inside it, so verification needs no coordinator
// cooperation and no shared secret.
type SessionTranscript struct {
	Version              string            `json:"version"`
	SessionID            string            `json:"session_id"`
	StartedAt            time.Time         `json:"started_at"`
	FinishedAt           time.Time         `json:"finished_at"`
	CredentialType       string            `json:"credential_type"`
	Address              string            `json:"address,omitempty"`
	ValidUntilLedger     uint32            `json:"valid_until_ledger"`
	NetworkPassphrase    string            `json:"network_passphrase"`
	EntryHash            string            `json:"entry_hash"`
	PayloadHash          string            `json:"payload_hash"`
	Participants         []string          `json:"participants"`
	Rounds               []TranscriptRound `json:"rounds"`
	Outcome              SessionOutcome    `json:"outcome"`
	FailureReason        string            `json:"failure_reason,omitempty"`
	AuditRecords         []AuditRecord     `json:"audit_records,omitempty"`
	CoordinatorPublicKey string            `json:"coordinator_public_key"`
	Signature            string            `json:"signature"`
}

// transcriptBody is SessionTranscript without the signature. Its field order is
// the signing order: Go marshals struct fields in declaration order, and every
// other field is a scalar, a slice in recorded order, or a time.Time, so the
// encoding is deterministic for a given transcript.
type transcriptBody struct {
	Version              string            `json:"version"`
	SessionID            string            `json:"session_id"`
	StartedAt            time.Time         `json:"started_at"`
	FinishedAt           time.Time         `json:"finished_at"`
	CredentialType       string            `json:"credential_type"`
	Address              string            `json:"address,omitempty"`
	ValidUntilLedger     uint32            `json:"valid_until_ledger"`
	NetworkPassphrase    string            `json:"network_passphrase"`
	EntryHash            string            `json:"entry_hash"`
	PayloadHash          string            `json:"payload_hash"`
	Participants         []string          `json:"participants"`
	Rounds               []TranscriptRound `json:"rounds"`
	Outcome              SessionOutcome    `json:"outcome"`
	FailureReason        string            `json:"failure_reason,omitempty"`
	AuditRecords         []AuditRecord     `json:"audit_records,omitempty"`
	CoordinatorPublicKey string            `json:"coordinator_public_key"`
}

func (t SessionTranscript) body() transcriptBody {
	return transcriptBody{
		Version:              t.Version,
		SessionID:            t.SessionID,
		StartedAt:            t.StartedAt,
		FinishedAt:           t.FinishedAt,
		CredentialType:       t.CredentialType,
		Address:              t.Address,
		ValidUntilLedger:     t.ValidUntilLedger,
		NetworkPassphrase:    t.NetworkPassphrase,
		EntryHash:            t.EntryHash,
		PayloadHash:          t.PayloadHash,
		Participants:         t.Participants,
		Rounds:               t.Rounds,
		Outcome:              t.Outcome,
		FailureReason:        t.FailureReason,
		AuditRecords:         t.AuditRecords,
		CoordinatorPublicKey: t.CoordinatorPublicKey,
	}
}

// signingBytes returns the canonical bytes the coordinator signs.
func (t SessionTranscript) signingBytes() ([]byte, error) {
	body := t.body()
	return json.Marshal(body)
}

// VerifyTranscript verifies a transcript's coordinator signature and internal
// consistency without contacting the coordinator. It checks that the signing
// bytes rebuild, the outcome is one of the three known values, and the
// Ed25519 signature verifies under the embedded public key.
//
// This is the "verifiable without the coordinator's cooperation" property: the
// verifier needs the transcript and nothing else.
func VerifyTranscript(t SessionTranscript) error {
	if t.Version != TranscriptVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrTranscriptVerification, t.Version)
	}
	switch t.Outcome {
	case SessionOutcomeComplete, SessionOutcomeFailed, SessionOutcomeAborted:
	default:
		return fmt.Errorf("%w: unknown outcome %q", ErrTranscriptVerification, t.Outcome)
	}
	if t.SessionID == "" || t.PayloadHash == "" || t.EntryHash == "" {
		return fmt.Errorf("%w: transcript is missing an identifier or hash", ErrTranscriptVerification)
	}
	if t.Outcome != SessionOutcomeComplete && t.FailureReason == "" {
		return fmt.Errorf("%w: an incomplete session has no failure reason", ErrTranscriptVerification)
	}

	publicKey, err := hex.DecodeString(t.CoordinatorPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: coordinator public key is not %d bytes of hex",
			ErrTranscriptVerification, ed25519.PublicKeySize)
	}
	signature, err := hex.DecodeString(t.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is not %d bytes of hex",
			ErrTranscriptVerification, ed25519.SignatureSize)
	}
	message, err := t.signingBytes()
	if err != nil {
		return fmt.Errorf("%w: rebuilding signing bytes: %v", ErrTranscriptVerification, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return fmt.Errorf("%w: coordinator signature does not verify", ErrTranscriptVerification)
	}
	return nil
}

// TranscriptConfig describes a session before it starts.
type TranscriptConfig struct {
	// Entry is the entry the session will sign.
	Entry xdr.SorobanAuthorizationEntry
	// ValidUntilLedger is the expiration the session commits to.
	ValidUntilLedger uint32
	// NetworkPassphrase is the network the entry is for.
	NetworkPassphrase string
	// Coordinator signs the finished transcript. Its secret is used only for
	// that signature and is never stored or emitted.
	Coordinator *keypair.Full
	// SessionID is optional. When empty a fresh random identifier is used.
	SessionID string
}

// TranscriptRecorder accumulates rounds for one session and signs the finished
// transcript. It never records a share, seed or signature share; the fields it
// accepts are addresses, counts, the payload hash, and AuditRecord values.
//
// A recorder is safe for concurrent use.
type TranscriptRecorder struct {
	transcript  SessionTranscript
	coordinator *keypair.Full
	mu          sync.Mutex
	finished    bool
}

// NewTranscriptRecorder validates the session up front, derives the payload and
// entry hashes, and records the participant set from the entry's credential
// tree. A session whose payload cannot be built is refused rather than recorded
// with a placeholder hash.
func NewTranscriptRecorder(cfg TranscriptConfig) (*TranscriptRecorder, error) {
	if cfg.Coordinator == nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: coordinator key is required: %w", ErrMissingSigner)
	}
	if cfg.ValidUntilLedger == 0 {
		return nil, fmt.Errorf("soroauth: new transcript recorder: %w", ErrInvalidExpiration)
	}
	if cfg.NetworkPassphrase == "" {
		return nil, fmt.Errorf("soroauth: new transcript recorder: empty network passphrase")
	}

	info, err := Inspect(cfg.Entry)
	if err != nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: %w", err)
	}
	preimage, err := Preimage(cfg.Entry, cfg.ValidUntilLedger, cfg.NetworkPassphrase)
	if err != nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: %w", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: %w", err)
	}
	entryBytes, err := cfg.Entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: %w", err)
	}
	entryHash := sha256.Sum256(entryBytes)

	sessionID := cfg.SessionID
	if sessionID == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("soroauth: new transcript recorder: session id: %w", err)
		}
		sessionID = hex.EncodeToString(buf)
	}

	publicKey, err := strkey.Decode(strkey.VersionByteAccountID, cfg.Coordinator.Address())
	if err != nil {
		return nil, fmt.Errorf("soroauth: new transcript recorder: coordinator address: %w", err)
	}

	return &TranscriptRecorder{
		coordinator: cfg.Coordinator,
		transcript: SessionTranscript{
			Version:              TranscriptVersion,
			SessionID:            sessionID,
			StartedAt:            time.Now().UTC(),
			CredentialType:       info.CredentialType,
			Address:              info.Address,
			ValidUntilLedger:     cfg.ValidUntilLedger,
			NetworkPassphrase:    cfg.NetworkPassphrase,
			EntryHash:            hex.EncodeToString(entryHash[:]),
			PayloadHash:          hex.EncodeToString(payload[:]),
			Participants:         transcriptParticipants(info),
			CoordinatorPublicKey: hex.EncodeToString(publicKey),
		},
	}, nil
}

// transcriptParticipants lists the top-level address and every delegate at
// every depth, sorted and de-duplicated. The same address at two levels is one
// participant.
func transcriptParticipants(info EntryInfo) []string {
	seen := make(map[string]bool)
	if info.Address != "" {
		seen[info.Address] = true
	}
	var walk func([]NodeInfo)
	walk = func(nodes []NodeInfo) {
		for _, node := range nodes {
			if node.Address != "" {
				seen[node.Address] = true
			}
			walk(node.Nested)
		}
	}
	walk(info.Delegates)

	out := make([]string, 0, len(seen))
	for address := range seen {
		out = append(out, address)
	}
	sort.Strings(out)
	return out
}

// RecordRound appends one round. Rounds are appended in call order and are not
// reordered: the transcript records what happened, not a tidied version of it.
func (r *TranscriptRecorder) RecordRound(signers []string, signedNodes, totalNodes int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return fmt.Errorf("soroauth: transcript recorder: session already finished")
	}
	if signedNodes < 0 || totalNodes < 0 || signedNodes > totalNodes {
		return fmt.Errorf("soroauth: transcript recorder: invalid node counts %d/%d", signedNodes, totalNodes)
	}
	r.transcript.Rounds = append(r.transcript.Rounds, TranscriptRound{
		Round:       len(r.transcript.Rounds) + 1,
		Signers:     append([]string(nil), signers...),
		SignedNodes: signedNodes,
		TotalNodes:  totalNodes,
	})
	return nil
}

// RecordAudit appends one audit record, reusing the shape from the signing
// audit trail. Recording an audit record never changes the outcome.
func (r *TranscriptRecorder) RecordAudit(record AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return fmt.Errorf("soroauth: transcript recorder: session already finished")
	}
	r.transcript.AuditRecords = append(r.transcript.AuditRecords, record)
	return nil
}

// Finish closes the session and returns the signed transcript. Calling Finish
// twice returns the transcript from the first call; a transcript is immutable
// once signed.
//
// A failed or aborted session records a non-empty reason. A complete session
// must not carry one.
func (r *TranscriptRecorder) Finish(outcome SessionOutcome, reason string) (SessionTranscript, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return r.transcript, nil
	}
	switch outcome {
	case SessionOutcomeComplete, SessionOutcomeFailed, SessionOutcomeAborted:
	default:
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: unknown outcome %q", outcome)
	}
	if outcome == SessionOutcomeComplete && reason != "" {
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: a complete session must not carry a failure reason")
	}
	if outcome != SessionOutcomeComplete && reason == "" {
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: a %s session requires a reason", outcome)
	}

	r.transcript.FinishedAt = time.Now().UTC()
	r.transcript.Outcome = outcome
	r.transcript.FailureReason = reason

	message, err := r.transcript.signingBytes()
	if err != nil {
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: %w", err)
	}
	signature, err := r.coordinator.Sign(message)
	if err != nil {
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: sign: %w", err)
	}
	r.transcript.Signature = hex.EncodeToString(signature)
	if err := VerifyTranscript(r.transcript); err != nil {
		return SessionTranscript{}, fmt.Errorf("soroauth: transcript recorder: %w", err)
	}
	r.finished = true
	return r.transcript, nil
}

// Abort closes the session as aborted with a reason.
func (r *TranscriptRecorder) Abort(reason string) (SessionTranscript, error) {
	return r.Finish(SessionOutcomeAborted, reason)
}

// Finished reports whether Finish or Abort has closed the session.
func (r *TranscriptRecorder) Finished() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finished
}
