package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// riskRequest is the JSON request body for POST /risk. It deliberately accepts
// no signing material and no configuration: the analyzer's documented defaults
// are the contract's defaults, and a caller that needs different heuristics
// links the library rather than this service.
type riskRequest struct {
	// Entry is the base64 authorization entry or transaction envelope.
	Entry string `json:"entry"`
}

// riskReport is one entry's findings. Its shape mirrors the verification
// report's location fields so a client can line a report back up with an
// envelope, and it carries the analyzer's note on every report so a clean
// result cannot be mistaken for a safety guarantee.
type riskReport struct {
	OperationIndex int                `json:"operation_index,omitempty"`
	EntryIndex     int                `json:"entry_index,omitempty"`
	CredentialType string             `json:"credential_type"`
	Address        string             `json:"address,omitempty"`
	Findings       []soroauth.Finding `json:"findings"`
	Note           string             `json:"note"`
}

// riskHandler answers a different question from /verify: not "do these
// signatures verify" but "what structural risks does this entry show". Findings
// are heuristics with stable identifiers and severities, and the report always
// carries the analyzer's own note about its limits. A request that completes is
// HTTP 200 whatever the findings say; a report with a critical finding is the
// answer, not a transport failure.
func (s *server) riskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	identity, ok := s.authenticate(r)
	if !ok {
		s.writeError(w, r, http.StatusUnauthorized, "missing or invalid bearer token")
		return
	}
	if !s.allowRate(w, r, identity) {
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.metrics.recordLimitRejection(limitConcurrency)
		w.Header().Set("Retry-After", "1")
		s.writeError(w, r, http.StatusServiceUnavailable,
			"service is at its concurrent-request limit; retry shortly")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.metrics.recordLimitRejection(limitBody)
			s.writeError(w, r, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body exceeds the %d-byte limit", s.cfg.MaxBodyBytes))
			return
		}
		s.writeError(w, r, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}

	var req riskRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}
	if req.Entry == "" {
		s.writeError(w, r, http.StatusBadRequest, "entry is required")
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

	reports := make([]riskReport, 0, len(locatedEntries))
	for _, item := range locatedEntries {
		info, err := soroauth.Inspect(item.entry)
		if err != nil {
			s.writeError(w, r, http.StatusBadRequest, "analysis failed: "+err.Error())
			return
		}
		findings, err := soroauth.Analyze(item.entry, nil)
		if err != nil {
			s.writeError(w, r, http.StatusBadRequest, "analysis failed: "+err.Error())
			return
		}
		if findings == nil {
			findings = []soroauth.Finding{}
		}
		report := riskReport{
			CredentialType: info.CredentialType,
			Address:        info.Address,
			Findings:       findings,
			Note:           soroauth.FindingNote,
		}
		if input.isEnvelope {
			report.OperationIndex = item.operationIndex + 1
			report.EntryIndex = item.entryIndex + 1
		}
		reports = append(reports, report)
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if input.isEnvelope {
		_ = enc.Encode(reports)
	} else {
		_ = enc.Encode(reports[0])
	}
}
