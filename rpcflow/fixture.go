// Package rpcflow records and replays Stellar RPC interactions against the
// testnet to detect protocol or API drift.
//
// A fixture is a recorded scenario: a signed authorization entry, the network
// context it was recorded under, and the outcome that was observed (accepted,
// rejected, or specific error). The rpc_drift job replays each fixture against
// the live testnet and opens a GitHub issue when the observed outcome differs
// from the recorded one.
//
// # Why this exists alongside the golden vectors
//
// The golden vectors in testdata/vectors/ prove that the Go library produces
// the correct bytes for given inputs. That is an offline correctness check; it
// does not require a network connection. The rpcflow fixtures prove that the
// live testnet accepts entries the library produces. A protocol upgrade,
// network reset, or change in the RPC endpoint's behaviour would not be caught
// by the golden vectors alone — the rpcflow replay job catches it on a
// schedule rather than after a user reports a submission failure.
//
// # Fixture lifecycle
//
// 1. Record: run the rpc_drift test suite with SOROAUTH_RECORD=true. Each
//    fixture's observed outcome is written back into the JSON file.
// 2. Commit the updated fixture files. The committed expected_outcome is now
//    the baseline.
// 3. The scheduled workflow replays and diffs. If the outcome changed, the
//    workflow opens a GitHub issue with the fixture name and both outcomes.
//
// Fixtures must never be edited by hand to suppress a failure. If the testnet
// outcome changed legitimately (a protocol upgrade), re-record the fixture,
// review the diff, and commit the update with a note in the commit body.
package rpcflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Outcome describes what the testnet returned when a fixture's signed entry
// was submitted via simulateTransaction.
type Outcome string

const (
	// OutcomeAccepted means simulateTransaction returned a successful result.
	OutcomeAccepted Outcome = "accepted"
	// OutcomeRejected means simulateTransaction returned an error. The error
	// code is in Fixture.ExpectedErrorCode.
	OutcomeRejected Outcome = "rejected"
)

// Fixture is one recorded RPC scenario.
type Fixture struct {
	// Name identifies the fixture in issue titles and log output.
	Name string `json:"name"`

	// Description explains what this fixture proves.
	Description string `json:"description"`

	// NetworkPassphrase is the network passphrase the entry was recorded
	// against. The replay uses the same passphrase.
	NetworkPassphrase string `json:"network_passphrase"`

	// SignedEntryXDR is the base64-encoded XDR of the signed
	// SorobanAuthorizationEntry that was submitted during recording.
	// It is empty for pending fixtures (Pending == true).
	SignedEntryXDR string `json:"signed_entry_xdr"`

	// ValidUntilLedger is the expiration ledger baked into the signed entry.
	// The replay submits the entry as-is; whether it has expired on the live
	// testnet does not affect the drift check, because the drift check
	// compares the error type, not the ledger offset.
	ValidUntilLedger uint32 `json:"valid_until_ledger"`

	// ExpectedOutcome is the last recorded outcome. The drift job compares
	// the live outcome against this value and flags any change.
	ExpectedOutcome Outcome `json:"expected_outcome"`

	// ExpectedErrorCode is the error code returned when ExpectedOutcome is
	// OutcomeRejected. It is an empty string when ExpectedOutcome is
	// OutcomeAccepted.
	ExpectedErrorCode string `json:"expected_error_code,omitempty"`

	// Pending marks the fixture as not yet recorded. Pending fixtures are
	// loaded and listed but skipped by the replay test. Record them by running
	// with SOROAUTH_RECORD=true.
	Pending bool `json:"pending,omitempty"`

	// RecordedAt is the RFC-3339 timestamp when the fixture was last
	// recorded. It is informational; the replay does not use it.
	RecordedAt string `json:"recorded_at,omitempty"`
}

// Load reads every *.json fixture file from dir and returns them in the order
// they were read. Any file that cannot be parsed is returned as an error
// alongside the successfully-loaded fixtures.
func Load(dir string) ([]Fixture, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("rpcflow: load fixtures from %s: %w", dir, err)
	}

	var fixtures []Fixture
	var errs []error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		f, err := loadOne(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", entry.Name(), err))
			continue
		}
		fixtures = append(fixtures, f)
	}

	if len(errs) > 0 {
		return fixtures, fmt.Errorf("rpcflow: %d fixture(s) failed to load: %v", len(errs), errs)
	}
	return fixtures, nil
}

func loadOne(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("read: %w", err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return Fixture{}, fmt.Errorf("parse: %w", err)
	}
	if f.Name == "" {
		return Fixture{}, fmt.Errorf("parse: fixture has no name")
	}
	if !f.Pending && f.SignedEntryXDR == "" {
		return Fixture{}, fmt.Errorf("parse: fixture %q has no signed_entry_xdr (mark it pending:true if not yet recorded)", f.Name)
	}
	return f, nil
}
