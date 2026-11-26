//go:build rpc_drift

// Package rpcflow provides RPC fixture replay tests.
//
// These tests require a live Stellar RPC endpoint and are excluded from the
// normal test run by the rpc_drift build tag. Run them with:
//
//	go test -tags rpc_drift -v ./rpcflow/...
//
// Set SOROAUTH_RPC_URL to point at a specific endpoint; it defaults to the
// public testnet. Set SOROAUTH_RECORD=true to overwrite the expected outcome
// in each fixture file with what the testnet returned — use this to re-baseline
// after a protocol upgrade or testnet reset.
//
// When a fixture's live outcome differs from its recorded expected outcome,
// the test fails and prints a diff. The scheduled workflow that runs these
// tests opens a GitHub issue on failure (see .github/workflows/rpc-drift.yml).
package rpcflow

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const defaultRPCURL = "https://soroban-testnet.stellar.org"

// fixtureDir returns the testdata/rpcflow directory relative to this file's
// location in the repository.
func fixtureDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file is the absolute path to replay_test.go; walk up one level to reach
	// the repo root (rpcflow's parent), then descend into testdata/rpcflow.
	root := filepath.Join(filepath.Dir(file), "..")
	return filepath.Join(root, "testdata", "rpcflow")
}

// newClient returns an RPC client pointed at SOROAUTH_RPC_URL or the testnet default.
func newClient(t *testing.T) *rpcclient.Client {
	t.Helper()
	url := os.Getenv("SOROAUTH_RPC_URL")
	if url == "" {
		url = defaultRPCURL
	}
	client := rpcclient.NewClient(url, nil)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestRPCFixtures replays every non-pending fixture in testdata/rpcflow against
// the live testnet and compares the outcome with the recorded expected_outcome.
// Any mismatch fails the test, which causes the CI workflow to open a GitHub
// issue.
//
// This test is not about the functional correctness of a specific transaction;
// it is a drift detector. If a fixture that was previously accepted is now
// rejected (or vice versa), or if the specific error code changed, that change
// in RPC behaviour is what we want to surface.
func TestRPCFixtures(t *testing.T) {
	dir := fixtureDir(t)

	fixtures, err := Load(dir)
	if err != nil {
		t.Fatalf("loading fixtures from %s: %v", dir, err)
	}

	record := os.Getenv("SOROAUTH_RECORD") == "true"
	if record {
		t.Log("SOROAUTH_RECORD=true: recording mode — fixture files will be updated")
	}

	client := newClient(t)

	// Verify the RPC endpoint is reachable before running fixtures.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	health, err := client.GetHealth(ctx)
	cancel()
	if err != nil {
		url := os.Getenv("SOROAUTH_RPC_URL")
		if url == "" {
			url = defaultRPCURL
		}
		t.Fatalf("RPC health check at %s failed: %v — is SOROAUTH_RPC_URL set correctly?", url, err)
	}
	t.Logf("RPC endpoint healthy: status=%s", health.Status)

	ran := 0
	for _, f := range fixtures {
		f := f
		if f.Pending {
			t.Logf("skipping pending fixture %q (run with SOROAUTH_RECORD=true to record it)", f.Name)
			continue
		}
		ran++
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			replayOne(t, client, f, dir, record)
		})
	}
	if ran == 0 {
		t.Skip("all fixtures are pending; record some first with SOROAUTH_RECORD=true")
	}
}

// replayOne replays one fixture and compares the outcome with f.ExpectedOutcome.
func replayOne(t *testing.T, client *rpcclient.Client, f Fixture, dir string, record bool) {
	t.Helper()

	// Decode the signed entry XDR.
	raw, err := base64.StdEncoding.DecodeString(f.SignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding signed_entry_xdr: %v", err)
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := entry.UnmarshalBinary(raw); err != nil {
		t.Fatalf("unmarshalling entry XDR: %v", err)
	}

	invokeXDR, err := buildSimulateRequest(entry)
	if err != nil {
		t.Fatalf("building simulate request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction: invokeXDR,
	})
	if err != nil {
		t.Fatalf("SimulateTransaction: %v", err)
	}

	// Determine the observed outcome.
	var observed Outcome
	var observedCode string
	if resp.Error != "" {
		observed = OutcomeRejected
		observedCode = extractErrorCode(resp.Error)
	} else {
		observed = OutcomeAccepted
	}

	t.Logf("fixture %q: expected=%s observed=%s", f.Name, f.ExpectedOutcome, observed)
	if observedCode != "" {
		t.Logf("  error code: %s", observedCode)
	}

	if record {
		if err := updateFixture(dir, f, observed, observedCode); err != nil {
			t.Errorf("recording fixture %q: %v", f.Name, err)
		}
		return
	}

	if observed != f.ExpectedOutcome {
		t.Errorf("DRIFT DETECTED for fixture %q:\n  expected outcome: %s\n  observed outcome: %s\n  error:            %s\n\nIf this is a legitimate protocol change, re-record with SOROAUTH_RECORD=true.",
			f.Name, f.ExpectedOutcome, observed, resp.Error)
		return
	}
	if observed == OutcomeRejected && observedCode != f.ExpectedErrorCode {
		t.Errorf("DRIFT DETECTED for fixture %q:\n  expected error code: %q\n  observed error code: %q\n  full error: %s",
			f.Name, f.ExpectedErrorCode, observedCode, resp.Error)
	}
}

// buildSimulateRequest constructs a base64-encoded transaction envelope that
// carries the given auth entry. The envelope is never submitted; it is only
// used for simulateTransaction to observe whether the RPC accepts the entry.
func buildSimulateRequest(entry xdr.SorobanAuthorizationEntry) (string, error) {
	fn := entry.RootInvocation.Function
	if fn.Type != xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn {
		return "", fmt.Errorf("root invocation is not a contract function call")
	}
	contractFn := fn.ContractFn

	op := xdr.Operation{
		Body: xdr.OperationBody{
			Type: xdr.OperationTypeInvokeHostFunction,
			InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
				HostFunction: xdr.HostFunction{
					Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
					InvokeContract: &xdr.InvokeContractArgs{
						ContractAddress: contractFn.ContractAddress,
						FunctionName:    contractFn.FunctionName,
						Args:            contractFn.Args,
					},
				},
				Auth: []xdr.SorobanAuthorizationEntry{entry},
			},
		},
	}

	// Use a well-known inactive source account. It does not need to exist for
	// simulateTransaction; the simulate call does not check sequence numbers.
	sourceAccount := xdr.MustMuxedAddress("GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN")

	envelope := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{
			Tx: xdr.Transaction{
				SourceAccount: sourceAccount,
				Fee:           100,
				SeqNum:        1,
				Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
				Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
				Operations:    []xdr.Operation{op},
				Ext:           xdr.TransactionExt{V: 0},
			},
		},
	}

	b64, err := xdr.MarshalBase64(envelope)
	if err != nil {
		return "", fmt.Errorf("encoding envelope: %w", err)
	}
	return b64, nil
}

// extractErrorCode extracts a recognisable error code from an RPC error string
// (e.g. "Error(Contract, #4)" → "Error(Contract, #4)"). If no code is found,
// it returns the first 80 characters of the error string.
func extractErrorCode(errStr string) string {
	for _, prefix := range []string{"Error(Contract,", "Error(Wasm,", "Error(Value,"} {
		if i := strings.Index(errStr, prefix); i >= 0 {
			end := strings.Index(errStr[i:], ")")
			if end >= 0 {
				return errStr[i : i+end+1]
			}
		}
	}
	if len(errStr) > 80 {
		return errStr[:80]
	}
	return errStr
}

// updateFixture writes the observed outcome back into the fixture JSON file on
// disk so that SOROAUTH_RECORD=true re-baselines the fixture.
func updateFixture(dir string, f Fixture, observed Outcome, observedCode string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading fixture dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		candidate, err := loadOne(path)
		if err != nil || candidate.Name != f.Name {
			continue
		}

		candidate.ExpectedOutcome = observed
		candidate.ExpectedErrorCode = observedCode
		candidate.Pending = false
		candidate.RecordedAt = time.Now().UTC().Format(time.RFC3339)

		data, err := json.MarshalIndent(candidate, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding fixture: %w", err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing fixture: %w", err)
		}
		return nil
	}
	return fmt.Errorf("fixture %q not found in %s", f.Name, dir)
}
