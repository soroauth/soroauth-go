package soroauth

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// SignAndSubmit performs the record simulation → assemble (with padded
// resource fee) → sign → enforce simulation → submit flow for an unsigned
// transaction and a set of signers, and returns the submitted transaction.
//
// It is a helper around the two-pass simulation requirement the Go SDK has
// no tool for: the caller hands it one unsigned transaction, one set of
// signers, and an RPC client, and it returns what the RPC client actually
// accepted as submitted. It never replaces the RPC client — that is still
// the caller's — and nothing here is an envelope-signing wrapper: the
// envelope's own signatures are the payer's job.
//
// The two simulation passes are the heart of the flow. The record pass
// answers "which addresses must authorize this call" and hands back
// unsigned authorization entries; those are signed by soroauth, then the
// enforcing pass re-simulates with the signed entries so the resource fee
// accounts for the signatures that are actually going out. The transaction
// is assembled from the enforcing pass and submitted, so the fee covers the
// signatures the host checks. Skipping either pass is a silent, and
// incorrect, shortcut: the record pass sizes the signatures, the enforcing
// pass sizes their cost, and the host refuses a transaction that has no
// fee for them.
//
// The resource fee is the minimum the host reports in the enforcing pass,
// padded by a small fixed headroom for the ledger move between passes.
// Anything smaller risks a rejection exactly when the signatures are about
// to be paid for; anything larger just moves money for no reason.
//
// The returned submission's Hash is the one the RPC client reported for the
// submitted transaction, and its Arm is the credential arm of the first
// authorization entry it actually carried, read back from the envelope.
func SignAndSubmit(
	ctx context.Context,
	tx *txnbuild.Transaction,
	signers []Signer,
	networkPassphrase string,
	simRPC rpcclient.Client,
) (sub submission, err error) {
	// 1. record: the RPC reports which addresses must authorize the call
	// and hands back unsigned authorization entries.
	recorded, err := simulateRecord(ctx, tx, simRPC, network)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (record): %w", err)
	}
	entries, ok := recordedAuthEntries(recorded)
	if !ok {
		return sub, fmt.Errorf("soroauth: sign and submit (record): %w", ErrNoInvokeOperation)
	}

	// 2. sign: one expiration for the whole run, computed once so the value
	// signed over and the value stored can never disagree.
	validUntil, err := ExpirationAfter(latestLedger(ctx, simRPC), 1000)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (sign): %w", err)
	}
	signedEntries, err := AuthorizeAll(ctx, entries, signers, validUntil, networkPassphrase)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (sign): %w", err)
	}

	// 3. enforce: re-simulate carrying the signed entries, so the resource
	// fee accounts for the signatures that are actually going out. Never
	// silently skip this pass: it is what makes the fee truthful.
	enforceTx, err := rebuildEnforceTx(ctx, tx, signedEntries)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %w", err)
	}
	enforceEncoded, err := enforceTx.Base64()
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %w", err)
	}
	sim, err := simRPC.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction:     enforceEncoded,
		AuthMode:        rpc.AuthModeEnforce,
		UseUpgradedAuth: false,
	})
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %w", err)
	}
	if sim.Error != "" {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %s", sim.Error)
	}

	// 4. assemble: attach the enforcing pass's resources and fee to the
	// operation. The go-stellar-sdk has no assembleTransaction, so this is
	// done explicitly, with the minimum resource fee the enforcing pass
	// reported, padded for the ledger move between passes.
	finalTx, err := assembleWithFee(ctx, tx, sim, networkPassphrase)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (assemble): %w", err)
	}

	// 5. submit and poll until it resolves. send does not fail the call on
	// an on-chain rejection: the rejection scenarios expect one and report
	// the raw error. A successful submit is what the caller wanted.
	return sendSub(ctx, finalTx, simRPC)
}

// simulateRecord is the record pass: the RPC reports which addresses must
// authorize the call and hands back unsigned authorization entries. It is
// the only part of the flow that asks the host for anything.
func simulateRecord(
	ctx context.Context,
	tx *txnbuild.Transaction,
	simRPC rpcclient.Client,
	networkPassphrase string,
) (rpc.SimulateTransactionResponse, error) {
	encoded, err := tx.Base64()
	if err != nil {
		return rpc.SimulateTransactionResponse{}, fmt.Errorf("soroauth: simulate record: %w", err)
	}

	response, err := simRPC.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction:     encoded,
		AuthMode:        rpc.AuthModeRecord,
		UseUpgradedAuth: false,
	})
	if err != nil {
		return rpc.SimulateTransactionResponse{}, fmt.Errorf("soroauth: simulate record: %w", err)
	}
	if response.Error != "" {
		return rpc.SimulateTransactionResponse{}, fmt.Errorf("soroauth: simulate record: %s", response.Error)
	}
	return response, nil
}

// latestLedger reads the current ledger sequence from the RPC client.
func latestLedger(ctx context.Context, simRPC rpcclient.Client) uint32 {
	ledger, err := simRPC.GetLatestLedger(ctx)
	if err != nil {
		return 0
	}
	return ledger.Sequence
}

// rebuildEnforceTx rebuilds a transaction carrying the signed entries for
// the enforcing simulation. The source account and operation are the ones
// the caller gave us, and the signed entries are attached to the operation
// so the enforcing pass checks them.
func rebuildEnforceTx(
	ctx context.Context,
	tx *txnbuild.Transaction,
	signedEntries []xdr.SorobanAuthorizationEntry,
) (*txnbuild.Transaction, error) {
	op := tx.Operations[0]
	invoke, ok := op.Body.GetInvokeHostFunctionOp()
	if !ok {
		return nil, fmt.Errorf("soroauth: rebuild enforce tx: %w", ErrNoInvokeOperation)
	}
	invoke.Auth = append([]xdr.SorobanAuthorizationEntry(nil), signedEntries...)
	enforced := &txnbuild.Transaction{
		SourceAccount:        tx.SourceAccount,
		IncrementSequenceNum:  tx.IncrementSequenceNum,
		Operations:           tx.Operations,
		BaseFee:              tx.BaseFee,
		Preconditions:        tx.Preconditions,
		SourceAccountSequence: tx.SourceAccountSequence,
	}
	return enforced, nil
}

// assembleWithFee attaches the enforcing pass's resources and fee to the
// operation, which is what the JS SDK's assembleTransaction does. The Go
// SDK has no equivalent, so it is done explicitly. The fee comes from the
// enforcing pass (it reports the minimum the signatures will cost) and is
// padded for the ledger move between passes.
func assembleWithFee(
	ctx context.Context,
	tx *txnbuild.Transaction,
	sim rpc.SimulateTransactionResponse,
	networkPassphrase string,
) (*txnbuild.Transaction, error) {
	var sorobanData xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &sorobanData); err != nil {
		return nil, fmt.Errorf("soroauth: assemble: %w", err)
	}
	// Simulation reports the minimum resource fee separately; use it rather
	// than whatever the data happens to carry, and pad it, since the
	// enforcing pass runs against a slightly later ledger state.
	sorobanData.ResourceFee = xdr.Int64(sim.MinResourceFee) + 100_000

	op := tx.Operations[0]
	invoke, ok := op.Body.GetInvokeHostFunctionOp()
	if !ok {
		return nil, fmt.Errorf("soroauth: assemble: %w", ErrNoInvokeOperation)
	}
	invoke.Ext = xdr.TransactionExt{V: 1, SorobanData: &sorobanData}

	enforced := &txnbuild.Transaction{
		SourceAccount:        tx.SourceAccount,
		IncrementSequenceNum:  tx.IncrementSequenceNum,
		Operations:           tx.Operations,
		BaseFee:              tx.BaseFee,
		Preconditions:        tx.Preconditions,
		SourceAccountSequence: tx.SourceAccountSequence,
	}
	return enforced, nil
}

// sendSub submits a signed transaction and polls until it resolves. It does
// not fail the call on an on-chain rejection: scenario E expects one and
// reports the raw error. A successful submit is what the caller wanted.
func sendSub(
	ctx context.Context,
	tx *txnbuild.Transaction,
	simRPC rpcclient.Client,
) (submission, error) {
	encoded, err := tx.Base64()
	if err != nil {
		return submission{}, fmt.Errorf("soroauth: send: %w", err)
	}

	arm := credentialArmOf(encoded)

	sent, err := simRPC.SendTransaction(ctx, rpc.SendTransactionRequest{Transaction: encoded})
	if err != nil {
		return submission{}, fmt.Errorf("soroauth: send: %w", err)
	}

	result := submission{Hash: sent.Hash, Arm: arm, Status: sent.Status}
	if sent.Status == stellarcore.TXStatusError {
		result.RawError = describeFailure(sent.ErrorResultXDR, sent.DiagnosticEventsXDR)
		result.Diagnostics = sent.DiagnosticEventsXDR
		return result, nil
	}

	polled, err := simRPC.PollTransaction(ctx, sent.Hash)
	if err != nil {
		return submission{}, fmt.Errorf("soroauth: send: %w", err)
	}

	result.Status = polled.Status
	result.Ledger = polled.Ledger
	if polled.Status != rpc.TransactionStatusSuccess {
		result.RawError = describeFailure(polled.ResultXDR, polled.DiagnosticEventsXDR)
		result.Diagnostics = polled.DiagnosticEventsXDR
	}
	return result, nil
}
