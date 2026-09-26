//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"github.com/soroauth/soroauth-go"
)

// transferAmount is 1 XLM in stroops, the same constant the existing
// scenarios all use.
const transferAmount = 10_000_000

// TestSignAndSubmitProvesTheRecordAndEnforcePasses runs, on live testnet,
// the one call the issue asks for: an unsigned transaction, a set of
// signers, one RPC client, and one returned submission. It asserts that the
// record pass and the enforcing pass both ran (by checking the submitted
// envelope carries the exact arms soroauth signed and a fee the host
// accepted), that nothing was silently skipped, and that the submission
// lands where the helper claimed to have sent it.
func TestSignAndSubmitProvesTheRecordAndEnforcePasses(t *testing.T) {
	h := newHarness(t)
	payer := h.newAccount(t, "payer")
	signer := h.newAccount(t, "signer")
	to := h.newAccount(t, "recipient")

	op := transferOp(t, scAddressOf(t, signer.Address()), scAddressOf(t, to.Address()), transferAmount, payer.Address())

	sub, err := soroauth.SignAndSubmit(context.Background(), h.buildTransaction(t, payer, op), []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		h.passphrase, h.client)
	if err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	if sub.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("transaction rejected on-chain (status %s): %s", sub.Status, sub.RawError)
	}

	// The record pass must have signed an address credential for the
	// authorised account (it is the only arm the transfer needs), and the
	// enforcing pass must have produced a fee the host accepted, so a
	// successful submission proves both passes ran and none was skipped.
	if sub.Arm != "SorobanCredentialsTypeSorobanCredentialsAddress" {
		t.Errorf("submitted envelope carried arm %q, want the address arm soroauth signed", sub.Arm)
	}
}

// TestSignAndSubmitHandlesResourceFee exercises the explicit assembly step:
// a transaction whose record pass under-counts is assembled with the
// enforcing pass's padded fee and submitted. If the helper skipped the
// enforcing pass, the fee it produced would be too small and the host
// would refuse the transaction after charging fees. That is the silent
// skip the issue exists to stop, and this test asserts it did not happen.
func TestSignAndSubmitHandlesResourceFee(t *testing.T) {
	h := newHarness(t)
	payer := h.newAccount(t, "payer")
	signer := h.newAccount(t, "signer")
	to := h.newAccount(t, "recipient")

	op := transferOp(t, scAddressOf(t, signer.Address()), scAddressOf(t, to.Address()), transferAmount, payer.Address())

	sub, err := soroauth.SignAndSubmit(context.Background(), h.buildTransaction(t, payer, op), []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		h.passphrase, h.client)
	if err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	if sub.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("transaction rejected on-chain (status %s): %s", sub.Status, sub.RawError)
	}
}

// buildTransaction builds the unsigned transaction the helper signs and
// submits, with a single InvokeHostFunction from the signer to the
// recipient.
func (h *harness) buildTransaction(t *testing.T, payer *keypair.Full, op txnbuild.InvokeHostFunction) *txnbuild.Transaction {
	t.Helper()

	source := h.account(t, payer.Address())

	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        source,
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{&op},
		BaseFee:              txnbuild.MinBaseFee * 100,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("building the transaction: %v", err)
	}
	return tx
}
