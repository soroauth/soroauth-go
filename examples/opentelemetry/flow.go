package opentelemetry

import (
	"context"
	"fmt"
	"sync"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

// Span names, one per stage of rpcflow.SignAndSubmit. Every name is
// "soroauth." plus the stage, so the whole flow filters as one prefix in a
// tracing backend.
const (
	// SpanFlow is the root span around the whole flow.
	SpanFlow = "soroauth.sign_and_submit"
	// SpanSimulateRecord is the record pass: the RPC reports which addresses
	// must authorize the call and returns unsigned entries.
	SpanSimulateRecord = "soroauth.simulate.record"
	// SpanLatestLedger is the ledger read that resolves a default expiration.
	// It appears only when the caller left ValidUntilLedger at zero.
	SpanLatestLedger = "soroauth.latest_ledger"
	// SpanSign is one Signer.Sign call, once per signed credential node.
	SpanSign = "soroauth.sign"
	// SpanSimulateEnforce is the enforcing pass: the same transaction
	// re-simulated carrying the signed entries, so the resource fee is the
	// price of the transaction that is actually submitted.
	SpanSimulateEnforce = "soroauth.simulate.enforce"
	// SpanSend is sendTransaction.
	SpanSend = "soroauth.send"
	// SpanPoll is polling getTransaction to a terminal status.
	SpanPoll = "soroauth.poll"
)

// Attribute keys. Every value is structural or public: addresses, counts,
// fees, ledgers, statuses and the transaction hash. No key carries a secret,
// an authorization entry, an envelope, a preimage, a payload or a signature,
// and flow_test.go asserts that over every span a run produces.
const (
	// AttrAuthMode is the simulation's auth mode ("record" or "enforce").
	AttrAuthMode = attribute.Key("soroauth.simulate.auth_mode")
	// AttrMinResourceFee is the minimum resource fee, in stroops, that a
	// simulation reported.
	AttrMinResourceFee = attribute.Key("soroauth.simulate.min_resource_fee")
	// AttrRecordResourceFee is the record pass's minimum resource fee, copied
	// onto the enforcing pass and the root span so the two sit side by side.
	AttrRecordResourceFee = attribute.Key("soroauth.simulate.record_min_resource_fee")
	// AttrEnforceResourceFee is the enforcing pass's minimum resource fee, on
	// the root span.
	AttrEnforceResourceFee = attribute.Key("soroauth.simulate.enforce_min_resource_fee")
	// AttrResourceFeeDelta is the enforcing pass's fee minus the record
	// pass's: how far the record pass's price was from the price of the
	// transaction actually submitted. It can be negative. On the testnet run
	// in this example's README the record pass reported 130770 stroops and
	// the enforcing pass 15365, a delta of -115405, so it is not "the cost
	// of the signatures"; it is the error a transaction priced from the
	// record pass alone would have carried.
	AttrResourceFeeDelta = attribute.Key("soroauth.simulate.resource_fee_delta")
	// AttrAuthEntries is how many authorization entries a simulation returned.
	AttrAuthEntries = attribute.Key("soroauth.simulate.auth_entries")
	// AttrLatestLedger is the latest ledger an RPC response reported.
	AttrLatestLedger = attribute.Key("soroauth.ledger.latest")
	// AttrSignerAddress is the public G… or C… address a Signer signs for.
	AttrSignerAddress = attribute.Key("soroauth.signer.address")
	// AttrPreimageType is the preimage's envelope type, which says whether the
	// signature is address-bound (CAP-71) or legacy (CAP-46-11).
	AttrPreimageType = attribute.Key("soroauth.preimage.type")
	// AttrTxHash is the transaction hash. It is public once sent.
	AttrTxHash = attribute.Key("soroauth.tx.hash")
	// AttrTxStatus is the RPC's reported transaction status.
	AttrTxStatus = attribute.Key("soroauth.tx.status")
	// AttrTxLedger is the ledger the transaction landed in.
	AttrTxLedger = attribute.Key("soroauth.tx.ledger")
	// AttrCredentialArm is the credential arm read back off the submitted
	// envelope by rpcflow, not assumed from what was built.
	AttrCredentialArm = attribute.Key("soroauth.credential_arm")
	// AttrErrorType is the Go type of a failed call's error. The error text
	// itself is never recorded: an RPC or host message is not under this
	// example's control, and a trace backend is a poor place to discover it
	// echoed something it should not have.
	AttrErrorType = attribute.Key("error.type")
)

// SignAndSubmit runs rpcflow.SignAndSubmit as one trace rooted at SpanFlow.
//
// It does not fork the flow. rpcflow.Client and soroauth.Signer are both
// interfaces, so the RPC client and every signer are wrapped in decorators
// that open a child span per call, and the flow itself runs unchanged. That is
// also why the stages are traced exactly as rpcflow orders them: the trace
// cannot show a pass rpcflow did not run.
func SignAndSubmit(ctx context.Context, tracer trace.Tracer, p rpcflow.Params) (rpcflow.Submission, error) {
	ctx, span := tracer.Start(ctx, SpanFlow, trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	client := &tracingClient{next: p.Client, tracer: tracer}
	p.Client = client
	signers := make([]soroauth.Signer, len(p.Signers))
	for i, s := range p.Signers {
		signers[i] = &tracingSigner{next: s, tracer: tracer}
	}
	p.Signers = signers

	sub, err := rpcflow.SignAndSubmit(ctx, p)

	span.SetAttributes(client.feeAttributes(true)...)
	if sub.Hash != "" {
		span.SetAttributes(AttrTxHash.String(sub.Hash))
	}
	if sub.Status != "" {
		span.SetAttributes(AttrTxStatus.String(sub.Status))
	}
	if sub.Ledger != 0 {
		span.SetAttributes(AttrTxLedger.Int64(int64(sub.Ledger)))
	}
	if sub.Arm != "" {
		span.SetAttributes(AttrCredentialArm.String(sub.Arm))
	}

	switch {
	case err != nil:
		failSpan(span, "the flow could not be completed", err)
	case sub.Status != rpc.TransactionStatusSuccess:
		span.SetStatus(codes.Error, "the transaction did not succeed: "+sub.Status)
	default:
		span.SetStatus(codes.Ok, "")
	}
	return sub, err
}

// failSpan marks a span failed without recording the error's text.
func failSpan(span trace.Span, description string, err error) {
	span.SetAttributes(AttrErrorType.String(fmt.Sprintf("%T", err)))
	span.SetStatus(codes.Error, description)
}

// tracingClient is an rpcflow.Client that opens one span per RPC call.
//
// It is created per flow, so the record pass's fee it remembers belongs to the
// same run as the enforcing pass it is compared with.
type tracingClient struct {
	next   rpcflow.Client
	tracer trace.Tracer

	mu         sync.Mutex
	recordFee  int64
	enforceFee int64
	haveRecord bool
	haveEnf    bool
}

// SimulateTransaction traces a simulation as the record or the enforcing pass,
// by the auth mode the flow asked for.
func (c *tracingClient) SimulateTransaction(ctx context.Context, req rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error) {
	name := "soroauth.simulate." + req.AuthMode
	switch req.AuthMode {
	case rpc.AuthModeRecord:
		name = SpanSimulateRecord
	case rpc.AuthModeEnforce:
		name = SpanSimulateEnforce
	}
	ctx, span := c.tracer.Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(AttrAuthMode.String(req.AuthMode)))
	defer span.End()

	resp, err := c.next.SimulateTransaction(ctx, req)
	if err != nil {
		failSpan(span, "simulateTransaction failed", err)
		return resp, err
	}
	if resp.Error != "" {
		// The host's message is not recorded, for the reason AttrErrorType
		// gives; rpcflow returns it to the caller unchanged.
		span.SetStatus(codes.Error, "the rpc refused the simulation")
		return resp, nil
	}

	entries := 0
	for _, result := range resp.Results {
		if result.AuthXDR != nil {
			entries += len(*result.AuthXDR)
		}
	}
	span.SetAttributes(
		AttrMinResourceFee.Int64(resp.MinResourceFee),
		AttrAuthEntries.Int(entries),
		AttrLatestLedger.Int64(int64(resp.LatestLedger)),
	)

	c.mu.Lock()
	switch req.AuthMode {
	case rpc.AuthModeRecord:
		c.recordFee, c.haveRecord = resp.MinResourceFee, true
	case rpc.AuthModeEnforce:
		c.enforceFee, c.haveEnf = resp.MinResourceFee, true
	}
	c.mu.Unlock()
	if req.AuthMode == rpc.AuthModeEnforce {
		span.SetAttributes(c.feeAttributes(false)...)
	}
	span.SetStatus(codes.Ok, "")
	return resp, nil
}

// feeAttributes reports the record fee and, once both passes have run, the
// delta. withEnforce adds the enforcing fee itself, for the root span; the
// enforcing span already carries it as AttrMinResourceFee.
func (c *tracingClient) feeAttributes(withEnforce bool) []attribute.KeyValue {
	c.mu.Lock()
	defer c.mu.Unlock()
	var attrs []attribute.KeyValue
	if c.haveRecord {
		attrs = append(attrs, AttrRecordResourceFee.Int64(c.recordFee))
	}
	if c.haveEnf && withEnforce {
		attrs = append(attrs, AttrEnforceResourceFee.Int64(c.enforceFee))
	}
	if c.haveRecord && c.haveEnf {
		attrs = append(attrs, AttrResourceFeeDelta.Int64(c.enforceFee-c.recordFee))
	}
	return attrs
}

// GetLatestLedger traces the ledger read rpcflow makes to resolve a default
// expiration.
func (c *tracingClient) GetLatestLedger(ctx context.Context) (rpc.GetLatestLedgerResponse, error) {
	ctx, span := c.tracer.Start(ctx, SpanLatestLedger, trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	resp, err := c.next.GetLatestLedger(ctx)
	if err != nil {
		failSpan(span, "getLatestLedger failed", err)
		return resp, err
	}
	span.SetAttributes(AttrLatestLedger.Int64(int64(resp.Sequence)))
	span.SetStatus(codes.Ok, "")
	return resp, nil
}

// SendTransaction traces the submission. The envelope it sends is not
// recorded; the hash and status the RPC answers with are.
func (c *tracingClient) SendTransaction(ctx context.Context, req rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error) {
	ctx, span := c.tracer.Start(ctx, SpanSend, trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	resp, err := c.next.SendTransaction(ctx, req)
	if err != nil {
		failSpan(span, "sendTransaction failed", err)
		return resp, err
	}
	span.SetAttributes(AttrTxHash.String(resp.Hash), AttrTxStatus.String(resp.Status))
	if resp.Status == "ERROR" {
		span.SetStatus(codes.Error, "the rpc rejected the transaction")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return resp, nil
}

// PollTransaction traces polling to a terminal status.
func (c *tracingClient) PollTransaction(ctx context.Context, txHash string) (rpc.GetTransactionResponse, error) {
	ctx, span := c.tracer.Start(ctx, SpanPoll,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(AttrTxHash.String(txHash)))
	defer span.End()
	resp, err := c.next.PollTransaction(ctx, txHash)
	if err != nil {
		failSpan(span, "polling the transaction failed", err)
		return resp, err
	}
	span.SetAttributes(AttrTxStatus.String(resp.Status), AttrTxLedger.Int64(int64(resp.Ledger)))
	if resp.Status == rpc.TransactionStatusSuccess {
		span.SetStatus(codes.Ok, "")
	} else {
		span.SetStatus(codes.Error, "the transaction did not succeed: "+resp.Status)
	}
	return resp, nil
}

// tracingSigner is a soroauth.Signer that opens one span per Sign call. It
// reports the same Address as the signer it wraps, so AuthorizeAll matches it
// to exactly the nodes the unwrapped signer would sign.
type tracingSigner struct {
	next   soroauth.Signer
	tracer trace.Tracer
}

// Address returns the wrapped signer's address.
func (s *tracingSigner) Address() string { return s.next.Address() }

// Sign traces one signature. Neither the preimage nor the payload nor the
// returned signature is recorded: only the address and the preimage's type.
func (s *tracingSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	ctx, span := s.tracer.Start(ctx, SpanSign, trace.WithAttributes(
		AttrSignerAddress.String(s.next.Address()),
		AttrPreimageType.String(preimage.Type.String()),
	))
	defer span.End()
	sig, err := s.next.Sign(ctx, preimage, payload)
	if err != nil {
		failSpan(span, "the signer refused or failed", err)
		return sig, err
	}
	span.SetStatus(codes.Ok, "")
	return sig, nil
}
