package opentelemetry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

// The record and enforcing passes report different minimum resource fees, so
// the delta attribute has a non-zero value to assert. Its sign is arbitrary
// here: on testnet the record pass has been observed pricing higher.
const (
	recordFee  = 51_000
	enforceFee = 58_250
)

// fakeClient answers the four rpcflow.Client calls offline and keeps what was
// sent, so the test can list every byte string that must never reach a span.
type fakeClient struct {
	recorded     string
	latest       uint32
	simErr       error
	pollStatus   string
	sentEnvelope string
}

func (f *fakeClient) SimulateTransaction(_ context.Context, req rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error) {
	if f.simErr != nil {
		return rpc.SimulateTransactionResponse{}, f.simErr
	}
	data, err := xdr.MarshalBase64(xdr.SorobanTransactionData{})
	if err != nil {
		return rpc.SimulateTransactionResponse{}, err
	}
	fee := int64(recordFee)
	if req.AuthMode == rpc.AuthModeEnforce {
		fee = enforceFee
	}
	auth := []string{f.recorded}
	return rpc.SimulateTransactionResponse{
		TransactionDataXDR: data,
		MinResourceFee:     fee,
		LatestLedger:       4200,
		Results:            []rpc.SimulateHostFunctionResult{{AuthXDR: &auth}},
	}, nil
}

func (f *fakeClient) GetLatestLedger(context.Context) (rpc.GetLatestLedgerResponse, error) {
	return rpc.GetLatestLedgerResponse{Sequence: f.latest}, nil
}

func (f *fakeClient) SendTransaction(_ context.Context, req rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error) {
	f.sentEnvelope = req.Transaction
	return rpc.SendTransactionResponse{Hash: strings.Repeat("ab", 32), Status: "PENDING"}, nil
}

func (f *fakeClient) PollTransaction(context.Context, string) (rpc.GetTransactionResponse, error) {
	status := f.pollStatus
	if status == "" {
		status = rpc.TransactionStatusSuccess
	}
	return rpc.GetTransactionResponse{TransactionDetails: rpc.TransactionDetails{Status: status, Ledger: 4242}}, nil
}

func testKey(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving %q: %v", label, err)
	}
	return kp
}

// recordedEntry is the unsigned address-arm entry a record pass returns for
// signer.
func recordedEntry(t *testing.T, signer string) string {
	t.Helper()
	address, err := soroauth.ParseAddress(signer)
	if err != nil {
		t.Fatalf("parsing %q: %v", signer, err)
	}
	var contractID xdr.ContractId
	contractID[0] = 1
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     7,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatalf("encoding the recorded entry: %v", err)
	}
	return encoded
}

type flowRun struct {
	spans  []sdktrace.ReadOnlySpan
	client *fakeClient
	payer  *keypair.Full
	signer *keypair.Full
	sub    rpcflow.Submission
	err    error
}

func runFlow(t *testing.T, client *fakeClient, validUntil uint32) flowRun {
	t.Helper()
	payer := testKey(t, "soroauth-otel-example-payer")
	signer := testKey(t, "soroauth-otel-example-signer")
	client.recorded = recordedEntry(t, signer.Address())

	var contractID xdr.ContractId
	contractID[0] = 1
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	sub, err := SignAndSubmit(context.Background(), provider.Tracer("test"), rpcflow.Params{
		Source: &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operation: txnbuild.InvokeHostFunction{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
			SourceAccount: payer.Address(),
		},
		Signers:           []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: network.TestNetworkPassphrase,
		Client:            client,
		ValidUntilLedger:  validUntil,
	})
	return flowRun{spans: recorder.Ended(), client: client, payer: payer, signer: signer, sub: sub, err: err}
}

func spanNamed(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	t.Fatalf("no span named %s", name)
	return nil
}

func intAttr(t *testing.T, s sdktrace.ReadOnlySpan, key string) int64 {
	t.Helper()
	for _, kv := range s.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.AsInt64()
		}
	}
	t.Fatalf("span %s has no attribute %s", s.Name(), key)
	return 0
}

// TestOneTraceSpansTheWholeFlow: every stage is a child of one root span, in
// the order rpcflow runs them, all in one trace.
func TestOneTraceSpansTheWholeFlow(t *testing.T) {
	tests := []struct {
		name       string
		validUntil uint32
		want       []string
	}{
		{"explicit expiration", 1234567,
			[]string{SpanSimulateRecord, SpanSign, SpanSimulateEnforce, SpanSend, SpanPoll}},
		{"default expiration reads the ledger", 0,
			[]string{SpanSimulateRecord, SpanLatestLedger, SpanSign, SpanSimulateEnforce, SpanSend, SpanPoll}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := runFlow(t, &fakeClient{latest: 5000}, tt.validUntil)
			if run.err != nil {
				t.Fatalf("SignAndSubmit: %v", run.err)
			}
			root := spanNamed(t, run.spans, SpanFlow)
			if root.Status().Code != codes.Ok {
				t.Errorf("root status %v, want Ok", root.Status())
			}
			var got []string
			for _, s := range run.spans {
				if s.SpanContext().TraceID() != root.SpanContext().TraceID() {
					t.Errorf("span %s is in trace %s, not the flow's trace %s", s.Name(), s.SpanContext().TraceID(), root.SpanContext().TraceID())
				}
				if s.Name() == SpanFlow {
					continue
				}
				if s.Parent().SpanID() != root.SpanContext().SpanID() {
					t.Errorf("span %s is not a child of %s", s.Name(), SpanFlow)
				}
				if !strings.HasPrefix(s.Name(), "soroauth.") {
					t.Errorf("span %s does not carry the soroauth. prefix", s.Name())
				}
				got = append(got, s.Name())
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("child spans ended in order %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResourceFeeDifferenceIsVisible: the enforcing pass and the root span
// both carry the difference between the two passes' fees, which is the point
// of running the second pass.
func TestResourceFeeDifferenceIsVisible(t *testing.T) {
	run := runFlow(t, &fakeClient{}, 1234567)
	if run.err != nil {
		t.Fatalf("SignAndSubmit: %v", run.err)
	}
	record := spanNamed(t, run.spans, SpanSimulateRecord)
	enforce := spanNamed(t, run.spans, SpanSimulateEnforce)
	root := spanNamed(t, run.spans, SpanFlow)

	if got := intAttr(t, record, string(AttrMinResourceFee)); got != recordFee {
		t.Errorf("record pass fee %d, want %d", got, recordFee)
	}
	if got := intAttr(t, enforce, string(AttrMinResourceFee)); got != enforceFee {
		t.Errorf("enforcing pass fee %d, want %d", got, enforceFee)
	}
	for _, s := range []sdktrace.ReadOnlySpan{enforce, root} {
		if got := intAttr(t, s, string(AttrRecordResourceFee)); got != recordFee {
			t.Errorf("%s record fee %d, want %d", s.Name(), got, recordFee)
		}
		if got := intAttr(t, s, string(AttrResourceFeeDelta)); got != enforceFee-recordFee {
			t.Errorf("%s fee delta %d, want %d", s.Name(), got, enforceFee-recordFee)
		}
	}
	if got := intAttr(t, root, string(AttrEnforceResourceFee)); got != enforceFee {
		t.Errorf("root enforcing fee %d, want %d", got, enforceFee)
	}
}

// TestNoSpanCarriesASecretAnEntryOrASignature collects every string a trace
// exports — span names, status descriptions, attribute keys and values, event
// names and attributes — and asserts that none contains a seed, an
// authorization entry (unsigned or signed), the submitted envelope, or any
// signature, in base64 or hex.
func TestNoSpanCarriesASecretAnEntryOrASignature(t *testing.T) {
	tests := []struct {
		name   string
		client *fakeClient
	}{
		{"successful run", &fakeClient{}},
		{"on-chain failure", &fakeClient{pollStatus: rpc.TransactionStatusFailed}},
		{"rpc failure", &fakeClient{simErr: errors.New("connection reset while sending AAAAsecretish")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := runFlow(t, tt.client, 1234567)

			forbidden := map[string]string{
				"payer seed":     run.payer.Seed(),
				"signer seed":    run.signer.Seed(),
				"recorded entry": run.client.recorded,
				"rpc error text": "AAAAsecretish",
			}
			if env := run.client.sentEnvelope; env != "" {
				forbidden["submitted envelope"] = env
				var envelope xdr.TransactionEnvelope
				if err := xdr.SafeUnmarshalBase64(env, &envelope); err != nil {
					t.Fatalf("decoding the submitted envelope: %v", err)
				}
				for i, sig := range envelope.Signatures() {
					forbidden["envelope signature (base64)"+string(rune('0'+i))] = base64.StdEncoding.EncodeToString(sig.Signature)
					forbidden["envelope signature (hex)"+string(rune('0'+i))] = hex.EncodeToString(sig.Signature)
				}
				for _, op := range envelope.Operations() {
					invoke, ok := op.Body.GetInvokeHostFunctionOp()
					if !ok {
						continue
					}
					for _, entry := range invoke.Auth {
						encoded, err := xdr.MarshalBase64(entry)
						if err != nil {
							t.Fatalf("encoding a signed entry: %v", err)
						}
						forbidden["signed entry"] = encoded
						sig, err := xdr.MarshalBase64(entry.Credentials.Address.Signature)
						if err != nil {
							t.Fatalf("encoding a signature: %v", err)
						}
						forbidden["entry signature ScVal"] = sig
						vec, ok := entry.Credentials.Address.Signature.GetVec()
						if !ok || vec == nil {
							t.Fatal("the signed entry carries no signature vector")
						}
						for _, item := range *vec {
							m, ok := item.GetMap()
							if !ok || m == nil {
								continue
							}
							for _, kv := range *m {
								if raw, ok := kv.Val.GetBytes(); ok && len(raw) == 64 {
									forbidden["entry signature (base64)"] = base64.StdEncoding.EncodeToString(raw)
									forbidden["entry signature (hex)"] = hex.EncodeToString(raw)
								}
							}
						}
						if forbidden["entry signature (hex)"] == "" {
							t.Fatal("found no 64-byte signature in the signed entry; the scan would not cover it")
						}
					}
				}
			} else if tt.client.simErr == nil {
				t.Fatal("the flow submitted nothing; the scan would prove nothing about signed bytes")
			}

			var exported []string
			for _, s := range run.spans {
				exported = append(exported, s.Name(), s.Status().Description)
				for _, kv := range s.Attributes() {
					exported = append(exported, string(kv.Key), kv.Value.Emit())
				}
				for _, ev := range s.Events() {
					exported = append(exported, ev.Name)
					for _, kv := range ev.Attributes {
						exported = append(exported, string(kv.Key), kv.Value.Emit())
					}
				}
			}
			if len(exported) == 0 {
				t.Fatal("no span was exported; the scan would pass vacuously")
			}
			for what, value := range forbidden {
				for _, s := range exported {
					if value != "" && strings.Contains(s, value) {
						t.Errorf("an exported span string carries the %s: %q", what, s)
					}
				}
			}
		})
	}
}

// TestFailuresMarkTheTrace: an on-chain failure and an RPC failure each mark
// the root span as an error, so a failed run is visible in a backend.
func TestFailuresMarkTheTrace(t *testing.T) {
	t.Run("on-chain failure", func(t *testing.T) {
		run := runFlow(t, &fakeClient{pollStatus: rpc.TransactionStatusFailed}, 1234567)
		if run.err != nil {
			t.Fatalf("an on-chain rejection is an outcome, not an error: %v", run.err)
		}
		if got := spanNamed(t, run.spans, SpanFlow).Status().Code; got != codes.Error {
			t.Errorf("root status %v, want Error", got)
		}
		if got := spanNamed(t, run.spans, SpanPoll).Status().Code; got != codes.Error {
			t.Errorf("poll status %v, want Error", got)
		}
	})
	t.Run("rpc failure", func(t *testing.T) {
		run := runFlow(t, &fakeClient{simErr: errors.New("connection reset")}, 1234567)
		if run.err == nil {
			t.Fatal("a failed simulation returned no error")
		}
		for _, name := range []string{SpanFlow, SpanSimulateRecord} {
			if got := spanNamed(t, run.spans, name).Status().Code; got != codes.Error {
				t.Errorf("%s status %v, want Error", name, got)
			}
		}
	})
}

// TestRenderTreeShowsTheFlowInOrder pins the shape the README's captured trace
// is printed in.
func TestRenderTreeShowsTheFlowInOrder(t *testing.T) {
	run := runFlow(t, &fakeClient{}, 1234567)
	out := RenderTree(run.spans)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{SpanFlow, "├─ " + SpanSimulateRecord, "├─ " + SpanSign, "├─ " + SpanSimulateEnforce, "├─ " + SpanSend, "└─ " + SpanPoll}
	if len(lines) != len(want) {
		t.Fatalf("rendered %d lines, want %d:\n%s", len(lines), len(want), out)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(lines[i], prefix+"  ") {
			t.Errorf("line %d is %q, want it to start with %q", i, lines[i], prefix)
		}
	}
	if !strings.Contains(lines[3], "simulate.resource_fee_delta=7250") {
		t.Errorf("the enforcing pass line does not show the fee delta: %q", lines[3])
	}
}
