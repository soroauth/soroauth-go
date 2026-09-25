package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// testContractAddress is a fixed C... address for the host function the test
// envelopes carry. The address is not funded and never submitted anywhere; it
// only has to be structurally valid XDR.
var testContractAddress = xdr.ScAddress{
	Type: xdr.ScAddressTypeScAddressTypeContract,
	ContractId: &xdr.ContractId{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	},
}

// testMuxedAddress is a valid G... address for the envelope source account and
// for a payment destination, derived the same way the golden vectors derive
// their keys.
func testMuxedAddress(t *testing.T) xdr.MuxedAccount {
	t.Helper()
	return xdr.MustMuxedAddress(vectorKeypair(t, "soroauth-cli-envelope-payer").Address())
}

// testInvokeOperation puts entries behind a valid invokeHostFunction
// operation.
func testInvokeOperation(entries ...xdr.SorobanAuthorizationEntry) xdr.Operation {
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: testContractAddress,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{},
				},
			},
			Auth: entries,
		},
	}}
}

// testPaymentOperation is a valid operation that is not an invokeHostFunction,
// so the tests can prove detection counts operations that are not invoke calls
// too.
func testPaymentOperation(t *testing.T) xdr.Operation {
	t.Helper()
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypePayment,
		PaymentOp: &xdr.PaymentOp{
			Destination: testMuxedAddress(t),
			Asset:       xdr.Asset{Type: xdr.AssetTypeAssetTypeNative},
			Amount:      1,
		},
	}}
}

// testEnvelopeXDR base64-encodes an envelope carrying the given operations.
func testEnvelopeXDR(t *testing.T, operations ...xdr.Operation) string {
	t.Helper()
	envelope := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: testMuxedAddress(t),
			Fee:           100,
			SeqNum:        1,
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
			Operations:    operations,
			Ext:           xdr.TransactionExt{V: 0},
		}},
	}
	encoded, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("encoding the test envelope: %v", err)
	}
	return encoded
}

// decodeTestEnvelope reads back an envelope the CLI printed.
func decodeTestEnvelope(t *testing.T, value string) xdr.TransactionEnvelope {
	t.Helper()
	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(strings.TrimSpace(value), &envelope); err != nil {
		t.Fatalf("decoding the envelope: %v", err)
	}
	return envelope
}

func TestInspectDetectsAnEnvelope(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	envelope := testEnvelopeXDR(t, testPaymentOperation(t), testInvokeOperation(entry))

	stdout, _, err := runCLI(t, "inspect", "--entry", envelope)
	if err != nil {
		t.Fatalf("inspect returned an error: %v", err)
	}

	var reports []struct {
		OperationIndex int    `json:"operation_index"`
		EntryIndex     int    `json:"entry_index"`
		CredentialType string `json:"credential_type"`
		Address        string `json:"address"`
		RootFunction   string `json:"root_function"`
	}
	if err := json.Unmarshal([]byte(stdout), &reports); err != nil {
		t.Fatalf("the output is not a JSON array: %v\n%s", err, stdout)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	if reports[0].OperationIndex != 1 || reports[0].EntryIndex != 0 {
		t.Errorf("the report is at operation %d entry %d, want operation 1 entry 0",
			reports[0].OperationIndex, reports[0].EntryIndex)
	}
	if reports[0].CredentialType != "address_v2" {
		t.Errorf("credential_type is %q, want address_v2", reports[0].CredentialType)
	}
	if reports[0].Address == "" {
		t.Error("the report names no address")
	}
}

// TestInspectStillReportsASingleEntryObject is the compatibility half of the
// auto-detection: a lone entry must keep the shape it always had.
func TestInspectStillReportsASingleEntryObject(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	got := inspectEntry(t, v.UnsignedEntryXDR)
	if got.CredentialType != "address_v2" {
		t.Errorf("credential_type is %q, want address_v2", got.CredentialType)
	}
}

func TestInspectRejectsAnEnvelopeWithNoInvokeOperation(t *testing.T) {
	_, _, err := runCLI(t, "inspect", "--entry", testEnvelopeXDR(t, testPaymentOperation(t)))
	if err == nil {
		t.Fatal("inspecting an envelope with no invoke operation succeeded")
	}
	if !strings.Contains(err.Error(), "invokeHostFunction") {
		t.Errorf("the error %q does not say the envelope carries no invokeHostFunction operation", err)
	}
}

func TestSignDetectsAnEnvelope(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	envelope := testEnvelopeXDR(t, testInvokeOperation(entry))

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": signer.Seed()},
		"sign",
		"--entry", envelope,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--json")
	if err != nil {
		t.Fatalf("sign returned an error: %v", err)
	}

	var out struct {
		SignedEnvelope string `json:"signed_envelope"`
		SignedEntry    string `json:"signed_entry"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("the output is not valid JSON: %v\n%s", err, stdout)
	}
	if out.SignedEntry != "" {
		t.Error("signing an envelope reported a signed_entry")
	}
	if out.SignedEnvelope == "" {
		t.Fatal("signing an envelope reported no signed_envelope")
	}

	signed := decodeTestEnvelope(t, out.SignedEnvelope)
	if signed.Type != xdr.EnvelopeTypeEnvelopeTypeTx {
		t.Fatalf("the returned envelope is %v, want envelope_type_tx", signed.Type)
	}
	if signed.V1 == nil || len(signed.V1.Tx.Operations) != 1 {
		t.Fatal("the returned envelope does not carry the one operation it was given")
	}
	auth := signed.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.Auth
	if len(auth) != 1 {
		t.Fatalf("got %d entries, want 1", len(auth))
	}
	signature := auth[0].Credentials.AddressV2.Signature
	// The unsigned placeholder is an empty ScvVec; a real ed25519 account
	// signature is a non-empty one.
	if signature.Type == xdr.ScValTypeScvVoid ||
		(signature.Type == xdr.ScValTypeScvVec &&
			(signature.Vec == nil || *signature.Vec == nil || len(**signature.Vec) == 0)) {
		t.Error("the entry was returned unsigned")
	}
}

func TestSignRefusesForWithAnEnvelope(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	envelope := testEnvelopeXDR(t, testInvokeOperation(entry))

	_, _, err := runCLIEnv(t, map[string]string{"SEED": signer.Seed()},
		"sign",
		"--entry", envelope,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--for", signer.Address())
	if err == nil {
		t.Fatal("signing an envelope with --for succeeded, want a usage error")
	}
	if !strings.Contains(err.Error(), "--for") {
		t.Errorf("the error %q does not explain the --for refusal", err)
	}
}

func TestPayloadDetectsAnEnvelope(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	envelope := testEnvelopeXDR(t, testInvokeOperation(entry))

	envelopeStdout, _, err := runCLI(t, "payload",
		"--entry", envelope,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--json")
	if err != nil {
		t.Fatalf("payload on an envelope returned an error: %v", err)
	}

	entryStdout, _, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--json")
	if err != nil {
		t.Fatalf("payload on the entry returned an error: %v", err)
	}

	var reports []struct {
		OperationIndex int    `json:"operation_index"`
		EntryIndex     int    `json:"entry_index"`
		SourceAccount  bool   `json:"source_account"`
		Preimage       string `json:"preimage"`
		Payload        string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(envelopeStdout), &reports); err != nil {
		t.Fatalf("the envelope output is not a JSON array: %v\n%s", err, envelopeStdout)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}

	var single struct {
		Preimage string `json:"preimage"`
		Payload  string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(entryStdout), &single); err != nil {
		t.Fatalf("the entry output is not valid JSON: %v\n%s", err, entryStdout)
	}

	if reports[0].Preimage != single.Preimage || reports[0].Payload != single.Payload {
		t.Error("the envelope payload report differs from the entry one, want the same bytes")
	}
	if reports[0].OperationIndex != 0 || reports[0].EntryIndex != 0 {
		t.Errorf("the report is at operation %d entry %d, want operation 0 entry 0",
			reports[0].OperationIndex, reports[0].EntryIndex)
	}
}
