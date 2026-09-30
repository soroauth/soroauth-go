package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// vectorFile is the part of a golden vector the service tests need: the entry
// before signing, and the network and expiration it was built for.
type vectorFile struct {
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	NetworkPassphrase string `json:"network_passphrase"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
}

func loadVector(t *testing.T, name string) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name+".json"))
	if err != nil {
		t.Fatalf("reading vector %s: %v", name, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling vector %s: %v", name, err)
	}
	return v
}

// testKeypair derives a public test keypair from a label; see
// CONTRIBUTING.md#deterministic-test-keys, including why the
// "soroauth-vector-signer-" labels must stay exactly as they are.
func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving key %q: %v", label, err)
	}
	return kp
}

// signEntry authorizes an unsigned base64 entry with one key, returning the
// signed entry as base64.
func signEntry(t *testing.T, unsigned string, kp *keypair.Full, validUntil uint32, passphrase string, opts ...soroauth.AuthorizeOption) string {
	t.Helper()
	entry, err := soroauth.DecodeAuthorizationEntry(unsigned)
	if err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}
	signed, err := soroauth.AuthorizeEntry(context.Background(), entry,
		soroauth.NewEd25519Signer(kp), validUntil, passphrase, opts...)
	if err != nil {
		t.Fatalf("signing the entry: %v", err)
	}
	encoded, err := xdr.MarshalBase64(signed)
	if err != nil {
		t.Fatalf("encoding the signed entry: %v", err)
	}
	return encoded
}

// postVerify sends a /verify request to a test server and returns the status
// and the decoded body.
func postVerify(t *testing.T, url string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	response, err := http.Post(url+"/verify", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("posting to /verify: %v", err)
	}
	defer response.Body.Close()
	var decoded map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return response.StatusCode, decoded
}

func nodes(t *testing.T, body map[string]interface{}) []interface{} {
	t.Helper()
	raw, ok := body["nodes"].([]interface{})
	if !ok {
		t.Fatalf("response has no nodes array: %v", body)
	}
	return raw
}

func verdictOf(node interface{}) string {
	return node.(map[string]interface{})["verdict"].(string)
}

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	response, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("getting /healthz: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", response.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the healthz body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("healthz status = %q, want ok", body["status"])
	}
}

func TestVerifyRejectsTheWrongMethod(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		request, err := http.NewRequest(method, srv.URL+"/verify", nil)
		if err != nil {
			t.Fatalf("building a %s request: %v", method, err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("sending a %s request: %v", method, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /verify status = %d, want 405", method, response.StatusCode)
		}
	}
}

func TestVerifyAcceptsASignedEntry(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signed := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, body := postVerify(t, srv.URL, map[string]interface{}{
		"entry":   signed,
		"network": v.NetworkPassphrase,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	if body["credential_type"] != "address_v2" {
		t.Errorf("credential_type = %v, want address_v2", body["credential_type"])
	}
	if body["verified"] != true {
		t.Errorf("verified = %v, want true: %v", body["verified"], body)
	}
	got := nodes(t, body)
	if len(got) != 1 {
		t.Fatalf("nodes = %d entries, want 1: %v", len(got), got)
	}
	// The verdict is compared against the library constant, not a string
	// literal, so the test fails if the service ever stops speaking the
	// CLI's verdicts rather than if English changes.
	if verdictOf(got[0]) != string(soroauth.VerdictVerified) {
		t.Errorf("node verdict = %q, want %q", verdictOf(got[0]), soroauth.VerdictVerified)
	}
}

func TestVerifyReportsAPartiallySignedTree(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")
	entry, err := soroauth.DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}

	d1 := testKeypair(t, "soroauth-server-delegate-1")
	d2 := testKeypair(t, "soroauth-server-delegate-2")
	wrapped, err := soroauth.WithDelegates(entry, v.ValidUntilLedger,
		[]soroauth.Delegate{{Address: d1.Address()}, {Address: d2.Address()}}, nil)
	if err != nil {
		t.Fatalf("wrapping with delegates: %v", err)
	}
	// Sign only the first delegate: the tree is partially signed, which a
	// custody policy may or may not accept — but the service reports it
	// either way.
	partial, err := soroauth.AuthorizeEntry(context.Background(), wrapped,
		soroauth.NewEd25519Signer(d1), v.ValidUntilLedger, v.NetworkPassphrase,
		soroauth.ForAddress(d1.Address()))
	if err != nil {
		t.Fatalf("signing one delegate: %v", err)
	}
	encoded, err := xdr.MarshalBase64(partial)
	if err != nil {
		t.Fatalf("encoding the partial entry: %v", err)
	}

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, body := postVerify(t, srv.URL, map[string]interface{}{
		"entry":   encoded,
		"network": v.NetworkPassphrase,
	})
	// Verification completed — the answer is "not fully signed", which is a
	// 200 carrying that answer, not a transport failure.
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	if body["verified"] != false {
		t.Errorf("verified = %v, want false for a partially signed tree", body["verified"])
	}
	verdicts := map[string]int{}
	for _, node := range nodes(t, body) {
		verdicts[verdictOf(node)]++
	}
	if verdicts[string(soroauth.VerdictVerified)] != 1 {
		t.Errorf("want exactly 1 verified node, got %v", verdicts)
	}
	if verdicts[string(soroauth.VerdictUnsigned)] != 2 {
		t.Errorf("want exactly 2 unsigned nodes (top level plus one delegate), got %v", verdicts)
	}
}

func TestVerifyRejectsMalformedRequests(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signed := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	tests := []struct {
		name string
		body interface{}
	}{
		{"missing entry", map[string]interface{}{"network": v.NetworkPassphrase}},
		{"missing network", map[string]interface{}{"entry": signed}},
		{"not base64", map[string]interface{}{"entry": "!!!", "network": v.NetworkPassphrase}},
		{"base64 but not XDR", map[string]interface{}{"entry": "aGVsbG8gd29ybGQ=", "network": v.NetworkPassphrase}},
		{"wrong expiration assertion", map[string]interface{}{
			"entry": signed, "network": v.NetworkPassphrase,
			"valid_until_ledger": v.ValidUntilLedger + 1,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := postVerify(t, srv.URL, tt.body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400: %v", status, body)
			}
			msg, ok := body["error"].(string)
			if !ok || msg == "" {
				t.Errorf("response carries no error message: %v", body)
			}
			if _, hasReport := body["nodes"]; hasReport {
				t.Errorf("an error response must not carry verdicts: %v", body)
			}
		})
	}
}

func TestVerifyReportsATamperedEntryAsInvalid(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signed := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)

	// Bump the stored expiration without re-signing: the payload the entry
	// commits to is no longer the one signed over.
	var parsed xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(signed, &parsed); err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}
	parsed.Credentials.AddressV2.SignatureExpirationLedger = xdr.Uint32(v.ValidUntilLedger + 1)
	tampered, err := xdr.MarshalBase64(parsed)
	if err != nil {
		t.Fatalf("encoding the tampered entry: %v", err)
	}

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, body := postVerify(t, srv.URL, map[string]interface{}{
		"entry":   tampered,
		"network": v.NetworkPassphrase,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	got := nodes(t, body)
	if len(got) != 1 || verdictOf(got[0]) != string(soroauth.VerdictInvalid) {
		t.Errorf("tampered node verdicts = %v, want one invalid", got)
	}
}

// testContractAddress is a fixed C... address for the host function the test
// envelope carries. It is never submitted anywhere; it only has to be
// structurally valid XDR.
var testContractAddress = xdr.ScAddress{
	Type: xdr.ScAddressTypeScAddressTypeContract,
	ContractId: &xdr.ContractId{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	},
}

func testEnvelopeXDR(t *testing.T, entries ...xdr.SorobanAuthorizationEntry) string {
	t.Helper()
	kp := testKeypair(t, "soroauth-server-envelope-payer")
	envelope := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(kp.Address()),
			Fee:           100,
			SeqNum:        1,
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
			Operations: []xdr.Operation{{Body: xdr.OperationBody{
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
			}}},
			Ext: xdr.TransactionExt{V: 0},
		}},
	}
	encoded, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("encoding the test envelope: %v", err)
	}
	return encoded
}

func TestVerifyAcceptsAnEnvelope(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signedB64 := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)
	var signed xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(signedB64, &signed); err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	raw, err := json.Marshal(map[string]interface{}{
		"entry":   testEnvelopeXDR(t, signed),
		"network": v.NetworkPassphrase,
	})
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	response, err := http.Post(srv.URL+"/verify", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("posting to /verify: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	var reports []map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&reports); err != nil {
		t.Fatalf("decoding the envelope response: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d entries, want 1", len(reports))
	}
	// Envelope positions are one-based, matching the CLI.
	if reports[0]["operation_index"] != float64(1) || reports[0]["entry_index"] != float64(1) {
		t.Errorf("positions = %v/%v, want 1/1",
			reports[0]["operation_index"], reports[0]["entry_index"])
	}
	inner, ok := reports[0]["nodes"].([]interface{})
	if !ok || len(inner) != 1 || verdictOf(inner[0]) != string(soroauth.VerdictVerified) {
		t.Errorf("envelope node verdicts = %v, want one verified", reports[0]["nodes"])
	}
}

func TestVerifyRejectsNonJSON(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	response, err := http.Post(srv.URL+"/verify", "application/json",
		strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("posting to /verify: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

func TestVerifyRejectsAnOversizeBody(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	// Well-formed JSON framing around a body past the cap: the failure is
	// about size, not syntax, so it must be 413 rather than 400.
	big := `{"entry":"` + strings.Repeat("A", maxRequestBodySize) + `","network":"testnet"}`
	response, err := http.Post(srv.URL+"/verify", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatalf("posting to /verify: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", response.StatusCode)
	}
}
