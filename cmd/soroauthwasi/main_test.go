package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// response is the success envelope run writes.
type response struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	PreimageXDR string `json:"preimageXdr"`
	PayloadHex  string `json:"payloadHex"`
	EntryB64    string `json:"entryB64"`
}

func runRequest(t *testing.T, body string) response {
	t.Helper()
	var out bytes.Buffer
	code := run(strings.NewReader(body), &out)
	if code != 0 {
		t.Fatalf("run exited %d, want 0 (output: %s)", code, out.String())
	}
	var resp response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response %q: %v", out.String(), err)
	}
	return resp
}

func TestRunPreimageMatchesGoldenVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "legacy_single_testnet.json"))
	if err != nil {
		t.Fatalf("reading the vector: %v", err)
	}
	var vector struct {
		NetworkPassphrase string `json:"network_passphrase"`
		ValidUntilLedger  uint32 `json:"valid_until_ledger"`
		UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
		PreimageXDR       string `json:"preimage_xdr"`
		PayloadHex        string `json:"payload_hex"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("decoding the vector: %v", err)
	}

	request, err := json.Marshal(map[string]any{
		"op":                "preimage",
		"entry":             vector.UnsignedEntryXDR,
		"validUntilLedger":  vector.ValidUntilLedger,
		"networkPassphrase": vector.NetworkPassphrase,
	})
	if err != nil {
		t.Fatalf("encoding the request: %v", err)
	}

	resp := runRequest(t, string(request))
	if !resp.OK {
		t.Fatalf("preimage failed: %s", resp.Error)
	}
	if resp.PreimageXDR != vector.PreimageXDR {
		t.Error("preimage differs from the golden vector")
	}
	if resp.PayloadHex != vector.PayloadHex {
		t.Errorf("payload = %s, want %s", resp.PayloadHex, vector.PayloadHex)
	}
}

func TestRunReportsUnknownOpWithoutCrashing(t *testing.T) {
	resp := runRequest(t, `{"op":"nope"}`)
	if resp.OK {
		t.Fatal("an unknown op was reported as success")
	}
	if !strings.Contains(resp.Error, "unknown op") {
		t.Errorf("error = %q, want it to name the unknown op", resp.Error)
	}
}

func TestRunReportsMalformedRequest(t *testing.T) {
	resp := runRequest(t, `{not json`)
	if resp.OK {
		t.Fatal("malformed JSON was reported as success")
	}
	if resp.Error == "" {
		t.Error("a malformed request produced no error message")
	}
}
