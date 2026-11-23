package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/soroauth/soroauth-go"
)

// postRisk sends a /risk request and returns the status and decoded body.
func postRisk(t *testing.T, url string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the request: %v", err)
	}
	response, err := http.Post(url+"/risk", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("posting to /risk: %v", err)
	}
	defer response.Body.Close()
	var decoded map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	return response.StatusCode, decoded
}

func TestRiskEndpointReportsFindings(t *testing.T) {
	v := loadVector(t, "legacy_single_testnet")
	signed := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, body := postRisk(t, srv.URL, map[string]interface{}{"entry": signed})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	if body["credential_type"] != soroauth.CredentialTypeAddress {
		t.Errorf("credential_type = %v, want %s", body["credential_type"], soroauth.CredentialTypeAddress)
	}
	if body["note"] != soroauth.FindingNote {
		t.Errorf("note = %v, want the analyzer's caveat", body["note"])
	}
	findings, ok := body["findings"].([]interface{})
	if !ok {
		t.Fatalf("findings is not an array: %v", body["findings"])
	}
	if len(findings) == 0 {
		t.Fatal("a legacy entry produced no findings")
	}

	var found bool
	for _, finding := range findings {
		entry := finding.(map[string]interface{})
		if entry["code"] == soroauth.FindingCodeLegacyCredentialsNotAddressBound {
			found = true
			if entry["severity"] != string(soroauth.SeverityInfo) {
				t.Errorf("legacy finding severity = %v, want %s", entry["severity"], soroauth.SeverityInfo)
			}
		}
		if entry["title"] == "" || entry["description"] == "" || entry["rationale"] == "" {
			t.Errorf("finding is missing prose: %v", entry)
		}
	}
	if !found {
		t.Fatalf("findings do not contain %s: %v", soroauth.FindingCodeLegacyCredentialsNotAddressBound, findings)
	}
}

func TestRiskEndpointCleanReportIsAnEmptyArray(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signed := signEntry(t, v.UnsignedEntryXDR,
		testKeypair(t, "soroauth-vector-signer-1"), v.ValidUntilLedger, v.NetworkPassphrase)

	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, body := postRisk(t, srv.URL, map[string]interface{}{"entry": signed})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", status, body)
	}
	findings, ok := body["findings"].([]interface{})
	if !ok {
		t.Fatalf("findings is null or not an array: %v", body["findings"])
	}
	if len(findings) != 0 {
		t.Fatalf("a clean V2 entry produced findings: %v", findings)
	}
	if body["note"] != soroauth.FindingNote {
		t.Errorf("note = %v, want the analyzer's caveat", body["note"])
	}
}

func TestRiskEndpointRefusesBadRequests(t *testing.T) {
	srv := httptest.NewServer(newMux())
	defer srv.Close()

	status, _ := postRisk(t, srv.URL, map[string]interface{}{})
	if status != http.StatusBadRequest {
		t.Errorf("missing entry status = %d, want 400", status)
	}
	status, _ = postRisk(t, srv.URL, map[string]interface{}{"entry": "!!!"})
	if status != http.StatusBadRequest {
		t.Errorf("undecodable entry status = %d, want 400", status)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		request, err := http.NewRequest(method, srv.URL+"/risk", nil)
		if err != nil {
			t.Fatalf("building a %s request: %v", method, err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("sending a %s request: %v", method, err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /risk status = %d, want 405", method, response.StatusCode)
		}
	}
}
