// Package openapi holds the generated client for server/openapi.yaml and the
// conformance check that proves the running service matches the spec.
//
// It is a module of its own so the OpenAPI toolchain and the validation
// library — neither of which the server needs to run — never enter the root
// module's dependency graph. The check builds and starts the real server binary
// and drives it exactly as a client would, then validates every response
// against the committed spec.
package openapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/server/openapi/client"
)

// authToken is configured on the service under test so the 401 path is
// exercised; the whole surface requires it except /healthz.
const authToken = "conformance-bearer-token"

var (
	doc       *openapi3.T
	apiRouter routers.Router
	baseURL   string
	serverCmd *exec.Cmd
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	loaded, err := openapi3.NewLoader().LoadFromFile(filepath.Join("..", "openapi.yaml"))
	if err != nil {
		log.Fatalf("loading openapi.yaml: %v", err)
	}
	if err := loaded.Validate(ctx); err != nil {
		log.Fatalf("openapi.yaml is not a valid OpenAPI document: %v", err)
	}
	doc = loaded

	apiRouter, err = gorillamux.NewRouter(doc)
	if err != nil {
		log.Fatalf("building the spec router: %v", err)
	}

	repoRoot := filepath.Join("..", "..")
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("soroauth-server-conformance-%d", os.Getpid()))
	build := exec.Command("go", "build", "-o", bin, "./server")
	build.Dir = repoRoot
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		log.Fatalf("building the server binary: %v", err)
	}
	defer os.Remove(bin)

	addr, err := freeLoopbackAddr()
	if err != nil {
		log.Fatalf("finding a free port: %v", err)
	}
	baseURL = "http://" + addr
	serverCmd = exec.Command(bin)
	serverCmd.Env = append(os.Environ(),
		"ADDR="+addr,
		"AUTH_TOKEN="+authToken,
		"METRICS_ADDR=off",
		// A single slot makes the 503 path deterministic to reach.
		"MAX_CONCURRENT_REQUESTS=1",
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("starting the server: %v", err)
	}
	if err := waitHealthy(baseURL); err != nil {
		_ = serverCmd.Process.Kill()
		log.Fatalf("the service never became healthy: %v", err)
	}

	code := m.Run()

	_ = serverCmd.Process.Kill()
	_ = serverCmd.Wait()
	os.Exit(code)
}

func freeLoopbackAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	return "127.0.0.1:" + strconv.Itoa(port), nil
}

func waitHealthy(base string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no 200 from /healthz within the deadline")
}

func findRoute(t *testing.T, specMethod, path string) (*routers.Route, map[string]string) {
	t.Helper()
	req, err := http.NewRequest(specMethod, baseURL+path, nil)
	if err != nil {
		t.Fatalf("building a %s %s route lookup: %v", specMethod, path, err)
	}
	route, pathParams, err := apiRouter.FindRoute(req)
	if err != nil {
		t.Fatalf("the spec has no route for %s %s: %v", specMethod, path, err)
	}
	return route, pathParams
}

// validateResponse proves the response is one the spec describes for the
// operation identified by specMethod and path. It is the conformance check
// itself: a change to a status code, a field name or the shape of an error
// fails here, naming the operation.
func validateResponse(t *testing.T, specMethod, path string, status int, header http.Header, respBody []byte) {
	t.Helper()
	route, pathParams := findRoute(t, specMethod, path)
	req, err := http.NewRequest(specMethod, baseURL+path, nil)
	if err != nil {
		t.Fatalf("building the validation request: %v", err)
	}
	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: pathParams, Route: route},
		Status:                 status,
		Header:                 header,
		Body:                   io.NopCloser(bytes.NewReader(respBody)),
	}
	if err := openapi3filter.ValidateResponse(context.Background(), respInput); err != nil {
		t.Errorf("%s %s response (status %d) does not match the spec: %v\nbody: %s",
			specMethod, path, status, err, respBody)
	}
}

// assertRequestMatchesSpec proves a well-formed request is one the spec
// accepts. It is called only for the cases whose request is meant to be valid;
// the error-path cases deliberately send requests the spec rejects.
func assertRequestMatchesSpec(t *testing.T, method, path, body string) {
	t.Helper()
	route, pathParams := findRoute(t, method, path)
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		t.Fatalf("building the validation request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	input := &openapi3filter.RequestValidationInput{Request: req, PathParams: pathParams, Route: route}
	if err := openapi3filter.ValidateRequest(context.Background(), input); err != nil {
		t.Errorf("%s %s request does not match the spec: %v", method, path, err)
	}
}

// send performs one HTTP request against the running service, with no spec
// assertion, and returns the status, headers and body.
func send(t *testing.T, method, path, body string, authenticate bool) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticate {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the %s %s response: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header, respBody
}

func vector(t *testing.T) (signed, passphrase string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "v2_single_testnet.json"))
	if err != nil {
		t.Fatalf("reading the golden vector: %v", err)
	}
	var v struct {
		SignedEntryXDR    string `json:"signed_entry_xdr"`
		NetworkPassphrase string `json:"network_passphrase"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshalling the golden vector: %v", err)
	}
	if v.SignedEntryXDR == "" {
		t.Fatal("the vector has no signed_entry_xdr")
	}
	return v.SignedEntryXDR, v.NetworkPassphrase
}

// envelopePayer is a fixed G… address for the test envelope's source account.
// It never funds anything and never appears on a network; only the authorizing
// entries inside the envelope matter to the service.
const envelopePayer = "GC33NWBJFXQSQMD3AMHTFEFT36IH5ZBG24L5RZMQGKO2SPBTVB74VZI5"

var testContractAddress = xdr.ScAddress{
	Type: xdr.ScAddressTypeScAddressTypeContract,
	ContractId: &xdr.ContractId{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	},
}

func envelopeXDR(t *testing.T, entries ...xdr.SorobanAuthorizationEntry) string {
	t.Helper()
	envelope := xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(envelopePayer),
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
		t.Fatalf("encoding the envelope: %v", err)
	}
	return encoded
}

// TestServiceMatchesSpec drives every declared operation and its error status,
// asserting each response validates against the spec. At the end it asserts
// every operation in the spec was visited, so a newly declared endpoint without
// a case fails the check rather than going untested.
func TestServiceMatchesSpec(t *testing.T) {
	signed, passphrase := vector(t)

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(signed, &entry); err != nil {
		t.Fatalf("decoding the signed vector: %v", err)
	}
	envelope := envelopeXDR(t, entry)

	validBody, err := json.Marshal(map[string]string{"entry": signed, "network": passphrase})
	if err != nil {
		t.Fatalf("marshalling the valid body: %v", err)
	}
	envelopeBody, err := json.Marshal(map[string]string{"entry": envelope, "network": passphrase})
	if err != nil {
		t.Fatalf("marshalling the envelope body: %v", err)
	}
	oversize := `{"entry":"` + strings.Repeat("A", 2<<20) + `","network":"testnet"}`

	cases := []struct {
		name string
		// method is the method actually sent; specMethod is the method of the
		// operation the response is validated against, which differs only for
		// the wrong-method cases whose 405 belongs to the declared operation.
		method       string
		specMethod   string
		path         string
		body         string
		authenticate bool
		checkRequest bool
		want         int
	}{
		{"healthz", "GET", "GET", "/healthz", "", false, true, http.StatusOK},
		{"healthz wrong method", "POST", "GET", "/healthz", "", false, false, http.StatusMethodNotAllowed},
		{"verify wrong method", "GET", "POST", "/verify", "", false, false, http.StatusMethodNotAllowed},
		{"verify unauthenticated", "POST", "POST", "/verify", string(validBody), false, false, http.StatusUnauthorized},
		{"verify malformed json", "POST", "POST", "/verify", "{", true, false, http.StatusBadRequest},
		{"verify missing entry", "POST", "POST", "/verify", `{"network":"testnet"}`, true, false, http.StatusBadRequest},
		{"verify undecodable entry", "POST", "POST", "/verify", `{"entry":"!!!","network":"testnet"}`, true, false, http.StatusBadRequest},
		{"verify oversize body", "POST", "POST", "/verify", oversize, true, false, http.StatusRequestEntityTooLarge},
		{"verify single entry", "POST", "POST", "/verify", string(validBody), true, true, http.StatusOK},
		{"verify envelope", "POST", "POST", "/verify", string(envelopeBody), true, true, http.StatusOK},
	}

	visited := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, header, body := send(t, tc.method, tc.path, tc.body, tc.authenticate)
			if status != tc.want {
				t.Fatalf("status = %d, want %d: %s", status, tc.want, body)
			}
			validateResponse(t, tc.specMethod, tc.path, status, header, body)
			if tc.checkRequest {
				assertRequestMatchesSpec(t, tc.method, tc.path, tc.body)
			}
		})
		visited[tc.specMethod+" "+tc.path] = true
	}

	// Every operation the spec declares must have been exercised above.
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			key := method + " " + path
			if !visited[key] {
				t.Errorf("the spec declares %s but no conformance case exercised it", key)
			}
		}
	}
}

// TestConcurrencyBoundIsDescribedBySpec holds the single concurrency slot open,
// then proves the refusal is a 503 the spec describes and advertises Retry-After.
func TestConcurrencyBoundIsDescribedBySpec(t *testing.T) {
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/verify", pr)
	if err != nil {
		t.Fatalf("building the held request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	pollBody := `{"entry":"x","network":"testnet"}`
	var (
		status int
		header http.Header
		body   []byte
	)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, header, body = send(t, http.MethodPost, "/verify", pollBody, true)
		if status == http.StatusServiceUnavailable {
			break
		}
		if status != http.StatusBadRequest {
			t.Fatalf("unexpected status while waiting for the bound: %d", status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("never observed a 503 at the concurrency bound (last status %d)", status)
	}
	if header.Get("Retry-After") == "" {
		t.Error("the 503 response is missing the Retry-After header the spec documents")
	}
	validateResponse(t, http.MethodPost, "/verify", status, header, body)

	_ = pw.Close()
}

// TestGeneratedClientAgainstRunningService exercises the client generated from
// the spec against the live process, for both the single-entry object and the
// envelope array, and validates the bytes it received against the spec.
func TestGeneratedClientAgainstRunningService(t *testing.T) {
	signed, passphrase := vector(t)

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(signed, &entry); err != nil {
		t.Fatalf("decoding the signed vector: %v", err)
	}
	envelope := envelopeXDR(t, entry)

	c, err := client.NewClientWithResponses(baseURL, client.WithRequestEditorFn(
		func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+authToken)
			return nil
		}))
	if err != nil {
		t.Fatalf("building the generated client: %v", err)
	}

	health, err := c.HealthzWithResponse(context.Background())
	if err != nil {
		t.Fatalf("generated client Healthz: %v", err)
	}
	if health.StatusCode() != http.StatusOK || health.JSON200 == nil || health.JSON200.Status != "ok" {
		t.Fatalf("generated client healthz = %d %+v", health.StatusCode(), health.JSON200)
	}
	validateResponse(t, http.MethodGet, "/healthz", health.StatusCode(), health.HTTPResponse.Header, health.Body)

	single, err := c.VerifyWithResponse(context.Background(), client.VerifyJSONRequestBody{Entry: signed, Network: passphrase})
	if err != nil {
		t.Fatalf("generated client Verify (single): %v", err)
	}
	if single.StatusCode() != http.StatusOK || single.JSON200 == nil {
		t.Fatalf("generated client single verify = %d", single.StatusCode())
	}
	report, err := single.JSON200.AsEntryReport()
	if err != nil {
		t.Fatalf("single verify did not decode as an EntryReport: %v", err)
	}
	if !report.Verified {
		t.Errorf("the signed vector did not report verified: %+v", report)
	}
	assertRequestMatchesSpec(t, http.MethodPost, "/verify",
		`{"entry":`+mustJSON(t, signed)+`,"network":`+mustJSON(t, passphrase)+`}`)
	validateResponse(t, http.MethodPost, "/verify", single.StatusCode(), single.HTTPResponse.Header, single.Body)

	env, err := c.VerifyWithResponse(context.Background(), client.VerifyJSONRequestBody{Entry: envelope, Network: passphrase})
	if err != nil {
		t.Fatalf("generated client Verify (envelope): %v", err)
	}
	if env.StatusCode() != http.StatusOK || env.JSON200 == nil {
		t.Fatalf("generated client envelope verify = %d", env.StatusCode())
	}
	reports, err := env.JSON200.AsVerifyResult1()
	if err != nil {
		t.Fatalf("envelope verify did not decode as an array: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("envelope reports = %d, want 1", len(reports))
	}
	if reports[0].OperationIndex == nil || *reports[0].OperationIndex != 1 {
		t.Errorf("envelope report is missing operation_index 1: %+v", reports[0])
	}
	validateResponse(t, http.MethodPost, "/verify", env.StatusCode(), env.HTTPResponse.Header, env.Body)
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshalling %q: %v", s, err)
	}
	return string(b)
}

// TestCannotCheckIsRepresentable guards the honesty boundary the spec must not
// flatten: the enum carries cannot_check as a distinct value, not a boolean.
func TestCannotCheckIsRepresentable(t *testing.T) {
	node := doc.Components.Schemas["NodeVerdict"]
	if node == nil || node.Value == nil {
		t.Fatal("NodeVerdict is missing from the spec")
	}
	verdict := node.Value.Properties["verdict"]
	if verdict == nil || verdict.Value == nil {
		t.Fatal("NodeVerdict.verdict is missing from the spec")
	}
	var found bool
	for _, value := range verdict.Value.Enum {
		if value == "cannot_check" {
			found = true
		}
	}
	if !found {
		t.Error("the verdict enum does not carry cannot_check as a distinct value")
	}
}
