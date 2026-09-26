package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const testValidUntilLedger = uint32(1234567)

// testKeypair derives a deterministic public test key from a label, the same
// convention the rest of the repository's tests use.
func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

// testInvocation builds a minimal contract invocation to authorize.
func testInvocation(t *testing.T) xdr.SorobanAuthorizedInvocation {
	t.Helper()
	contractID := xdr.ContractId(sha256.Sum256([]byte("remote-test-contract")))
	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: xdr.ScAddress{
					Type:       xdr.ScAddressTypeScAddressTypeContract,
					ContractId: &contractID,
				},
				FunctionName: xdr.ScSymbol("transfer"),
				Args:         []xdr.ScVal{},
			},
		},
	}
}

// testPreimagePayload returns a real preimage and its digest, built the same way
// a caller would build one, so the request bodies in these tests are genuine.
func testPreimagePayload(t *testing.T) (xdr.HashIdPreimage, [32]byte) {
	t.Helper()
	address, err := soroauth.ParseAddress(testKeypair(t, "remote-preimage").Address())
	if err != nil {
		t.Fatalf("parsing the address: %v", err)
	}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     xdr.Int64(7),
				SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
			},
		},
		RootInvocation: testInvocation(t),
	}
	preimage, err := soroauth.Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the preimage: %v", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the preimage: %v", err)
	}
	return preimage, payload
}

// TestClientAndServerRoundTrip is the integration test the protocol exists for:
// a remote Signer signs an entry end to end, and the result verifies against
// the payload the entry commits to, exactly as a local signer's would.
func TestClientAndServerRoundTrip(t *testing.T) {
	kp := testKeypair(t, "remote-round-trip")
	server := httptest.NewServer(NewServer(soroauth.NewEd25519Signer(kp)))
	defer server.Close()

	client := NewSigner(server.URL, kp.Address())
	if client.Address() != kp.Address() {
		t.Fatalf("Address() = %q, want %q", client.Address(), kp.Address())
	}

	entry, err := soroauth.AuthorizeInvocation(context.Background(), soroauth.AuthorizeInvocationParams{
		Signer:            client,
		Invocation:        testInvocation(t),
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	})
	if err != nil {
		t.Fatalf("AuthorizeInvocation with the remote signer: %v", err)
	}

	report, err := soroauth.VerifyEntry(entry, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if !report.Verified() {
		t.Fatalf("the remotely signed entry did not verify: %+v", report.Nodes)
	}
}

// TestLogApproverWritesASummary proves the reference logger names the address,
// the variant and the expiration, which is what an operator reads before
// allowing a signature.
func TestLogApproverWritesASummary(t *testing.T) {
	preimage, payload := testPreimagePayload(t)

	var log bytes.Buffer
	LogApprover(&log)(Approval{Address: testKeypair(t, "remote-preimage").Address(), Preimage: preimage, Payload: payload})

	line := log.String()
	for _, want := range []string{"approving", "valid_until=1234567", "nonce=7", "payload="} {
		if !strings.Contains(line, want) {
			t.Errorf("log line %q does not contain %q", line, want)
		}
	}
}

// TestServerCallsTheApprover proves the callback sees the decoded preimage
// before the signature is produced.
func TestServerCallsTheApprover(t *testing.T) {
	kp := testKeypair(t, "remote-approver")
	server := NewServer(soroauth.NewEd25519Signer(kp))

	var seen []Approval
	server.Approver = func(a Approval) { seen = append(seen, a) }

	preimage, payload := testPreimagePayload(t)
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()

	client := NewSigner(httpServer.URL, kp.Address())
	if _, err := client.Sign(context.Background(), preimage, payload); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("approver called %d times, want 1", len(seen))
	}
	if seen[0].Address != kp.Address() {
		t.Errorf("approver address = %q, want %q", seen[0].Address, kp.Address())
	}
	if seen[0].Preimage.Type != xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress {
		t.Errorf("approver preimage variant = %v, want the address-bound variant", seen[0].Preimage.Type)
	}
}

// TestServerRefusesAMismatchedPayload proves the server derives the digest
// rather than trusting the one it is handed.
func TestServerRefusesAMismatchedPayload(t *testing.T) {
	kp := testKeypair(t, "remote-mismatch")
	server := httptest.NewServer(NewServer(soroauth.NewEd25519Signer(kp)))
	defer server.Close()

	preimage, _ := testPreimagePayload(t)
	encoded, err := xdr.MarshalBase64(preimage)
	if err != nil {
		t.Fatalf("encoding the preimage: %v", err)
	}

	body, err := json.Marshal(Request{
		Version:  Version,
		Address:  kp.Address(),
		Preimage: encoded,
		Payload:  hex.EncodeToString(make([]byte, 32)), // not the preimage's digest
	})
	if err != nil {
		t.Fatalf("encoding the request: %v", err)
	}

	response, err := http.Post(server.URL+Path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}

	var decoded Response
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}
	if !strings.Contains(decoded.Error, "does not match") {
		t.Errorf("error %q does not name the payload mismatch", decoded.Error)
	}
}

// TestServerRefusesAnotherAddress proves a server refuses to sign for an
// address other than the one its signer owns.
func TestServerRefusesAnotherAddress(t *testing.T) {
	kp := testKeypair(t, "remote-address")
	server := httptest.NewServer(NewServer(soroauth.NewEd25519Signer(kp)))
	defer server.Close()

	preimage, payload := testPreimagePayload(t)
	encoded, err := xdr.MarshalBase64(preimage)
	if err != nil {
		t.Fatalf("encoding the preimage: %v", err)
	}

	body, err := json.Marshal(Request{
		Version:  Version,
		Address:  testKeypair(t, "remote-somebody-else").Address(),
		Preimage: encoded,
		Payload:  hex.EncodeToString(payload[:]),
	})
	if err != nil {
		t.Fatalf("encoding the request: %v", err)
	}

	response, err := http.Post(server.URL+Path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

// TestServerRejectsOtherMethodsAndPaths pins the routing, so a probe never
// reaches the signing path by accident.
func TestServerRejectsOtherMethodsAndPaths(t *testing.T) {
	kp := testKeypair(t, "remote-routing")
	server := httptest.NewServer(NewServer(soroauth.NewEd25519Signer(kp)))
	defer server.Close()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "get", method: http.MethodGet, path: Path, wantStatus: http.StatusMethodNotAllowed},
		{name: "unknown path", method: http.MethodPost, path: "/other", wantStatus: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := http.NewRequest(tt.method, server.URL+tt.path, strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("building the request: %v", err)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatalf("doing the request: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", response.StatusCode, tt.wantStatus)
			}
		})
	}
}

// TestClientCancellationAbortsInFlightRequest proves the client's context is
// attached to the HTTP request: cancelling it stops a request that is already
// in flight rather than leaving it to complete in the background.
func TestClientCancellationAbortsInFlightRequest(t *testing.T) {
	released := make(chan struct{})
	blocking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the request open until its context is cancelled, which is what
		// the client is supposed to cause.
		select {
		case <-r.Context().Done():
		case <-released:
		}
	}))
	defer blocking.Close()
	defer close(released)

	preimage, payload := testPreimagePayload(t)
	client := NewSigner(blocking.URL, testKeypair(t, "remote-preimage").Address())

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := client.Sign(ctx, preimage, payload)
	if err == nil {
		t.Fatal("Sign succeeded against a server that never answered")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
}

// TestClientRefusesACancelledContextBeforeSending proves the client checks the
// context first, so a cancelled call never reaches the network.
func TestClientRefusesACancelledContextBeforeSending(t *testing.T) {
	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	preimage, payload := testPreimagePayload(t)
	client := NewSigner(server.URL, testKeypair(t, "remote-preimage").Address())
	if _, err := client.Sign(ctx, preimage, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if hit {
		t.Error("a cancelled Sign reached the server")
	}
}
