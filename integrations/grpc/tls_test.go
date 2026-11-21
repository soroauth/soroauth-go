package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/soroauth/soroauth-go"

	soroauthv1 "github.com/soroauth/soroauth-go/integrations/grpc/gen"
)

// Test strategy, from issue #554:
//
//   - Test certificates are generated at test time and never committed.
//     A committed key would be a real finding even if labelled test-only.
//   - Untrusted client: a client that presents a certificate from a CA the
//     server does not trust is refused in the handshake, before any gRPC
//     method runs.
//   - Expired certificate: a client whose certificate's NotAfter is in the
//     past is refused in the handshake.
//   - Pin mismatch: a client whose chain validates but whose SPKI is not
//     in the server's pin set is refused by the VerifyPeerCertificate
//     callback.
//   - The insecure path must not be reachable by default: there is no
//     plaintext constructor, and LoadServerCredentials with a missing
//     certificate or an empty CA pool fails fast rather than falling back.

type pki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// newCA builds a self-signed CA good for one test. Tests never share a CA,
// so a cross-test contamination is impossible by construction.
func newCA(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "soroauth grpc test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &pki{caCert: cert, caKey: key}
}

// pool returns a CertPool containing just this CA.
func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	return pool
}

// leafOpts carries the knobs the leaf-generating helpers accept. The two
// knobs are the common name (used as the server's SAN) and the lifetime.
type leafOpts struct {
	commonName string
	notBefore  time.Time
	notAfter   time.Time
	isServer   bool
}

// issueLeaf issues a server or client leaf under this CA.
func (p *pki) issueLeaf(t *testing.T, opts leafOpts) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Minute)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(1 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: opts.commonName},
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if opts.isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{opts.commonName}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return cert, leaf
}

// startTLSServer brings up a gRPC server bound to a random port, backed by
// a single-signer SoroauthService, and returns its address plus a cleanup.
// The server uses the supplied TransportCredentials; a handshake failure is
// a server-side log line and a client-side error.
func startTLSServer(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Use the real SoroauthService: that is what the issue's
	// "no plaintext method runs" guarantee covers. A caller that gets
	// through the handshake would reach Verify; a caller that does not
	// never touches it.
	signer := soroauth.NewEd25519Signer(mustTestKeypair(t))
	srv := grpc.NewServer(grpc.Creds(creds))
	soroauthv1.RegisterSoroauthServiceServer(srv, NewServer(signer))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})
	return lis.Addr().String()
}

// dialAndPing opens a gRPC client with the supplied credentials and sends
// one Verify request with an obviously malformed entry. The purpose is not
// to test Verify; it is to force a handshake and observe which layer
// refused the call. A handshake failure maps to codes.Unavailable with
// "tls:" in the message; a method failure maps to InvalidArgument.
func dialAndPing(t *testing.T, addr string, creds credentials.TransportCredentials) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close()
	client := soroauthv1.NewSoroauthServiceClient(conn)
	_, err = client.Verify(ctx, &soroauthv1.VerifyRequest{Entry: "not base64", Network: "testnet"})
	return err
}

// TestMTLSHappyPath proves a client that presents a certificate from the
// server's trusted CA reaches the method layer. The method call itself
// fails because the entry is malformed; the point is that the TLS
// handshake succeeded.
func TestMTLSHappyPath(t *testing.T) {
	ca := newCA(t)
	serverCert, _ := ca.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})
	clientCert, _ := ca.issueLeaf(t, leafOpts{commonName: "test-client"})

	srvCreds, err := LoadServerCredentials(ServerTLSConfig{
		Certificate: serverCert,
		ClientCAs:   ca.pool(),
	})
	if err != nil {
		t.Fatalf("server creds: %v", err)
	}
	clientCreds, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: clientCert,
		RootCAs:     ca.pool(),
		ServerName:  "localhost",
	})
	if err != nil {
		t.Fatalf("client creds: %v", err)
	}
	addr := startTLSServer(t, srvCreds)

	err = dialAndPing(t, addr, clientCreds)
	if err == nil {
		t.Fatal("expected a method-level error with a malformed entry, got nil")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("code = %s (%v), want InvalidArgument — handshake likely failed", code, err)
	}
}

// TestMTLSRefusesUntrustedClient proves a client whose certificate is from
// a different CA is refused in the handshake, not inside a method.
func TestMTLSRefusesUntrustedClient(t *testing.T) {
	serverCA := newCA(t)
	otherCA := newCA(t)

	serverCert, _ := serverCA.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})
	badClient, _ := otherCA.issueLeaf(t, leafOpts{commonName: "rogue-client"})

	srvCreds, err := LoadServerCredentials(ServerTLSConfig{
		Certificate: serverCert,
		ClientCAs:   serverCA.pool(),
	})
	if err != nil {
		t.Fatalf("server creds: %v", err)
	}
	clientCreds, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: badClient,
		RootCAs:     serverCA.pool(), // client still trusts the server
		ServerName:  "localhost",
	})
	if err != nil {
		t.Fatalf("client creds: %v", err)
	}
	addr := startTLSServer(t, srvCreds)

	err = dialAndPing(t, addr, clientCreds)
	if err == nil {
		t.Fatal("untrusted client reached a method; it must be refused at the handshake")
	}
	// A handshake refusal arrives as codes.Unavailable (connection failed),
	// never InvalidArgument (a method ran). Pin the first because that is
	// what distinguishes the two layers.
	if code := status.Code(err); code == codes.InvalidArgument {
		t.Fatalf("untrusted client reached the method layer (code=%s, %v); refuse at handshake", code, err)
	}
}

// TestMTLSRefusesExpiredClient proves a client whose certificate is no
// longer valid is refused in the handshake. x509 verification happens
// inside the TLS stack, before gRPC dispatch.
func TestMTLSRefusesExpiredClient(t *testing.T) {
	ca := newCA(t)
	serverCert, _ := ca.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})
	expiredClient, _ := ca.issueLeaf(t, leafOpts{
		commonName: "expired-client",
		notBefore:  time.Now().Add(-2 * time.Hour),
		notAfter:   time.Now().Add(-time.Hour),
	})

	srvCreds, err := LoadServerCredentials(ServerTLSConfig{
		Certificate: serverCert,
		ClientCAs:   ca.pool(),
	})
	if err != nil {
		t.Fatalf("server creds: %v", err)
	}
	clientCreds, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: expiredClient,
		RootCAs:     ca.pool(),
		ServerName:  "localhost",
	})
	if err != nil {
		t.Fatalf("client creds: %v", err)
	}
	addr := startTLSServer(t, srvCreds)

	err = dialAndPing(t, addr, clientCreds)
	if err == nil {
		t.Fatal("expired client reached a method; it must be refused at the handshake")
	}
	if code := status.Code(err); code == codes.InvalidArgument {
		t.Fatalf("expired client reached the method layer (code=%s, %v); refuse at handshake", code, err)
	}
}

// TestMTLSRefusesPinMismatch proves that even a chain-valid client is
// refused when its SPKI is not in the server's pin set.
func TestMTLSRefusesPinMismatch(t *testing.T) {
	ca := newCA(t)
	serverCert, _ := ca.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})
	okClient, okLeaf := ca.issueLeaf(t, leafOpts{commonName: "ok-client"})
	otherClient, _ := ca.issueLeaf(t, leafOpts{commonName: "other-client"})

	// Pin only the first client's SPKI. The second is signed by the same
	// CA, so chain validation would accept it; the pin check must refuse.
	srvCreds, err := LoadServerCredentials(ServerTLSConfig{
		Certificate:           serverCert,
		ClientCAs:             ca.pool(),
		AllowedClientSPKIPins: []string{SPKIPin(okLeaf)},
	})
	if err != nil {
		t.Fatalf("server creds: %v", err)
	}

	// Happy path (the pinned client) reaches the method layer.
	okCreds, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: okClient,
		RootCAs:     ca.pool(),
		ServerName:  "localhost",
	})
	if err != nil {
		t.Fatalf("ok client creds: %v", err)
	}
	addr := startTLSServer(t, srvCreds)
	err = dialAndPing(t, addr, okCreds)
	if err == nil {
		t.Fatal("pinned client expected to reach method and fail on malformed entry")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Fatalf("pinned client did not reach method: code=%s, %v", code, err)
	}

	// Mismatched client (chain-valid, wrong SPKI) must be refused.
	otherCreds, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: otherClient,
		RootCAs:     ca.pool(),
		ServerName:  "localhost",
	})
	if err != nil {
		t.Fatalf("other client creds: %v", err)
	}
	err = dialAndPing(t, addr, otherCreds)
	if err == nil {
		t.Fatal("pin mismatch reached a method; it must be refused at the handshake")
	}
	if code := status.Code(err); code == codes.InvalidArgument {
		t.Fatalf("pin mismatch reached the method layer (code=%s, %v); refuse at handshake", code, err)
	}
}

// TestLoadServerCredentialsRequiresConfig pins the fail-closed shape: a
// missing certificate, a missing CA pool, or an empty pin list that is
// treated as "no pinning" each produce a deterministic outcome. The
// insecure path cannot be reached by passing zero values.
func TestLoadServerCredentialsRequiresConfig(t *testing.T) {
	ca := newCA(t)
	cert, _ := ca.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})

	if _, err := LoadServerCredentials(ServerTLSConfig{ClientCAs: ca.pool()}); !errors.Is(err, ErrMissingCertificate) {
		t.Errorf("missing cert should return ErrMissingCertificate, got %v", err)
	}
	if _, err := LoadServerCredentials(ServerTLSConfig{Certificate: cert}); !errors.Is(err, ErrMissingRoots) {
		t.Errorf("missing pool should return ErrMissingRoots, got %v", err)
	}
	if _, err := LoadServerCredentials(ServerTLSConfig{Certificate: cert, ClientCAs: ca.pool()}); err != nil {
		t.Errorf("minimum viable config rejected: %v", err)
	}
}

// TestLoadClientCredentialsRequiresServerName asserts the one place
// crypto/tls disables hostname verification is not reachable here. An
// empty ServerName is refused at config build time rather than silently
// accepting any server certificate.
func TestLoadClientCredentialsRequiresServerName(t *testing.T) {
	ca := newCA(t)
	cert, _ := ca.issueLeaf(t, leafOpts{commonName: "client"})

	_, err := LoadClientCredentials(ClientTLSConfig{
		Certificate: cert,
		RootCAs:     ca.pool(),
	})
	if !errors.Is(err, ErrMissingServerName) {
		t.Fatalf("missing ServerName should return ErrMissingServerName, got %v", err)
	}
}

// TestSPKIPinIsStable pins the hex encoding behaviour the config format
// documents: lower-case, no delimiters, 64 characters.
func TestSPKIPinIsStable(t *testing.T) {
	ca := newCA(t)
	_, leaf := ca.issueLeaf(t, leafOpts{commonName: "localhost", isServer: true})
	pin := SPKIPin(leaf)
	if len(pin) != 64 {
		t.Errorf("SPKIPin returned %d characters, want 64 (sha256 hex)", len(pin))
	}
	if strings.ToLower(pin) != pin {
		t.Errorf("SPKIPin returned mixed case %q; config expects lower-case", pin)
	}
}

// mustTestKeypair builds a throwaway keypair used by the service only to
// satisfy the "server has a signer" check — none of the TLS tests send a
// well-formed entry, so this keypair never signs anything.
func mustTestKeypair(t *testing.T) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-tls-test-keypair")))
	if err != nil {
		t.Fatalf("test keypair: %v", err)
	}
	return kp
}
