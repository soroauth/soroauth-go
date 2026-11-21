package grpc

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// mTLS and optional pinning for the gRPC service.
//
// A gRPC signing service is a far more sensitive endpoint than the HTTP
// verifier: it holds or proxies signing authority. Transport security and
// client identity are the minimum for that. The service's documented posture
// of a trusted network does not survive contact with a real deployment, so
// this file ships the credentials an operator installs in front of a Server
// before exposing it anywhere.
//
// Design notes, from the issue's guidance:
//
//   - Refuse at the transport layer. An unverified client is refused in the
//     TLS handshake before any gRPC method is dispatched, so an interceptor
//     order bug cannot accidentally let a request in.
//
//   - Pinning is optional. When pins are configured, the peer's SPKI SHA-256
//     fingerprint must match one of them: a valid CA chain is not enough.
//     When pins are not configured, standard chain validation is the whole
//     check — a sane default rather than an opinionated one.
//
//   - Test certs are generated at test time (see tls_test.go) and never
//     committed. A committed key would be a real finding even if labelled
//     as "test only".
//
//   - There is no plaintext default. A caller must pass credentials
//     explicitly; InsecureForTestingOnly exists for tests inside this
//     package but is not reachable from a NewServer or NewClient path.

// ServerTLSConfig configures a server that requires and verifies a client
// certificate. An operator loads it from files; a test builds it in memory.
type ServerTLSConfig struct {
	// Certificate is the server's leaf certificate and private key.
	Certificate tls.Certificate
	// ClientCAs is the pool of CAs the server trusts to sign client certs.
	// A nil pool refuses every client, which is the deliberate fail-closed
	// behaviour when configuration is incomplete.
	ClientCAs *x509.CertPool
	// AllowedClientSPKIPins, when non-empty, further restricts accepted
	// clients to those whose SubjectPublicKeyInfo SHA-256 matches one of
	// these hex strings. A chain that validates but does not pin is
	// refused with ErrClientPinMismatch.
	AllowedClientSPKIPins []string
}

// ClientTLSConfig configures a client that requires a verified server
// certificate and sends its own client certificate on every connection.
type ClientTLSConfig struct {
	// Certificate is the client's leaf certificate and private key.
	Certificate tls.Certificate
	// RootCAs is the pool of CAs the client trusts for server certs.
	// A nil pool refuses every server.
	RootCAs *x509.CertPool
	// ServerName is the expected SAN on the server's certificate. Must be
	// set: an empty ServerName under crypto/tls disables hostname
	// verification, which is the exact posture mTLS is supposed to fix.
	ServerName string
	// AllowedServerSPKIPins, when non-empty, further restricts accepted
	// servers to those whose SPKI SHA-256 matches one of these hex strings.
	AllowedServerSPKIPins []string
}

// ErrClientPinMismatch is the error the verify callback returns when a
// client's certificate chain validates but its SPKI fingerprint is not in
// the configured pin set. Exported so a caller can errors.Is against it.
var ErrClientPinMismatch = errors.New("soroauth grpc: client certificate SPKI pin mismatch")

// ErrServerPinMismatch is the mirror for a client checking a server.
var ErrServerPinMismatch = errors.New("soroauth grpc: server certificate SPKI pin mismatch")

// ErrMissingCertificate is returned when a config has no certificate loaded.
// A client or server built from such a config would fall back to anonymous
// handshake, which is the fail-open behaviour this package refuses to carry.
var ErrMissingCertificate = errors.New("soroauth grpc: certificate is required")

// ErrMissingRoots is returned when a config has no CA pool. A nil pool would
// accept nothing, which is correct, but the caller's expectation is a
// configured set — refusing at build time names the mistake rather than
// appearing as "every connection failed".
var ErrMissingRoots = errors.New("soroauth grpc: CA pool is required")

// ErrMissingServerName is returned by LoadClientCredentials when ServerName
// is empty. See ClientTLSConfig.ServerName for why this is refused.
var ErrMissingServerName = errors.New("soroauth grpc: ServerName is required for a client")

// LoadServerCredentials builds the TransportCredentials a gRPC server uses
// to require and verify client certificates. An unverified client is
// refused in the handshake, before any gRPC method runs.
//
// When cfg.AllowedClientSPKIPins is non-empty, a VerifyPeerCertificate
// callback additionally checks that the peer's leaf certificate's SPKI
// hashes to one of the configured pins. The behaviour on mismatch is the
// same as on chain failure: handshake rejected with
// ErrClientPinMismatch wrapped by the TLS error.
func LoadServerCredentials(cfg ServerTLSConfig) (credentials.TransportCredentials, error) {
	if len(cfg.Certificate.Certificate) == 0 {
		return nil, ErrMissingCertificate
	}
	if cfg.ClientCAs == nil {
		return nil, ErrMissingRoots
	}
	t := &tls.Config{
		Certificates: []tls.Certificate{cfg.Certificate},
		ClientCAs:    cfg.ClientCAs,
		// ClientAuthType is the transport-layer refusal the issue calls out:
		// a connection whose client certificate does not validate against
		// ClientCAs is torn down before any gRPC method runs, which is
		// stricter than any interceptor-order arrangement could be.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	if len(cfg.AllowedClientSPKIPins) > 0 {
		pins := normalisePins(cfg.AllowedClientSPKIPins)
		t.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPins(rawCerts, pins, ErrClientPinMismatch)
		}
	}
	return credentials.NewTLS(t), nil
}

// LoadClientCredentials is the mirror of LoadServerCredentials: a client
// that presents its own certificate and verifies the server's.
//
// ServerName must be set; crypto/tls disables hostname verification when it
// is empty, which would defeat the whole point of mTLS. The one place
// hostname verification is suppressed is inside InsecureForTestingOnly,
// which is not reachable from a production path.
func LoadClientCredentials(cfg ClientTLSConfig) (credentials.TransportCredentials, error) {
	if len(cfg.Certificate.Certificate) == 0 {
		return nil, ErrMissingCertificate
	}
	if cfg.RootCAs == nil {
		return nil, ErrMissingRoots
	}
	if cfg.ServerName == "" {
		return nil, ErrMissingServerName
	}
	t := &tls.Config{
		Certificates: []tls.Certificate{cfg.Certificate},
		RootCAs:      cfg.RootCAs,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	}
	if len(cfg.AllowedServerSPKIPins) > 0 {
		pins := normalisePins(cfg.AllowedServerSPKIPins)
		t.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPins(rawCerts, pins, ErrServerPinMismatch)
		}
	}
	return credentials.NewTLS(t), nil
}

// SPKIPin returns the hex SHA-256 fingerprint of a certificate's
// SubjectPublicKeyInfo. This is the shape AllowedClient/ServerSPKIPins
// takes, so an operator produces one by running this (or `openssl x509
// -pubkey | openssl rsa -pubin -outform der | sha256sum`) over the leaf
// they want to pin and pasting the result into configuration.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// verifyPins is the VerifyPeerCertificate body shared by server and client
// pinning. rawCerts[0] is the leaf; a handshake with no peer certificate
// would have already been refused upstream by the TLS stack.
func verifyPins(rawCerts [][]byte, pins map[string]struct{}, mismatch error) error {
	if len(rawCerts) == 0 {
		return mismatch
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: parsing leaf certificate: %v", mismatch, err)
	}
	fp := SPKIPin(leaf)
	if _, ok := pins[fp]; !ok {
		return fmt.Errorf("%w: got %s", mismatch, fp)
	}
	return nil
}

// normalisePins builds a lookup set of lower-cased pins. Operators paste
// fingerprints from varied tools; accepting both cases is a convenience
// that costs nothing and avoids an outage from a mixed-case configuration
// row.
func normalisePins(pins []string) map[string]struct{} {
	out := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		out[lowerHex(p)] = struct{}{}
	}
	return out
}

// lowerHex normalises a hex fingerprint. It never allocates on an already
// lower-case string.
func lowerHex(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'F' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'F' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// LoadServerCredentialsFromFiles is the file-based convenience wrapper
// most production callers use. The CA bundle is one PEM file, the server
// certificate and key are a pair, and the pin set is either nil or passed
// through unchanged.
//
// A read failure is returned with the path included so an operator can
// find the misconfigured file.
func LoadServerCredentialsFromFiles(certFile, keyFile, caFile string, pins []string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("soroauth grpc: loading server cert/key from %q, %q: %w", certFile, keyFile, err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return LoadServerCredentials(ServerTLSConfig{
		Certificate:           cert,
		ClientCAs:             pool,
		AllowedClientSPKIPins: pins,
	})
}

// LoadClientCredentialsFromFiles mirrors LoadServerCredentialsFromFiles.
// ServerName must be supplied — this wrapper deliberately does not try to
// infer it from the certificate.
func LoadClientCredentialsFromFiles(certFile, keyFile, caFile, serverName string, pins []string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("soroauth grpc: loading client cert/key from %q, %q: %w", certFile, keyFile, err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return LoadClientCredentials(ClientTLSConfig{
		Certificate:           cert,
		RootCAs:               pool,
		ServerName:            serverName,
		AllowedServerSPKIPins: pins,
	})
}

// loadCAPool reads a PEM file into a CertPool. An empty pool (no PEM blocks
// parsed) is refused: a silent nothing-trusted outcome is what this
// function is supposed to prevent.
func loadCAPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("soroauth grpc: reading CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("soroauth grpc: CA bundle %q contained no usable certificates", path)
	}
	return pool, nil
}
