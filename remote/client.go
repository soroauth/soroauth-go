package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// defaultTimeout bounds a request even when the caller's context has no
// deadline, so a wedged server cannot hang a signing call forever.
const defaultTimeout = 30 * time.Second

// Signer is a soroauth.Signer whose signatures are produced by a remote server
// speaking this package's protocol.
//
// It satisfies soroauth.Signer, so it can be passed anywhere a local signer is
// accepted — AuthorizeEntry, AuthorizeAll, the CLI — with no other change. The
// context given to Sign is attached to the HTTP request, so cancelling it
// aborts an in-flight request rather than leaving it to finish in the
// background.
//
// It holds no secret: an address and a URL. It is safe to construct per call.
type Signer struct {
	address string
	url     string
	client  *http.Client
}

// Option adjusts a remote Signer.
type Option func(*Signer)

// WithHTTPClient sets the HTTP client the remote Signer uses.
//
// The default is http.DefaultClient with a timeout, so a request cannot hang
// forever even if the caller passes a context with no deadline. Supply your own
// to add transport settings, never to remove the timeout.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Signer) {
		if client != nil {
			s.client = client
		}
	}
}

// NewSigner returns a Signer that asks the server at baseURL to produce the
// signature for address.
//
// baseURL is the server root; the request path is appended. address must be the
// address the server signs for, since the server refuses a request addressed
// elsewhere.
func NewSigner(baseURL, address string, opts ...Option) *Signer {
	s := &Signer{
		address: address,
		url:     strings.TrimRight(baseURL, "/") + Path,
		client:  &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Address implements soroauth.Signer.
func (s *Signer) Address() string {
	if s == nil {
		return ""
	}
	return s.address
}

// Sign implements soroauth.Signer by asking the remote server to sign.
//
// Both the preimage and the payload are transmitted, so the remote end can
// inspect the structure it is approving rather than blind-signing the digest.
// The server recomputes the digest from the preimage and refuses a mismatch.
func (s *Signer) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: %w", err)
	}
	if s == nil || s.address == "" {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: %w", soroauth.ErrMissingSigner)
	}

	encodedPreimage, err := xdr.MarshalBase64(preimage)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: encoding the preimage: %w", err)
	}

	body, err := json.Marshal(Request{
		Version:  Version,
		Address:  s.address,
		Preimage: encodedPreimage,
		Payload:  hex.EncodeToString(payload[:]),
	})
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: encoding the request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: building the request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		// A cancelled context surfaces here as a transport error; unwrapping
		// keeps errors.Is(err, context.Canceled) working for the caller.
		return xdr.ScVal{}, fmt.Errorf("remote: sign: %w", err)
	}
	defer response.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBytes))
	decoder.DisallowUnknownFields()
	var decoded Response
	if err := decoder.Decode(&decoded); err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: server returned status %d with an unreadable body: %w", response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK {
		message := decoded.Error
		if message == "" {
			message = response.Status
		}
		return xdr.ScVal{}, fmt.Errorf("remote: sign: server refused: %s", message)
	}
	if decoded.Error != "" {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: server refused: %s", decoded.Error)
	}
	if decoded.Version != Version {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: server answered protocol version %d, want %d", decoded.Version, Version)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(decoded.Signature)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: signature is not valid base64: %w", err)
	}
	var signature xdr.ScVal
	if err := signature.UnmarshalBinary(signatureBytes); err != nil {
		return xdr.ScVal{}, fmt.Errorf("remote: sign: signature is not valid XDR: %w", err)
	}
	return signature, nil
}
