package remote

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// MaxRequestBytes bounds the JSON request body the reference server will read.
//
// The body is untrusted input, so it is read through a limit rather than in
// full: a request larger than this is refused with a 400 instead of being
// buffered. It is far larger than any real preimage, whose invocation tree is
// bounded by the caller's own construction.
const MaxRequestBytes = 1 << 20

// Server is a reference implementation of the remote signing protocol.
//
// It holds one soroauth.Signer and answers POST /sign for the address that
// signer signs for; a request addressed anywhere else is refused. Before it
// signs it recomputes SHA-256 of the transmitted preimage and refuses the
// request when that disagrees with the transmitted payload, so the digest a
// caller presents is always the digest of the structure the signer inspects.
//
// It is deliberately stateless and key-holding only in the sense that it wraps
// a Signer. It has no authentication, no authorization, no rate limiting and no
// TLS of its own; anyone who can reach it can ask it to sign. It is a reference
// for the protocol, not a production service — put authentication and transport
// security in front of it before exposing it anywhere.
type Server struct {
	signer   soroauth.Signer
	Approver func(Approval)
}

// NewServer returns a reference server that signs with signer.
//
// The returned server implements http.Handler. Set Approver to observe each
// approval before it happens; see LogApprover for a ready-made logger.
func NewServer(signer soroauth.Signer) *Server {
	return &Server{signer: signer}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method must be POST")
		return
	}
	if s == nil || s.signer == nil {
		writeError(w, http.StatusInternalServerError, "server has no signer")
		return
	}

	decoder := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBytes))
	decoder.DisallowUnknownFields()
	var req Request
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if req.Version != Version {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol version %d, want %d", req.Version, Version))
		return
	}
	if req.Address != s.signer.Address() {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("this server signs for %s, not %q", s.signer.Address(), req.Address))
		return
	}

	preimageBytes, err := base64.StdEncoding.DecodeString(req.Preimage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "preimage is not valid base64: "+err.Error())
		return
	}
	var preimage xdr.HashIdPreimage
	if err := preimage.UnmarshalBinary(preimageBytes); err != nil {
		writeError(w, http.StatusBadRequest, "preimage is not valid XDR: "+err.Error())
		return
	}

	payloadBytes, err := hex.DecodeString(req.Payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "payload is not valid hex: "+err.Error())
		return
	}
	if len(payloadBytes) != 32 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("payload is %d bytes, want 32", len(payloadBytes)))
		return
	}
	var payload [32]byte
	copy(payload[:], payloadBytes)

	// The whole point of sending the preimage is that the digest is derived
	// here rather than trusted, so a client cannot have the signer approve one
	// structure while presenting a digest for another.
	recomputed, err := soroauth.Payload(preimage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot hash the preimage: "+err.Error())
		return
	}
	if recomputed != payload {
		writeError(w, http.StatusBadRequest, "payload does not match SHA-256 of the preimage")
		return
	}

	if s.Approver != nil {
		s.Approver(Approval{Address: req.Address, Preimage: preimage, Payload: payload})
	}

	signature, err := s.signer.Sign(r.Context(), preimage, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signer refused: "+err.Error())
		return
	}

	encoded, err := xdr.MarshalBase64(signature)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot encode the signature: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, Response{Version: Version, Signature: encoded})
}

// LogApprover returns an Approver that writes a one-line summary of each
// approval to w.
//
// It is a reference convenience for the server above, kept opt-in so the
// package does no logging of its own: a deployment that wants a different
// record sets its own Approver instead. Nothing secret can reach the line —
// the preimage and payload are public, and the key stays inside the Signer.
func LogApprover(w io.Writer) func(Approval) {
	return func(a Approval) {
		var nonce int64
		var expiration uint32
		switch a.Preimage.Type {
		case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization:
			if a.Preimage.SorobanAuthorization != nil {
				nonce = int64(a.Preimage.SorobanAuthorization.Nonce)
				expiration = uint32(a.Preimage.SorobanAuthorization.SignatureExpirationLedger)
			}
		case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress:
			if a.Preimage.SorobanAuthorizationWithAddress != nil {
				nonce = int64(a.Preimage.SorobanAuthorizationWithAddress.Nonce)
				expiration = uint32(a.Preimage.SorobanAuthorizationWithAddress.SignatureExpirationLedger)
			}
		}
		fmt.Fprintf(w, "remote: approving address=%s variant=%s nonce=%d valid_until=%d payload=%x\n",
			a.Address, a.Preimage.Type, nonce, expiration, a.Payload)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, Response{Version: Version, Error: message})
}
