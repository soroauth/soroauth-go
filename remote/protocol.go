package remote

import "github.com/stellar/go-stellar-sdk/xdr"

// Version is the protocol version this package speaks.
//
// It is sent in every request and echoed in every response, so a client and a
// server that disagree about the schema fail with a named version mismatch
// rather than by misreading each other's fields. It is bumped whenever the
// request or response shape changes; there is no negotiation.
const Version = 1

// Path is the HTTP path the reference server serves.
const Path = "/sign"

// Request is the JSON body a client sends to ask a remote signer to sign.
//
// Address names the credential node the signature belongs to, so a server
// holding several keys can refuse a request addressed elsewhere. Preimage is
// the base64 XDR HashIdPreimage — sent whole, so the signer can inspect what it
// is approving — and Payload is the lowercase hex SHA-256 of that preimage's
// XDR encoding.
type Request struct {
	Version  int    `json:"version"`
	Address  string `json:"address"`
	Preimage string `json:"preimage"`
	Payload  string `json:"payload"`
}

// Response is the JSON body a server returns.
//
// Exactly one of Signature and Error is set. Signature is the base64 XDR ScVal
// to write verbatim into the credential node, the same value a local Signer
// would have returned.
type Response struct {
	Version   int    `json:"version"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Approval is what a server hands to its Approver callback before it signs.
//
// It carries the decoded preimage and payload so the callback can log, audit
// or veto what is about to be approved. It contains no secret: the preimage and
// payload are public structures, and the key never leaves the server's Signer.
type Approval struct {
	// Address is the address the request was addressed to.
	Address string

	// Preimage is the decoded preimage. Its variant and fields say which arm
	// is being signed, for which address, and against which expiration.
	Preimage xdr.HashIdPreimage

	// Payload is the 32-byte digest that will be signed.
	Payload [32]byte
}
