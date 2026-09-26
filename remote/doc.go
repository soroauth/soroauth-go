// Package remote defines a wire protocol for signing a Soroban authorization
// payload over HTTP, and ships a reference server implementing it plus a client
// that satisfies soroauth.Signer.
//
// The point of the protocol is that the *preimage* is transmitted, not just the
// digest. soroauth's Signer interface receives both so that a remote or
// hardware signer can inspect the whole structure it is approving — which
// contract, which function, which arguments, which address and nonce — rather
// than blind-signing an opaque 32-byte hash. A protocol that shipped only the
// hash would make that inspection impossible and is exactly the mistake this
// package exists to avoid.
//
// The shape of a request is deliberately small:
//
//	POST /sign
//	{"version":1,"address":"G…","preimage":"<base64 XDR HashIdPreimage>","payload":"<hex>"}
//
// and a response is either a signature or an error:
//
//	{"version":1,"signature":"<base64 XDR ScVal>"}
//	{"version":1,"error":"…"}
//
// The server recomputes SHA-256 of the transmitted preimage and refuses the
// request when it does not match the transmitted payload, so a client cannot
// ask the signer to approve one thing while presenting a digest for another.
// The client sends the context through to the HTTP request, so cancelling the
// caller's context aborts an in-flight request.
//
// This is a reference implementation, not a production service. It deliberately
// does not authenticate callers, does not store keys, does not persist anything,
// and does not rate-limit. Anyone who can reach it can ask it to sign, which is
// why the reference configuration is a loopback address and why any real
// deployment must add authentication and transport security in front of it.
package remote
