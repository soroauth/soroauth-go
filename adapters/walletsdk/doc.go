// Package walletsdk presents soroauth through the shape a wallet SDK expects,
// so a wallet can adopt it without restructuring.
//
// Wallets are the largest consumer of soroauth, and the two things they hold
// are a transaction envelope and a keypair. This package takes both:
//
//	kp, err := okxkeypair.Random()            // github.com/okx/go-wallet-sdk
//	var env xdr.TransactionEnvelope
//	err = xdr.SafeUnmarshalBase64(base64XDR, &env) // a full TransactionEnvelope
//
//	// What does this envelope need from me?
//	required, err := walletsdk.Requirements(env, kp.Address())
//
//	// Sign it. The result will not surrender an envelope until the enforce
//	// pass is recorded.
//	signed, err := walletsdk.Sign(ctx, env, kp, validUntilLedger, passphrase)
//	enforceRequest := signed.Entries()
//	// ... simulate again in enforce mode ...
//	signed.MarkEnforced()
//	submittable, err := signed.Envelope()
//
//	// Later, or on another machine, check a signature that is already there.
//	err = walletsdk.VerifyEnvelope(env, kp, validUntilLedger, passphrase)
//
// # The two simulation passes
//
// soroauth signs authorization entries, and signing them changes what the
// transaction costs to run. The transaction assembled from the record-mode
// simulation therefore carries too small a resource fee, and submitting it
// produces a fee error rather than a signature error. That second pass is the
// caller's RPC client's job, and this package does not do it for you.
//
// What it does instead is refuse to forget it. Signed.Entries reports the
// signed entries so they can be put into the enforce simulation, and
// Signed.Envelope refuses with ErrEnforcePassMissing until MarkEnforced has
// recorded that the pass ran. There is no way to get a submittable envelope out
// of this package without saying, in the code, that the enforce pass happened.
//
// # The wallet SDKs this binds to
//
// The bridge is the Keypair interface, three methods wide, which
// github.com/okx/go-wallet-sdk's *coins/stellar/keypair.Full satisfies as it
// stands. okx.go binds it by name so the worked integration is a file you can
// read; any other SDK with the same three methods goes through NewSigner with
// no adapter of its own.
//
// # Why this is a separate module
//
// This package depends on a wallet SDK, and the root module must not. It lives
// in its own Go module whose only requires are soroauth itself, a wallet SDK,
// and the Stellar XDR types, so importing soroauth never drags a wallet SDK
// along. The cost of that boundary is that `go test ./...` at the repository
// root does not descend into a nested module, which is why CI runs this
// module's tests as a job of their own.
package walletsdk
