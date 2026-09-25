package walletsdk_test

import (
	"context"

	okxkeypair "github.com/okx/go-wallet-sdk/coins/stellar/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/adapters/walletsdk"
)

// ExampleSign is the whole adapter in one function: take the envelope a wallet
// was handed, ask what it wants, sign it, record the enforce simulation pass,
// and take the submittable envelope.
//
// The examples here carry no output comment, so `go test` compiles them but
// does not run them: the key is random and none of this may reach a network.
func ExampleSign() {
	// A base64 TransactionEnvelope, as an RPC client hands one back.
	var base64XDR string

	kp, err := okxkeypair.Random()
	if err != nil {
		panic(err)
	}

	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(base64XDR, &env); err != nil {
		panic(err)
	}

	// What does this envelope need from me?
	requirements, err := walletsdk.Requirements(env, kp.Address())
	if err != nil {
		panic(err)
	}

	// The entries this wallet still owes a signature for.
	var outstanding []walletsdk.Requirement
	for _, requirement := range requirements {
		if requirement.Wanted && !requirement.Signed {
			outstanding = append(outstanding, requirement)
		}
	}
	_ = outstanding

	ctx := context.Background()
	validUntilLedger := uint32(1_000_000)
	passphrase := network.TestNetworkPassphrase

	signed, err := walletsdk.Sign(ctx, env, kp, validUntilLedger, passphrase)
	if err != nil {
		panic(err)
	}

	// The enforce simulation runs in your RPC client, with the entries Sign
	// just produced. Envelope refuses to hand anything over until this says
	// that pass happened.
	enforceRequest := signed.Entries()
	_ = enforceRequest
	signed.MarkEnforced()

	submittable, err := signed.Envelope()
	if err != nil {
		panic(err)
	}

	// Later, or on another machine, check a signature that is already there.
	if err := walletsdk.VerifyEnvelope(submittable, kp, validUntilLedger, passphrase); err != nil {
		panic(err)
	}
}

// ExampleFromOKXKeypair shows the worked integration: a keypair from
// github.com/okx/go-wallet-sdk already satisfies the three-method Keypair
// interface this adapter bridges, so adopting it is one call.
func ExampleFromOKXKeypair() {
	kp, err := okxkeypair.Random()
	if err != nil {
		panic(err)
	}

	signer, err := walletsdk.FromOKXKeypair(kp)
	if err != nil {
		panic(err)
	}

	// The signer writes the built-in account signature shape onto the
	// credential nodes whose address is this keypair's.
	_ = signer.Address()

	// Any other wallet SDK whose keypair has Address, Sign([]byte) ([]byte,
	// error) and Verify([]byte, []byte) error goes through NewSigner with no
	// adapter of its own.
	generic, err := walletsdk.NewSigner(kp)
	if err != nil {
		panic(err)
	}
	_ = generic
}
