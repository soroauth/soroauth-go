package policy_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/policy"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func ExamplePolicySigner() {
	seedHash := sha256.Sum256([]byte("policy-example-signer"))
	kp, _ := keypair.FromRawSeed(seedHash)
	signer := soroauth.NewEd25519Signer(kp)

	rule := policy.NewMaxAmountRule(100)
	pol := policy.NewPolicySigner(signer, []policy.PolicyRule{rule})

	entry := xdr.SorobanAuthorizationEntry{}
	preimage, _ := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	payload, _ := soroauth.Payload(preimage)

	_, err := pol.Sign(context.Background(), preimage, payload)
	if err != nil {
		fmt.Println("policy check refused:", err != nil)
	}

	// Output:
	// policy check refused: true
}
