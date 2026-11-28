package soroauth_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func ExampleNewFallbackSigner() {
	seedHash := sha256.Sum256([]byte("signer-fallback-example"))
	kp1, _ := keypair.FromRawSeed(seedHash)
	s1 := soroauth.NewEd25519Signer(kp1)
	s2 := soroauth.NewEd25519Signer(kp1)

	chain, err := soroauth.NewFallbackSigner([]soroauth.Signer{s1, s2})
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = chain
	fmt.Println("fallback chain constructed")
	// Output:
	// fallback chain constructed
}

func ExampleNewQuorumSigner() {
	seedHash := sha256.Sum256([]byte("signer-quorum-example"))
	kp1, _ := keypair.FromRawSeed(seedHash)
	s1 := soroauth.NewEd25519Signer(kp1)
	s2 := soroauth.NewEd25519Signer(kp1)

	chain, err := soroauth.NewQuorumSigner(2, []soroauth.Signer{s1, s2})
	if err != nil {
		fmt.Println(err)
		return
	}

	entry := xdr.SorobanAuthorizationEntry{}
	preimage, _ := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	payload, _ := soroauth.Payload(preimage)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = chain.Sign(ctx, preimage, payload)
	if err != nil {
		fmt.Println("quorum not met or error:", err != nil)
	}

	// Output:
	// quorum not met or error: true
}
