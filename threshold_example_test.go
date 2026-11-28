package soroauth_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/frost"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleThresholdSigner_success demonstrates a successful signature using a threshold signer
// with enough participants contributing valid shares.
func ExampleThresholdSigner_success() {
	account := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	kpA, _ := keypair.FromRawSeed(sha256.Sum256([]byte("threshold-party-a")))
	kpB, _ := keypair.FromRawSeed(sha256.Sum256([]byte("threshold-party-b")))
	partyA := kpA.Address()
	partyB := kpB.Address()

	signer, err := soroauth.NewThresholdSigner(account, 2, partyA, partyB)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	ctx := context.Background()
	round, err := signer.Begin(ctx)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Fixed test share 1 (deterministic 32-byte prefix + data)
	share1 := make([]byte, 64)
	copy(share1[:32], []byte(partyA))
	share1[32] = 0x42

	// Fixed test share 2
	share2 := make([]byte, 64)
	copy(share2[:32], []byte(partyB))
	share2[32] = 0x24

	_, err = signer.Contribute(ctx, round, share1)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	accSig, err := signer.Contribute(ctx, round, share2)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	if accSig != nil && signer.IsComplete() {
		fmt.Println("Threshold met: signature produced successfully.")
	}

	// Output:
	// Threshold met: signature produced successfully.
}

// ExampleThresholdSigner_refusalBelowThreshold demonstrates that a below-threshold attempt
// refuses cleanly with no partial result.
func ExampleThresholdSigner_refusalBelowThreshold() {
	account := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	kpA, _ := keypair.FromRawSeed(sha256.Sum256([]byte("threshold-party-a")))
	kpB, _ := keypair.FromRawSeed(sha256.Sum256([]byte("threshold-party-b")))
	partyA := kpA.Address()
	partyB := kpB.Address()

	signer, err := soroauth.NewThresholdSigner(account, 2, partyA, partyB)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	ctx := context.Background()
	round, err := signer.Begin(ctx)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Only 1 share provided for a 2-of-2 (or 2-of-3) requirement
	share1 := make([]byte, 64)
	copy(share1[:32], []byte(partyA))
	share1[32] = 0x42

	res, err := signer.Contribute(ctx, round, share1)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	if res == nil && !signer.IsComplete() {
		fmt.Println("Refused cleanly: below threshold, no partial result produced.")
	}

	// Attempting to sign the entry directly before threshold is met fails
	preimage := xdr.HashIdPreimage{}
	var payload [32]byte
	_, signErr := signer.Sign(ctx, preimage, payload)
	if signErr != nil {
		fmt.Println("Sign failed as expected due to missing signers.")
	}

	// Output:
	// Refused cleanly: below threshold, no partial result produced.
	// Sign failed as expected due to missing signers.
}
func ExampleFROSTSigner() {
	seedHash := sha256.Sum256([]byte("threshold-example"))
	kp, _ := keypair.FromRawSeed(seedHash)
	address := kp.Address()

	secretShares, vk, pkShares, err := frost.TrustedDealerKeygen(2, 3)
	if err != nil {
		fmt.Println(err)
		return
	}

	coord, err := frost.NewFROSTCoordinator(vk, pkShares, 2, 3, address)
	if err != nil {
		fmt.Println(err)
		return
	}

	p1, _ := frost.NewFROSTParticipant(secretShares[0], pkShares[0], 1, coord)
	signer, err := frost.NewFROSTSigner(coord, []*frost.FROSTParticipant{p1})
	if err != nil {
		fmt.Println("below-threshold refusal successfully caught:", err != nil)
		return
	}

	entry := xdr.SorobanAuthorizationEntry{}
	preimage, _ := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	payload, _ := soroauth.Payload(preimage)
	_, _ = signer.Sign(context.Background(), preimage, payload)

	// Output:
	// below-threshold refusal successfully caught: true
}
