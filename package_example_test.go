package soroauth

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Example is the path from a simulated authorization entry to a signed one:
// decode what simulateTransaction returned, make sure it is the address-bound
// V2 arm, choose an expiration from the ledger simulation reported, sign, and
// encode the result to put back into the transaction.
//
// The inputs are fixed so the output is stable. simulatedAuth is the unsigned
// entry of the legacy_single_testnet golden vector, which @stellar/stellar-sdk
// generated, and the key is derived from that vector's public test label (see
// "Deterministic test keys" in CONTRIBUTING.md). Upgrading that entry and
// signing it gives the v2_single_testnet vector byte for byte, so the payload
// printed below is that vector's payload_hex.
func Example() {
	// One element of SimulateTransactionResponse.Results[i].AuthXDR (JSON
	// "auth"). Simulation may return the legacy arm even when
	// UseUpgradedAuth was requested, as it does here.
	const simulatedAuth = "AAAAAQAAAAAAAAAAt7bYKS3hKDB7Aw8ykLPfkH7kJtcX2OWQMp2pPDOof8oRIhD0femBFQAAAAAAAAAQAAAAAQAAAAAAAAAAAAAAATRrZDx31oeiVF0aSLeGFRrK5f+qDrWvYPXG86PwH6rRAAAACHRyYW5zZmVyAAAADQAAAAEAAAAAAAAAAQAAAAMAAAAHAAAABP////kAAAAF//////////8AAAAG/9////////8AAAAPAAAACHRyYW5zZmVyAAAADgAAABFhIHN0cmluZyBhcmd1bWVudAAAAAAAAA0AAAAIc29yb2F1dGgAAAASAAAAAAAAAADPqMFVnXxt0Bnz2j/PUq2wC1ksRV8F0C/Wn7FszQMp5AAAABIAAAABiYTtffRvjkxhpdNokUurCdK7WuhA3mCRriGP1/FA4bIAAAAQAAAAAQAAAAIAAAADAAAAAQAAAAMAAAACAAAAEQAAAAEAAAABAAAADwAAAAZhbW91bnQAAAAAAAr//////////wAAAAAAAAAqAAAAAA=="
	// SimulateTransactionResponse.LatestLedger.
	const latestLedger = 1_234_447

	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-vector-signer-1")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	entry, err := DecodeAuthorizationEntry(simulatedAuth)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err = UpgradeToV2(entry)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// About ten minutes of ledgers. The returned ledger is the last one in
	// which the signature is accepted.
	validUntil, err := ExpirationAfter(latestLedger, 120)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	signed, err := AuthorizeEntry(context.Background(), entry, NewEd25519Signer(kp),
		validUntil, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	preimage, err := Preimage(signed, validUntil, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	payload, err := Payload(preimage)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	info, err := Inspect(signed)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// This string replaces the unsigned entry in the transaction's auth list
	// before the enforce-mode simulation and submission.
	encoded, err := xdr.MarshalBase64(signed)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("%s signed=%t valid_until=%d\n", info.CredentialType, info.TopLevelSigned, info.ValidUntilLedger)
	fmt.Printf("payload %x\n", payload)
	fmt.Println("encoded bytes:", len(encoded))

	// Output:
	// address_v2 signed=true valid_until=1234567
	// payload 234c80770a3dcf2f628a1f0aabac82f180f0ec510461c419574307c255caea00
	// encoded bytes: 752
}
