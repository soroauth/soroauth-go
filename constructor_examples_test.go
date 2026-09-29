package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
)

func ExampleNewThresholdSigner() {
	kp1, _ := keypair.FromRawSeed([32]byte{1, 2, 3})
	kp2, _ := keypair.FromRawSeed([32]byte{4, 5, 6})
	signer, err := NewThresholdSigner("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", 2, kp1.Address(), kp2.Address())
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

func ExampleNewThresholdPartySigner() {
	kp, _ := keypair.FromRawSeed([32]byte{1, 2, 3})
	edSigner := NewEd25519Signer(kp)
	signer, err := NewThresholdPartySigner("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", edSigner)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

func ExampleNewVaultSigner() {
	// A new vault signer that connects to a Vault Transit engine
	signer, err := NewVaultSigner(context.Background(), VaultConfig{
		Address: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		Token:   "s.mocktoken",
		BaseURL: "http://127.0.0.1:8200",
		Mount:   "transit",
		KeyName: "soroban-key",
	})
	if err != nil {
		// Shows connection failure output offline
		fmt.Printf("error: %v\n", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: error: calling vault: Get "http://127.0.0.1:8200/v1/transit/keys/soroban-key": dial tcp 127.0.0.1:8200: connect: connection refused
}

// mockLedgerTransport provides a fake ledger for offline examples.
type mockLedgerTransport struct{}

// Exchange implements LedgerTransport.
func (m mockLedgerTransport) Exchange(ctx context.Context, apdu []byte) ([]byte, error) {
	// 32-byte public key of zeroes + status word 0x9000
	resp := make([]byte, 32+2)
	resp[32] = 0x90
	resp[33] = 0x00
	return resp, nil
}

func ExampleNewLedgerSigner() {
	signer, err := NewLedgerSigner(context.Background(), mockLedgerTransport{})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}
