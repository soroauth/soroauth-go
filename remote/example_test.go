package remote_test

import (
	"fmt"
	"github.com/soroauth/soroauth-go/remote"
)

func ExampleNewSigner() {
	signer := remote.NewSigner("http://localhost:8080", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

func ExampleNewServer() {
	// Dummy signer that implements soroauth.Signer
	// In a real application, you'd use a real signer here
	server := remote.NewServer(nil) // Assuming NewServer takes a soroauth.Signer
	fmt.Printf("server != nil: %t\n", server != nil)

	// Output: server != nil: true
}
