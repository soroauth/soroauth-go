package gcpkms_test

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/soroauth/soroauth-go/adapters/gcpkms"
)

func ExampleNewSigner() {
	// Provide a nil client for the example, which fails instantly
	// but demonstrates the signature. In real code, pass a *kms.KeyManagementClient.
	var client *kms.KeyManagementClient
	signer, err := gcpkms.NewSigner("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "keyVersion", client)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: error: gcpkms: new signer: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF: soroauth: no signer provided
}
