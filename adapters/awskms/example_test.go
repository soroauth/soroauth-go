package awskms_test

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/soroauth/soroauth-go/adapters/awskms"
)

func ExampleNewSigner() {
	// Pass a nil client for the example. Real code passes a *kms.Client.
	var client *kms.Client
	signer, err := awskms.NewSigner("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "keyId", client)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: error: awskms: new signer: soroauth: no signer provided
}
