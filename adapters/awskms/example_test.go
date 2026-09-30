package awskms_test

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/soroauth/soroauth-go/adapters/awskms"
)

func ExampleNewSigner() {
	// A nil client, to show what the constructor does with one rather than to
	// reach AWS: the example runs offline and makes no network call. In real
	// code this is a *kms.Client from kms.NewFromConfig.
	//
	// Note this is a *typed* nil. NewSigner refuses it, which is the point —
	// accepting it would hand back a signer that panics later, inside Sign.
	var client *kms.Client
	signer, err := awskms.NewSigner("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "keyId", client)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: error: awskms: new signer: no signer for address
}
