package pkcs11_test

import (
	"fmt"

	"github.com/soroauth/soroauth-go/adapters/pkcs11"
)

func ExampleNewSigner() {
	// A nil ctx, to show constructor rejection rather than to reach a real HSM.
	// In real code, ctx is a wrapper around a github.com/miekg/pkcs11 *pkcs11.Ctx.
	var ctx pkcs11.P11Ctx
	_, err := pkcs11.NewSigner(
		"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		0,
		"my-ed25519-key",
		ctx,
		func() ([]byte, error) { return []byte("pin"), nil },
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Output: error: pkcs11: new signer: no signer for address
}
