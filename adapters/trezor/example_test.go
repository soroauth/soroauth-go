package trezor_test

import (
	"fmt"

	"github.com/soroauth/soroauth-go/adapters/trezor"
)

func ExampleNewSigner() {
	// A nil transport, to show constructor rejection rather than to reach a
	// real device. In real code, transport wraps the Trezor USB/HID layer.
	var tr trezor.Transport
	_, err := trezor.NewSigner(
		"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		tr,
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Output: error: trezor: new signer: no signer for address
}
