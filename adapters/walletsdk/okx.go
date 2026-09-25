package walletsdk

import (
	"fmt"

	okxkeypair "github.com/okx/go-wallet-sdk/coins/stellar/keypair"

	"github.com/soroauth/soroauth-go"
)

// FromOKXKeypair adapts an OKX wallet SDK keypair into a soroauth.Signer.
//
// github.com/okx/go-wallet-sdk's *coins/stellar/keypair.Full already satisfies
// Keypair, so this is NewSigner with a concrete parameter type: it exists so the
// worked integration with a real wallet SDK is one call the reader can find,
// instead of an interface satisfiability argument they have to check for
// themselves.
//
//	kp, err := okxkeypair.Random()
//	if err != nil {
//		return err
//	}
//	signer, err := walletsdk.FromOKXKeypair(kp)
//
// The address is checked to be a G… account and the key is asked to verify its
// own signature before it is returned; see NewSigner. TestOKXKeypairEndToEnd
// runs a keypair from this SDK through the whole adapter against a real signed
// entry.
func FromOKXKeypair(kp *okxkeypair.Full) (soroauth.Signer, error) {
	if kp == nil {
		return nil, fmt.Errorf("walletsdk: from okx keypair: %w", soroauth.ErrMissingSigner)
	}

	signer, err := NewSigner(kp)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: from okx keypair: %w", err)
	}
	return signer, nil
}
