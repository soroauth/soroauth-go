package soroauth_test

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Signed entry from testdata/vectors/v2_empty_args.json.
const equalExampleSigned = "AAAAAgAAAAAAAAAAt7bYKS3hKDB7Aw8ykLPfkH7kJtcX2OWQMp2pPDOof8oRIhD0femBFQAS1ocAAAAQAAAAAQAAAAEAAAARAAAAAQAAAAIAAAAPAAAACnB1YmxpY19rZXkAAAAAAA0AAAAgt7bYKS3hKDB7Aw8ykLPfkH7kJtcX2OWQMp2pPDOof8oAAAAPAAAACXNpZ25hdHVyZQAAAAAAAA0AAABAbuXXkAcIyh8u0Zn00vEvHKc8tx0CAzKdu7usBiNSJnO8dY9pAfTTjoe2f0MKiq1NIv59QCKHQPyMLRvPTocqDwAAAAAAAAABayKAB7bw0Aj4BirOOVQHTOXNv1TqTMUDAi8Ik+b1DrMAAAAEbm9vcAAAAAAAAAAA"

// ExampleEqual shows that a signature is part of the XDR equality check.
func ExampleEqual() {
	entry, err := soroauth.DecodeAuthorizationEntry(equalExampleSigned)
	if err != nil {
		panic(err)
	}
	other, err := soroauth.Clone(entry)
	if err != nil {
		panic(err)
	}

	fmt.Println("matching signatures:", soroauth.Equal(entry, other))
	other.Credentials.AddressV2.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	fmt.Println("different signatures:", soroauth.Equal(entry, other))

	// Output:
	// matching signatures: true
	// different signatures: false
}

// ExampleClone changes a nested field through the copy's credential pointer.
func ExampleClone() {
	entry, err := soroauth.DecodeAuthorizationEntry(equalExampleSigned)
	if err != nil {
		panic(err)
	}
	cloned, err := soroauth.Clone(entry)
	if err != nil {
		panic(err)
	}

	cloned.Credentials.AddressV2.SignatureExpirationLedger++
	fmt.Println("original ledger:", entry.Credentials.AddressV2.SignatureExpirationLedger)
	fmt.Println("cloned ledger:", cloned.Credentials.AddressV2.SignatureExpirationLedger)

	// Output:
	// original ledger: 1234567
	// cloned ledger: 1234568
}
