package soroauth

import (
	"crypto/sha256"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleParseAddress_roundTrip parses the two address forms a credential may
// name, both derived from fixed labels the way every test key is, and formats
// each back. The strkey that comes out is the one that went in, which is what
// lets a caller compare addresses as strings or as XDR interchangeably.
func ExampleParseAddress_roundTrip() {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	contractSeed := sha256.Sum256([]byte("soroauth-example-contract"))
	contract, err := strkey.Encode(strkey.VersionByteContract, contractSeed[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, address := range []string{account.Address(), contract} {
		parsed, err := ParseAddress(address)
		if err != nil {
			fmt.Println("parse:", err)
			return
		}
		formatted, err := FormatAddress(parsed)
		if err != nil {
			fmt.Println("format:", err)
			return
		}
		fmt.Println(formatted, formatted == address)
	}

	// Output:
	// GAE47QJ5KGKGSXUHVS4ZDV6TS54EQXXRWEHGFLNMUC347AOIREDHL6MM true
	// CAPR3WQ46HIJ2GEOJSVHXQQBCKCZ4AJRBRCYMSJTB4LTJJQYX3NC6RZT true
}

// ExampleFormatAddress_muxed shows FormatAddress refusing a muxed account.
// ParseAddress never builds one, and FormatAddress refuses to render one
// rather than unwrapping it, so a caller is never shown an address that no
// address credential can carry (CAP-46-11).
func ExampleFormatAddress_muxed() {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	muxed, err := xdr.MuxedAccountFromAccountId(account.Address(), 7)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	address := xdr.ScAddress{
		Type: xdr.ScAddressTypeScAddressTypeMuxedAccount,
		MuxedAccount: &xdr.MuxedEd25519Account{
			Id:      muxed.Med25519.Id,
			Ed25519: muxed.Med25519.Ed25519,
		},
	}

	if _, err := FormatAddress(address); err != nil {
		fmt.Println("refused:", err)
	}

	// Output:
	// refused: soroauth: format address: muxed (M…) addresses are not valid in an address credential
}
