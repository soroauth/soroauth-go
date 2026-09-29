package soroauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// preimageExampleEntry builds an unsigned address credential of the given arm
// for a fixed account, nonce and contract call, so the preimage examples print
// the same bytes on every run.
func preimageExampleEntry(arm xdr.SorobanCredentialsType) (xdr.SorobanAuthorizationEntry, error) {
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	address, err := ParseAddress(account.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	contractSeed := sha256.Sum256([]byte("soroauth-example-contract"))
	contractStrkey, err := strkey.Encode(strkey.VersionByteContract, contractSeed[:])
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	contract, err := ParseAddress(contractStrkey)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}

	credentials := &xdr.SorobanAddressCredentials{
		Address:   address,
		Nonce:     42,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{Type: arm},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{},
				},
			},
		},
	}
	switch arm {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		entry.Credentials.Address = credentials
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		entry.Credentials.AddressV2 = credentials
	}
	return entry, nil
}

// ExamplePreimage shows that the credentials arm, not the caller, picks the
// preimage variant: the legacy arm (CAP-46-11) gets one that does not name the
// signing address, and the V2 arm (CAP-71-01) gets one that binds it in. A
// source-account entry has no preimage at all, because the transaction
// envelope's own signature covers it.
func ExamplePreimage() {
	const validUntilLedger = 1_234_567

	for _, arm := range []xdr.SorobanCredentialsType{
		xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
	} {
		entry, err := preimageExampleEntry(arm)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		preimage, err := Preimage(entry, validUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Printf("%s -> %s address_bound=%t\n",
			arm, preimage.Type, preimage.SorobanAuthorizationWithAddress != nil)
	}

	source := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}
	_, err := Preimage(source, validUntilLedger, network.TestNetworkPassphrase)
	fmt.Println("source account refused:", errors.Is(err, ErrSourceAccountCredentials))

	// Output:
	// SorobanCredentialsTypeSorobanCredentialsAddress -> EnvelopeTypeEnvelopeTypeSorobanAuthorization address_bound=false
	// SorobanCredentialsTypeSorobanCredentialsAddressV2 -> EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress address_bound=true
	// source account refused: true
}

// ExamplePayload hashes a preimage into the 32 bytes a signer signs. Every
// input is fixed, so the digest is too. The network passphrase and the
// expiration ledger are both part of what is signed: changing either one
// changes the payload, which is why a signature made for testnet cannot be
// replayed on the public network, and why the expiration written into an entry
// has to be the one it was signed with.
//
// The printed digest was cross-checked against @stellar/stellar-sdk@17.1.0,
// the same pinned reference the golden vectors come from, by building the same
// HashIdPreimage there and hashing it.
func ExamplePayload() {
	entry, err := preimageExampleEntry(xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	payloadFor := func(validUntilLedger uint32, passphrase string) (string, error) {
		preimage, err := Preimage(entry, validUntilLedger, passphrase)
		if err != nil {
			return "", err
		}
		payload, err := Payload(preimage)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(payload[:]), nil
	}

	testnet, err := payloadFor(1_234_567, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	public, err := payloadFor(1_234_567, network.PublicNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	later, err := payloadFor(1_234_568, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(testnet)
	fmt.Println("differs on the public network:", public != testnet)
	fmt.Println("differs one ledger later:", later != testnet)

	// Output:
	// 34ae26a3f29077bf1c15dd5d3617a7b79b09b9a1612a661b4f7bd04aa9ed12dc
	// differs on the public network: true
	// differs one ledger later: true
}
