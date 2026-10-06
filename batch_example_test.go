package soroauth_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const batchExampleContract = "CDHAN6JJTQCD6QDPW3PJPV2NFV3QDQY5HVXEUHCAGH3GZRU2V2Q5V6RA"

// batchExampleKeypair derives a keypair from a fixed label, so the examples are
// reproducible. These are public test keys and hold nothing.
func batchExampleKeypair(label string) *keypair.Full {
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		panic(err)
	}
	return kp
}

// batchExampleEntry builds an unsigned V2-arm entry for the given address.
func batchExampleEntry(address string, nonce int64) xdr.SorobanAuthorizationEntry {
	parsed, err := soroauth.ParseAddress(address)
	if err != nil {
		panic(err)
	}
	contract, err := soroauth.ParseAddress(batchExampleContract)
	if err != nil {
		panic(err)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   parsed,
				Nonce:     xdr.Int64(nonce),
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
}

// batchExampleSourceAccountEntry is the arm the transaction's own signature
// authorizes.
func batchExampleSourceAccountEntry() xdr.SorobanAuthorizationEntry {
	entry := batchExampleEntry(batchExampleKeypair("batch-a").Address(), 1)
	entry.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
	}
	return entry
}

// ExampleAuthorizeAll signs a whole batch, or none of it.
//
// This is the call for what simulateTransaction hands back: a slice that can
// mix arms. Source-account entries pass through untouched, so a caller does not
// have to sort them out first.
func ExampleAuthorizeAll() {
	first := batchExampleKeypair("batch-first")
	second := batchExampleKeypair("batch-second")

	entries := []xdr.SorobanAuthorizationEntry{
		batchExampleSourceAccountEntry(),
		batchExampleEntry(first.Address(), 11),
		batchExampleEntry(second.Address(), 22),
	}

	signed, err := soroauth.AuthorizeAll(context.Background(), entries, []soroauth.Signer{
		soroauth.NewEd25519Signer(first),
		soroauth.NewEd25519Signer(second),
	}, 5_000_000, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for i, entry := range signed {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Printf("entry %d: %s signed=%t\n", i, info.CredentialType, info.TopLevelSigned)
	}

	// Output:
	// entry 0: source_account signed=false
	// entry 1: address_v2 signed=true
	// entry 2: address_v2 signed=true
}

// ExampleAuthorizeAll_missingSigner shows the refusal, which is the point of
// the function.
//
// An entry that goes out unsigned produces a transaction the network accepts,
// charges for, and then fails during application. So an address entry with no
// applicable signer fails the whole call and names the address. Nothing is
// skipped quietly, and the returned slice is nil rather than partial — a caller
// cannot accidentally submit a batch that is half signed.
func ExampleAuthorizeAll_missingSigner() {
	present := batchExampleKeypair("batch-present")
	absent := batchExampleKeypair("batch-absent")

	entries := []xdr.SorobanAuthorizationEntry{
		batchExampleEntry(present.Address(), 11),
		batchExampleEntry(absent.Address(), 22),
	}

	signed, err := soroauth.AuthorizeAll(context.Background(), entries,
		// Only a signer for the first entry.
		[]soroauth.Signer{soroauth.NewEd25519Signer(present)},
		5_000_000, network.TestNetworkPassphrase)

	fmt.Println("returned entries:", len(signed))
	fmt.Println("is ErrMissingSigner:", errors.Is(err, soroauth.ErrMissingSigner))
	fmt.Println("names the address:", err != nil && strings.Contains(err.Error(), absent.Address()))

	// Output:
	// returned entries: 0
	// is ErrMissingSigner: true
	// names the address: true
}

// ExampleWithConcurrency bounds how many entries VerifyAll checks at once.
//
// Verification is CPU-bound signature work with no shared state, so the only
// reason to bound it is to leave room for whatever else the process is doing.
// The default is already bounded; this is for a caller who wants a different
// ceiling. It does not change any verdict — only how fast they arrive.
func ExampleWithConcurrency() {
	kp := batchExampleKeypair("batch-verify")
	entry, err := soroauth.AuthorizeEntry(context.Background(),
		batchExampleEntry(kp.Address(), 7), soroauth.NewEd25519Signer(kp),
		5_000_000, network.TestNetworkPassphrase)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	results, err := soroauth.VerifyAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry, entry},
		network.TestNetworkPassphrase,
		soroauth.WithConcurrency(2))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, r := range results {
		fmt.Printf("entry %d: err=%v\n", r.Index, r.Error)
	}

	// Output:
	// entry 0: err=<nil>
	// entry 1: err=<nil>
}
