package soroauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// BenchmarkDecodeAuthorizationEntry measures the bounded decode of an entry
// that came from somewhere else, which is the path Inspect and the CLI use for
// untrusted input (issue #121).
//
// The three signing-path benchmarks this file once carried (Preimage, Payload
// and AuthorizeEntry) live in bench_signing_test.go, which came from issue #107
// and is the copy that testdata/bench/budgets.json gates; duplicating the names
// here only made the package fail to build.
//
// The entry is built with benchAddressEntry so its bytes have the same shape as
// the signing-path benchmarks' input. ns/op is machine-dependent, and this
// benchmark has no budget entry, so checkbench reports it as a warning rather
// than gating on it.
func BenchmarkDecodeAuthorizationEntry(b *testing.B) {
	entry := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		"soroauth-bench-signer", 42)
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		b.Fatalf("encoding the benchmark entry: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := DecodeAuthorizationEntry(encoded); err != nil {
			b.Fatalf("DecodeAuthorizationEntry returned an unexpected error: %v", err)
		}
	}
}

// benchFullySignableBatch builds the same 12-entry, three-arm shape as
// bench_signing_test.go's benchRealisticBatch, but with a signer for every
// node RequireAllSigned will check — including each delegates entry's two
// delegates, which benchRealisticBatch's four rotating signers never match
// (by design: BenchmarkAuthorizeAll only needs one match per entry). Reusing
// benchRealisticBatch's own labels for the shared prefix keeps the two
// batches' address-arm entries identical, so BenchmarkAuthorizeAll and
// BenchmarkAuthorizeAllRequireAllSigned differ only by RequireAllSigned's own
// cost, not by a different batch shape.
func benchFullySignableBatch(b *testing.B) (entries []xdr.SorobanAuthorizationEntry, signers []Signer) {
	b.Helper()
	entries, signers = benchRealisticBatch(b)

	for i := 3; i < len(entries); i += 4 {
		dA := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-a-%d", i))
		dB := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-b-%d", i))
		signers = append(signers, NewEd25519Signer(dA), NewEd25519Signer(dB))
	}
	return entries, signers
}

// BenchmarkAuthorizeAllRequireAllSigned is BenchmarkAuthorizeAll's own
// 12-entry batch shape (bench_signing_test.go), with a signer added for
// every node and RequireAllSigned turned on (issue #103), so the two
// benchmarks can be compared directly: the difference between them is
// RequireAllSigned's post-signing walk plus the extra signers, not a
// different batch. Like BenchmarkDecodeAuthorizationEntry, this has no
// budget entry, so checkbench reports it as a warning only.
func BenchmarkAuthorizeAllRequireAllSigned(b *testing.B) {
	entries, signers := benchFullySignableBatch(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeAll(ctx, entries, signers, testValidUntilLedger, network.TestNetworkPassphrase,
			RequireAllSigned()); err != nil {
			b.Fatal(err)
		}
	}
}
