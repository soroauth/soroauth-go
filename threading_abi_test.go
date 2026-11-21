package soroauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"runtime"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestABIThreadingContract exercises every library entry point the C ABI
// surface (bindings/c/soroauth.go) calls into, from many goroutines in
// parallel, over the full golden-vector set. Its purpose is to be the
// evidence attached to bindings/c/THREADING.md: when it passes under
// `go test -race`, the contract's Go-side claim ("all functions are safe to
// call concurrently") holds for this commit.
//
// What it does not do: cover the host (JVM, Python, Node) side of the
// boundary. A race detector sees the Go runtime; a caller that mishandles a
// char* on the host side is outside what this proves.
func TestABIThreadingContract(t *testing.T) {
	vectors := loadVectors(t)
	// A small vector set would let scheduling sweep away a race rather than
	// expose it; the suite ships with ~20, which is enough that each goroutine
	// hits a different one most iterations.
	if len(vectors) < 3 {
		t.Fatalf("not enough vectors to exercise concurrency: %d", len(vectors))
	}

	// Work scaled from GOMAXPROCS so the test runs the same shape on a laptop
	// and on CI without picking an unrealistically small or large number.
	workers := runtime.GOMAXPROCS(0) * 4
	if workers < 8 {
		workers = 8
	}
	const iterationsPerWorker = 24

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		seed := int64(w) + 1
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < iterationsPerWorker; i++ {
				v := vectors[rng.Intn(len(vectors))]
				exerciseVector(t, v)
			}
		}(seed)
	}
	wg.Wait()
}

// exerciseVector runs every library call the C ABI makes against one vector.
// Any path that panics or returns an unexpected error makes the test fail
// from whichever goroutine hit it. Byte-for-byte equality against the
// recorded preimage, payload, and signed entry is asserted where the
// recorded fields exist, so a concurrent call that corrupted another call's
// intermediate state would be caught here rather than only by the race
// detector.
func exerciseVector(t *testing.T, v vector) {
	entry, err := DecodeAuthorizationEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Errorf("%s: decoding the unsigned entry: %v", v.Name, err)
		return
	}

	// Source-account vectors have no preimage, no payload, no signature.
	// AuthorizeEntry is still safe to call on them: it returns the entry
	// unchanged.
	isSourceAccount := entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount

	if !isSourceAccount {
		pre, err := Preimage(entry, v.ValidUntilLedger, v.NetworkPassphrase)
		if err != nil {
			t.Errorf("%s: Preimage: %v", v.Name, err)
			return
		}
		got, err := Payload(pre)
		if err != nil {
			t.Errorf("%s: Payload: %v", v.Name, err)
			return
		}
		if hex.EncodeToString(got[:]) != v.PayloadHex {
			t.Errorf("%s: concurrent payload drift:\n got %s\nwant %s", v.Name, hex.EncodeToString(got[:]), v.PayloadHex)
			return
		}
	}

	info, err := Inspect(entry)
	if err != nil {
		t.Errorf("%s: Inspect: %v", v.Name, err)
		return
	}
	// Render paths read the inspected info and the entry; they must not
	// panic under concurrent use.
	if _, err := InvocationTreeASCII(entry.RootInvocation); err != nil {
		t.Errorf("%s: InvocationTreeASCII: %v", v.Name, err)
		return
	}
	_ = DelegateTreeASCII(info)

	cfg := DefaultRiskConfig()
	cfg.CurrentLedger = v.ValidUntilLedger
	if _, err := Analyze(entry, &cfg); err != nil {
		t.Errorf("%s: Analyze: %v", v.Name, err)
		return
	}

	// AuthorizeEntry drives the deep-copy path in internal/xdrcopy, which is
	// the main place the library keeps buffer state across calls (sync.Pool).
	// Only replay steps that single-key AuthorizeEntry can reproduce, which
	// excludes the multisig vector (it is proved by the golden suite) and
	// delegate chains that need multiple signers wired by the suite.
	if isSourceAccount || len(v.Steps) == 0 {
		return
	}
	// Only run full-replay equality on single-step single-key vectors; the
	// rest of the vector matrix is covered by TestGoldenVectors. The point of
	// this test is concurrency, not re-running the signature suite.
	if len(v.Steps) != 1 || v.Steps[0].Multisig != nil {
		return
	}
	step := v.Steps[0]
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(step.SignerLabel)))
	if err != nil {
		t.Errorf("%s: deriving keypair for %q: %v", v.Name, step.SignerLabel, err)
		return
	}
	signer := NewEd25519Signer(kp)
	opts := []AuthorizeOption{}
	if step.ForAddress != nil {
		opts = append(opts, ForAddress(*step.ForAddress))
	}
	signed, err := AuthorizeEntry(context.Background(), entry, signer, v.ValidUntilLedger, v.NetworkPassphrase, opts...)
	if err != nil {
		t.Errorf("%s: AuthorizeEntry: %v", v.Name, err)
		return
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Errorf("%s: MarshalBinary: %v", v.Name, err)
		return
	}
	if base64.StdEncoding.EncodeToString(raw) != v.SignedEntryXDR {
		t.Errorf("%s: concurrent AuthorizeEntry drift", v.Name)
	}
}
