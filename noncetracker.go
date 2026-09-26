package soroauth

import (
	"context"
	"fmt"
	"sync"
)

// NonceTracker is implemented by anything that remembers which nonces have
// already been reserved for which address, so a caller signing concurrently
// can refuse to hand out the same nonce twice before a signature is ever
// built.
//
// The nonce is what makes a signature single-use (see newNonce in
// invocation.go), and it is the host — not this library — that enforces
// that on-chain: rs-soroban-env's verify_and_consume_nonce
// (soroban-env-host/src/auth.rs) rejects a repeat at apply time, after the
// transaction has already paid its fee. A NonceTracker is a local,
// best-effort aid that catches a collision earlier, within whatever this
// tracker's own store has seen. It cannot know about a nonce consumed
// elsewhere: by another process, by a NonceTracker backed by a different
// store, or by a transaction that reserved a nonce here and then was never
// submitted. Passing Reserve never proves a nonce is valid on-chain; it only
// proves this tracker has not handed it out before. Callers who need a
// correctness guarantee, not a collision-avoidance aid, still have to rely
// on the host's own rejection.
//
// A NonceTracker is orthogonal to nonce generation: nothing here replaces
// newNonce's crypto/rand source, and AuthorizeInvocation does not use a
// NonceTracker automatically. A caller who wants both generates a nonce
// (with AuthorizeInvocation, or by calling crypto/rand directly) and then
// reserves it, retrying generation on ErrNonceAlreadyReserved if it must
// avoid a same-process collision.
//
// Implementations must be safe for concurrent use, since avoiding a race
// between two goroutines picking the same nonce is the entire point of the
// interface.
type NonceTracker interface {
	// Reserve records nonce as used for address in this tracker's store,
	// returning ErrNonceAlreadyReserved if it was already reserved for that
	// address. ctx lets a store-backed implementation (Redis, a database)
	// honour cancellation and deadlines on its own I/O; the in-memory
	// implementation checks only ctx.Err() up front, since it never blocks.
	Reserve(ctx context.Context, address string, nonce int64) error
}

// inMemoryNonceTracker is a NonceTracker backed by a process-local map,
// guarded by a mutex so Reserve is safe to call from multiple goroutines at
// once.
type inMemoryNonceTracker struct {
	mu       sync.Mutex
	reserved map[string]map[int64]struct{}
}

// NewInMemoryNonceTracker returns a NonceTracker backed by an in-process
// map.
//
// It remembers nothing across a process restart and shares nothing with any
// other NonceTracker instance, including another NewInMemoryNonceTracker
// call in the same process — two backends started this way track
// independent reservations. A caller who signs from more than one process,
// or who needs reservations to survive a restart, must back NonceTracker
// with a shared store (Redis, a database, …) instead; any type implementing
// the one-method NonceTracker interface works with the rest of this
// library the same way.
func NewInMemoryNonceTracker() NonceTracker {
	return &inMemoryNonceTracker{reserved: make(map[string]map[int64]struct{})}
}

// Reserve implements NonceTracker.
func (t *inMemoryNonceTracker) Reserve(ctx context.Context, address string, nonce int64) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("soroauth: nonce tracker reserve: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	nonces := t.reserved[address]
	if nonces == nil {
		nonces = make(map[int64]struct{})
		t.reserved[address] = nonces
	}
	if _, exists := nonces[nonce]; exists {
		return fmt.Errorf("soroauth: nonce tracker reserve: %s: %w", address,
			&NonceAlreadyReservedError{Address: address, Nonce: nonce})
	}
	nonces[nonce] = struct{}{}
	return nil
}
