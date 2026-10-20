package soroauth

import (
	"context"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// CachedSigner wraps any Signer whose Address() requires a remote call or expensive
// computation, caching the resolved address to avoid repeated network round-trips
// during delegate tree walks or multi-node signing flows.
//
// # Lifetime and Invalidation
//
// The cached address is retained until either:
//  1. The configured TTL (Time-To-Live) expires (if non-zero).
//  2. Explicit invalidation is triggered via Invalidate().
//
// # Key Rotation Warning
//
// If the underlying signer's address changes due to a key rotation while the cache
// is active, the cached address will become stale until the TTL expires or Invalidate()
// is called. If key rotation cannot be monitored or notified, callers should either set
// a short TTL or explicitly call Invalidate() upon rotation events.
type CachedSigner struct {
	signer Signer
	ttl    time.Duration

	mu        sync.Mutex
	address   string
	err       error
	fetchedAt time.Time
}

// NewCachedSigner returns a concurrency-safe caching wrapper around the given Signer.
// A ttl of 0 means the address is cached indefinitely until explicitly invalidated.
func NewCachedSigner(signer Signer, ttl time.Duration) *CachedSigner {
	return &CachedSigner{
		signer: signer,
		ttl:    ttl,
	}
}

// Address returns the cached address if valid; otherwise, it calls the underlying
// signer's Address() method, caches the result, and returns it.
func (c *CachedSigner) Address() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.address != "" || c.err != nil {
		if c.ttl <= 0 || now.Sub(c.fetchedAt) < c.ttl {
			return c.address
		}
	}

	c.address = c.signer.Address()
	c.fetchedAt = now
	return c.address
}

// Invalidate clears the cached address, ensuring the next call to Address()
// re-fetches from the underlying signer. This must be invoked upon key rotation.
func (c *CachedSigner) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.address = ""
	c.err = nil
	c.fetchedAt = time.Time{}
}

// Sign delegates directly to the underlying Signer.
func (c *CachedSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	return c.signer.Sign(ctx, preimage, payload)
}
