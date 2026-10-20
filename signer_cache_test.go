package soroauth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingSigner struct {
	addr        string
	lookupCount atomic.Int64
}

func (s *countingSigner) Address() string {
	s.lookupCount.Add(1)
	return s.addr
}

func (s *countingSigner) Sign(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
	return xdr.ScVal{}, nil
}

func TestCachedSigner_OncePerTreeWalk(t *testing.T) {
	base := &countingSigner{addr: "GABBCDEFGHIJKLMNOPQRSTUVWXYZ"}
	cached := NewCachedSigner(base, 0)

	// Simulate a multi-node tree walk or multiple signing calls calling Address()
	for i := 0; i < 50; i++ {
		addr := cached.Address()
		assert.Equal(t, "GABBCDEFGHIJKLMNOPQRSTUVWXYZ", addr)
	}

	assert.Equal(t, int64(1), base.lookupCount.Load(), "underlying Address() should be called exactly once")
}

func TestCachedSigner_RaceAndTTL(t *testing.T) {
	base := &countingSigner{addr: "GABBCDEFGHIJKLMNOPQRSTUVWXYZ"}
	cached := NewCachedSigner(base, 50*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cached.Address()
			_, _ = cached.Sign(context.Background(), xdr.HashIdPreimage{}, [32]byte{})
		}()
	}
	wg.Wait()

	require.GreaterOrEqual(t, base.lookupCount.Load(), int64(1))

	// Test explicit invalidation
	cached.Invalidate()
	_ = cached.Address()
	require.GreaterOrEqual(t, base.lookupCount.Load(), int64(2))
}
