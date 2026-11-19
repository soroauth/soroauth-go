package soroauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithRateLimit_RefuseMode(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	inner := NewEd25519Signer(kp)

	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     1,
		Interval: time.Second,
		Mode:     RateLimitRefuse,
	})

	// First call should succeed.
	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		limited,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	// Second call should be rate-limited.
	_, err = AuthorizeEntry(
		context.Background(),
		entry,
		limited,
		101,
		network.TestNetworkPassphrase,
		AllowResign(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited), "expected ErrRateLimited, got: %v", err)
}

func TestWithRateLimit_BlockMode_ContextCancellation(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	inner := NewEd25519Signer(kp)

	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     1,
		Interval: 10 * time.Second,
		Mode:     RateLimitBlock,
	})

	// Exhaust the token.
	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		limited,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	// Block mode with a cancelled context.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = AuthorizeEntry(
		ctx,
		entry,
		limited,
		101,
		network.TestNetworkPassphrase,
		AllowResign(),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "expected context deadline, got: %v", err)
}

func TestWithRateLimit_ConcurrencySafe(t *testing.T) {
	kp := keypair.MustRandom()
	inner := NewEd25519Signer(kp)

	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     100,
		Interval: time.Second,
		Mode:     RateLimitRefuse,
	})

	var wg sync.WaitGroup
	var succeeded atomic.Int32
	var rateLimited atomic.Int32

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := testAddressEntry(t, kp.Address())
			_, err := AuthorizeEntry(
				context.Background(),
				entry,
				limited,
				100,
				network.TestNetworkPassphrase,
			)
			if err == nil {
				succeeded.Add(1)
			} else if errors.Is(err, ErrRateLimited) {
				rateLimited.Add(1)
			}
		}()
	}

	wg.Wait()

	assert.True(t, succeeded.Load() > 0, "at least some calls should succeed")
	assert.True(t, rateLimited.Load() > 0, "at least some calls should be rate-limited")
}

func TestWithRateLimit_DistinctError(t *testing.T) {
	kp := keypair.MustRandom()
	inner := NewEd25519Signer(kp)

	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     1,
		Interval: time.Hour,
		Mode:     RateLimitRefuse,
	})

	entry := testAddressEntry(t, kp.Address())

	// Exhaust the token.
	_, _ = AuthorizeEntry(context.Background(), entry, limited, 100, network.TestNetworkPassphrase)

	_, err := AuthorizeEntry(context.Background(), entry, limited, 101, network.TestNetworkPassphrase, AllowResign())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRateLimited))
	assert.False(t, errors.Is(err, ErrMissingSigner))
	assert.False(t, errors.Is(err, ErrSignatureMismatch))
}

func TestWithRateLimit_BlockMode_WrappedSignerNotCalled(t *testing.T) {
	kp := keypair.MustRandom()

	var called atomic.Bool
	inner := SignerFunc(kp.Address(), func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		called.Store(true)
		return xdr.ScVal{}, nil
	})

	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     1,
		Interval: 10 * time.Second,
		Mode:     RateLimitBlock,
	})

	entry := testAddressEntry(t, kp.Address())

	// Exhaust the token.
	_, _ = AuthorizeEntry(context.Background(), entry, limited, 100, network.TestNetworkPassphrase)
	called.Store(false)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _ = AuthorizeEntry(ctx, entry, limited, 101, network.TestNetworkPassphrase, AllowResign())

	assert.False(t, called.Load(), "wrapped signer should not have been called when rate-limited and context cancelled")
}

func TestWithRateLimit_ComposesWithRetry(t *testing.T) {
	kp := keypair.MustRandom()
	inner := NewEd25519Signer(kp)

	// Rate-limit inside retry (recommended order).
	limited := WithRateLimit(inner, RateLimitConfig{
		Rate:     10,
		Interval: time.Second,
		Mode:     RateLimitRefuse,
	})
	retried := WithRetry(limited, RetryConfig{
		Attempts:       3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})

	entry := testAddressEntry(t, kp.Address())

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		retried,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	// Reverse order also works.
	retried2 := WithRetry(inner, RetryConfig{
		Attempts:       3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})
	limited2 := WithRateLimit(retried2, RateLimitConfig{
		Rate:     10,
		Interval: time.Second,
		Mode:     RateLimitRefuse,
	})

	_, err = AuthorizeEntry(
		context.Background(),
		entry,
		limited2,
		101,
		network.TestNetworkPassphrase,
		AllowResign(),
	)
	require.NoError(t, err)
}
