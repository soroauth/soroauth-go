package soroauth

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ErrRateLimited is returned when the rate limiter refuses a signing request
// because the rate limit has been reached. It is a distinct error a caller
// can match on with errors.Is, not a generic failure.
var ErrRateLimited = errors.New("signing rate limit exceeded")

// RateLimitMode determines whether the limiter blocks until a token is
// available or refuses immediately.
type RateLimitMode int

const (
	// RateLimitBlock waits for a token to become available, honouring context
	// cancellation and deadline while waiting.
	RateLimitBlock RateLimitMode = iota
	// RateLimitRefuse refuses immediately with ErrRateLimited when no token
	// is available.
	RateLimitRefuse
)

// RateLimitConfig configures the rate-limited signer wrapper.
type RateLimitConfig struct {
	// Rate is the maximum number of signing operations per Interval.
	Rate int
	// Interval is the window over which Rate is measured.
	Interval time.Duration
	// Mode controls whether the limiter blocks or refuses when the rate is
	// exceeded. RateLimitRefuse is the recommended default for a signing
	// path, because waiting silently is the wrong default: a caller that
	// does not expect a signing call to block may be better served by an
	// explicit refusal it can handle.
	Mode RateLimitMode
}

// WithRateLimit wraps a Signer with a rate limiter. The limiter uses a
// token bucket refilled at a fixed interval.
//
// The recommended order when composing with WithRetry is:
//
//	WithRetry(WithRateLimit(signer, cfg), retryCfg)
//
// Rate-limiting inside retry means a transient failure does not burn through
// the quota on retries. The reverse order (rate-limiting outside retry) means
// each retry attempt counts against the limit, which is usually not what an
// operator wants.
func WithRateLimit(signer Signer, cfg RateLimitConfig) Signer {
	if cfg.Rate <= 0 {
		cfg.Rate = 1
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	return &rateLimitedSigner{
		inner:    signer,
		rate:     cfg.Rate,
		interval: cfg.Interval,
		mode:     cfg.Mode,
		tokens:   cfg.Rate,
		last:     time.Now(),
	}
}

type rateLimitedSigner struct {
	inner    Signer
	rate     int
	interval time.Duration
	mode     RateLimitMode

	mu     sync.Mutex
	tokens int
	last   time.Time
}

func (s *rateLimitedSigner) Address() string { return s.inner.Address() }

func (s *rateLimitedSigner) IsDeterministic() bool {
	if c, ok := s.inner.(SignerCapabilities); ok {
		return c.IsDeterministic()
	}
	return false
}

func (s *rateLimitedSigner) IsInteractive() bool {
	if c, ok := s.inner.(SignerCapabilities); ok {
		return c.IsInteractive()
	}
	return true
}

func (s *rateLimitedSigner) IsRemote() bool {
	if c, ok := s.inner.(SignerCapabilities); ok {
		return c.IsRemote()
	}
	return false
}

func (s *rateLimitedSigner) SupportsBatchedPresence() bool {
	if c, ok := s.inner.(SignerCapabilities); ok {
		return c.SupportsBatchedPresence()
	}
	return false
}

func (s *rateLimitedSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: rate-limited sign: %w", err)
	}

	if err := s.acquire(ctx); err != nil {
		return xdr.ScVal{}, err
	}

	return s.inner.Sign(ctx, preimage, payload)
}

// refill adds tokens based on elapsed time since last refill.
// Must be called with s.mu held.
func (s *rateLimitedSigner) refill() {
	now := time.Now()
	elapsed := now.Sub(s.last)
	if elapsed <= 0 {
		return
	}
	newTokens := int(elapsed/s.interval) * s.rate
	if newTokens > 0 {
		s.tokens += newTokens
		if s.tokens > s.rate {
			s.tokens = s.rate
		}
		s.last = now
	}
}

// acquire tries to take one token. In refuse mode it fails immediately
// if none is available. In block mode it waits, honouring ctx.
func (s *rateLimitedSigner) acquire(ctx context.Context) error {
	s.mu.Lock()
	s.refill()
	if s.tokens > 0 {
		s.tokens--
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if s.mode == RateLimitRefuse {
		return fmt.Errorf("soroauth: rate-limited sign: %w", ErrRateLimited)
	}

	// Block mode: wait for a token with jitter.
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("soroauth: rate-limited sign: %w", err)
		}

		waitDur := s.interval / time.Duration(s.rate)
		jitter := cryptoRandDuration(waitDur / 10)
		waitDur += jitter

		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return fmt.Errorf("soroauth: rate-limited sign: %w", ctx.Err())
		case <-timer.C:
		}

		s.mu.Lock()
		s.refill()
		if s.tokens > 0 {
			s.tokens--
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
	}
}

// cryptoRandDuration returns a random duration in [0, max) using crypto/rand.
func cryptoRandDuration(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0
	}
	n := binary.LittleEndian.Uint64(buf[:])
	return time.Duration(n % uint64(max))
}
