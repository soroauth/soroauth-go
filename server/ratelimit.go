package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

// callerLimiter bounds the request rate of one caller. Each caller gets its own
// token bucket, so a single noisy client cannot spend another client's quota.
//
// The limit exists for availability, not correctness: decoding an authorization
// entry is unbounded work from the caller's point of view, and a large delegate
// tree costs real CPU. Shedding happens before the body is read and before the
// entry is decoded, which is the only place a rate limit protects the expensive
// part. decodepolicy bounds what a single request may cost; this bounds how many
// such requests one caller may start.
//
// Tokens refill in whole steps rather than continuously. That keeps the
// arithmetic integer-only and makes the Retry-After hint exact: a refused caller
// waits until the next refill, never a value the limiter has to round up from a
// floating-point bucket.
type callerLimiter struct {
	// rate is the number of tokens added per interval.
	rate int
	// burst is the maximum bucket depth: the number of requests a caller may
	// make back-to-back after an idle period.
	burst int
	// interval is the refill window, one second in production.
	interval time.Duration
	// now is injectable so the tests do not sleep through refill windows.
	now func() time.Time

	mu        sync.Mutex
	buckets   map[string]*callerBucket
	lastSweep time.Time
	// idleFor is how long an untouched bucket is kept. Without it, a caller
	// that connects once from a new address would leave an entry forever.
	idleFor time.Duration
}

// callerBucket is one caller's remaining tokens and the start of its current
// refill window.
type callerBucket struct {
	tokens int
	last   time.Time
}

// newCallerLimiter builds a limiter. The caller must pass positive values;
// loadConfig refuses anything else, and newServer supplies the defaults for a
// config built directly by a test.
func newCallerLimiter(rate, burst int, interval time.Duration) *callerLimiter {
	if rate <= 0 {
		rate = defaultRateLimitPerSecond
	}
	if burst <= 0 {
		burst = defaultRateLimitBurst
	}
	if burst < rate {
		burst = rate
	}
	if interval <= 0 {
		interval = time.Second
	}
	now := time.Now
	return &callerLimiter{
		rate:     rate,
		burst:    burst,
		interval: interval,
		now:      now,
		buckets:  make(map[string]*callerBucket),
		idleFor:  10 * interval,
	}
}

// allow takes one token for key, or reports how long until the next refill. A
// true result means the request may proceed; a false result is a shed request
// with a retry hint the caller can put in Retry-After.
func (l *callerLimiter) allow(key string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now)

	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &callerBucket{tokens: l.burst, last: now}
		l.buckets[key] = bucket
	}

	// Advance the window by whole intervals. A partial interval is carried
	// forward in `last`, so repeated requests do not reset the refill clock.
	if elapsed := now.Sub(bucket.last); elapsed >= l.interval {
		steps := int(elapsed / l.interval)
		bucket.tokens += steps * l.rate
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		bucket.last = bucket.last.Add(time.Duration(steps) * l.interval)
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true, 0
	}
	return false, bucket.last.Add(l.interval).Sub(now)
}

// sweep drops buckets that have been idle longer than idleFor. It runs at most
// once a minute, so the common path is a map lookup rather than a full walk.
func (l *callerLimiter) sweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for key, bucket := range l.buckets {
		if now.Sub(bucket.last) > l.idleFor {
			delete(l.buckets, key)
		}
	}
}

// callerIdentity names the caller a request belongs to. A configured bearer
// token is an identity: it is the credential the caller proved, and it is
// hashed before use so the token itself never becomes a map key or a log field.
// With no token configured (loopback only), the peer address is the identity
// available; the host is used rather than host:port so a caller cannot reset its
// quota simply by opening another connection.
func callerIdentity(r *http.Request, token string) string {
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		return "token:" + hex.EncodeToString(sum[:8])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return "addr:" + host
}

// retryAfterSeconds turns a limiter wait into the integer seconds an HTTP
// Retry-After header carries, rounding up and never advertising zero.
func retryAfterSeconds(wait time.Duration) int {
	if wait <= 0 {
		return 1
	}
	seconds := int((wait + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
