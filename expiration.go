package soroauth

import (
	"fmt"
	"math"
)

// ExpirationAfter returns the expiration ledger that is ledgers ahead of
// latestLedger, for callers turning "valid for about an hour" into the absolute
// ledger number an entry must carry.
//
// The semantics of that number, both read from the host rather than inferred:
//
// It is inclusive. The host rejects only once the current ledger is past the
// stored value — verify_and_consume_nonce fails with "signature has expired"
// when `ledger_seq > *live_until_ledger` (rs-soroban-env
// soroban-env-host/src/auth.rs). So the expiration ledger itself is still
// valid, and a value of latestLedger+1 is good for one more ledger. The JS SDK
// doc comment describes the bound as exclusive; the host source is the
// authority.
//
// A worked example of that boundary. Suppose the RPC reports latestLedger
// 1000. Ledger 1000 has already closed, so a transaction built now is applied
// in ledger 1001 at the earliest:
//
//	call                          returns    accepted if applied in     rejected from
//	ExpirationAfter(1000, 1)      1001       ledger 1001                ledger 1002
//	ExpirationAfter(1000, 720)    1720       ledgers 1001 to 1720       ledger 1721
//	ExpirationAfter(1000, 0)      refused    never (1000 has closed)    -
//
// The returned ledger is the last one in which the entry is accepted, not the
// first one in which it is rejected.
//
// It has an upper bound this function cannot enforce. The host also rejects a
// value above the network's max_live_until_ledger, with "signature expiration
// is too late" (same function). That is a network setting, so it cannot be
// known offline and is deliberately not hard-coded here: a constant baked into
// this library would silently become wrong when the network changed it. Callers
// who need the real ceiling must read it from the network.
//
// ledgers must be at least 1. Zero would produce an expiration equal to
// latestLedger, which is already expired: the latest ledger an RPC reports has
// closed, so the earliest ledger a transaction carrying the entry can be
// applied in is latestLedger+1, and the host rejects it there. Zero is refused
// with ErrInvalidExpiration rather than quietly producing a signature that can
// never be accepted. An overflowing
// sum is refused for the same reason: wrapping would turn a long lifetime into
// an expiration in the past.
func ExpirationAfter(latestLedger, ledgers uint32) (uint32, error) {
	if ledgers == 0 {
		return 0, fmt.Errorf(
			"soroauth: expiration after: ledgers must be at least 1: %w", ErrInvalidExpiration)
	}
	if latestLedger > math.MaxUint32-ledgers {
		return 0, fmt.Errorf(
			"soroauth: expiration after: %d + %d overflows a ledger sequence: %w",
			latestLedger, ledgers, ErrInvalidExpiration)
	}
	return latestLedger + ledgers, nil
}
