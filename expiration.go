package soroauth

import (
	"fmt"
	"math"

	"github.com/stellar/go-stellar-sdk/xdr"
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

// EntryValidity is the result of CheckExpiration.
type EntryValidity struct {
	// Valid is whether the entry is accepted at currentLedger. The host's
	// rule is inclusive: an entry is valid when currentLedger <= ExpirationLedger
	// (verify_and_consume_nonce rejects with "signature has expired" only
	// when ledger_seq > *live_until_ledger; rs-soroban-env
	// soroban-env-host/src/auth.rs).
	Valid bool `json:"valid"`

	// RemainingLedgers is the number of ledgers the entry is still accepted
	// in, including currentLedger itself when valid. It is zero when expired.
	RemainingLedgers uint32 `json:"remaining_ledgers"`

	// ExpirationLedger is the SignatureExpirationLedger stored on the entry.
	// For the delegates arm, this is the top-level expiration, which governs
	// every delegate node — every node signs the same payload, and that
	// payload contains the expiration.
	ExpirationLedger uint32 `json:"expiration_ledger"`
}

// CheckExpiration reports whether entry is still valid at currentLedger and
// how many ledgers remain.
//
// The validity check implements the host's inclusive bound: the entry is valid
// when currentLedger <= SignatureExpirationLedger. The remaining-ledger count
// includes currentLedger itself — an entry whose expiration equals
// currentLedger has 1 remaining ledger.
//
// For the delegates arm, the top-level expiration governs every node in the
// tree: every delegate signs the same payload, and the expiration is part of
// that payload. The returned ExpirationLedger is always the top-level value.
//
// Source-account entries carry no expiration — the transaction envelope's own
// signature covers them — so CheckExpiration returns an error wrapping
// ErrSourceAccountCredentials rather than a misleading validity report.
//
// This function does not cap the expiration against the network's
// max_live_until_ledger, because that setting cannot be known offline.
// Callers who need to enforce the network ceiling must read it from the
// network and compare it themselves.
func CheckExpiration(entry xdr.SorobanAuthorizationEntry, currentLedger uint32) (EntryValidity, error) {
	creds, err := addressCredentials(entry.Credentials)
	if err != nil {
		return EntryValidity{}, fmt.Errorf("soroauth: check expiration: %w", err)
	}
	exp := uint32(creds.SignatureExpirationLedger)

	valid := currentLedger <= exp
	var remaining uint32
	if valid {
		remaining = exp - currentLedger + 1
	}
	return EntryValidity{
		Valid:            valid,
		RemainingLedgers: remaining,
		ExpirationLedger: exp,
	}, nil
}

// IsExpired reports whether entry has expired at currentLedger.
//
// It is a convenience wrapper around CheckExpiration for callers who only need
// the boolean. Source-account entries return an error wrapping
// ErrSourceAccountCredentials.
func IsExpired(entry xdr.SorobanAuthorizationEntry, currentLedger uint32) (bool, error) {
	v, err := CheckExpiration(entry, currentLedger)
	if err != nil {
		return false, err
	}
	return !v.Valid, nil
}

// WithinMargin reports whether entry has at least margin ledgers of validity
// remaining at currentLedger.
//
// An expired entry always returns false regardless of margin. A margin of 0 is
// equivalent to asking whether the entry is valid at all. A margin of 1 means
// the entry must still be accepted in the current ledger. Source-account
// entries return an error wrapping ErrSourceAccountCredentials.
func WithinMargin(entry xdr.SorobanAuthorizationEntry, currentLedger, margin uint32) (bool, error) {
	v, err := CheckExpiration(entry, currentLedger)
	if err != nil {
		return false, err
	}
	if !v.Valid {
		return false, nil
	}
	return v.RemainingLedgers >= margin, nil
}
