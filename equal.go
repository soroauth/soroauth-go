package soroauth

import (
	"bytes"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// Equal returns true if two SorobanAuthorizationEntry values are XDR byte-
// identical. The comparison is a flat binary comparison of the encoded XDR,
// so two entries that differ only in delegate order, nonce value, or expiration
// ledger are considered unequal even though they may authorize the same
// operation. This is intentionally a byte-equality check, not a semantic
// equivalence check.
//
// An encoding failure (e.g. an entry that cannot be marshalled) returns false.
// It is never wrapped in an error; callers should not treat a false result as
// a refusal or fault.
func Equal(a, b xdr.SorobanAuthorizationEntry) bool {
	ba, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	bb, err := b.MarshalBinary()
	if err != nil {
		return false
	}
	return bytesEqual(ba, bb)
}

// Clone returns a deep copy of entry that shares no memory with the input.
// The copy is produced by round-tripping through XDR encoding. The returned
// value is safe to mutate without affecting the original.
func Clone(entry xdr.SorobanAuthorizationEntry) (xdr.SorobanAuthorizationEntry, error) {
	copied, err := xdrcopy.Copy(entry)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: clone: %w", err)
	}
	return copied, nil
}

// bytesEqual returns true if two byte slices are equal.
func bytesEqual(a, b []byte) bool {
	return len(a) == len(b) && bytes.Equal(a, b)
}
