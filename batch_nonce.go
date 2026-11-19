package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// nonceKey is the composite key used to detect a nonce collision: an address
// and a nonce together uniquely identify a credential node's replay-protection
// token for that address. Two entries carrying the same (address, nonce) pair
// would each consume the same on-chain ledger entry, so the second is rejected
// by verify_and_consume_nonce (rs-soroban-env soroban-env-host/src/auth.rs)
// after fees are paid.
type nonceKey struct {
	address string
	nonce   int64
}

// CheckBatchNonces reports whether any two address entries in a batch share
// both an address and a nonce.
//
// Two entries for the same address with different nonces are distinct ledger
// entries and do not collide. Two entries for different addresses with the same
// nonce also do not collide, because the host keys the nonce ledger entry on
// (address, nonce). Only an identical (address, nonce) pair in two entries
// for the same address is a problem.
//
// Source-account entries carry no nonce and are skipped. The check runs in
// entry order and reports the first collision found, naming the address, both
// entry indices and the nonce so the caller can fix the right entry.
//
// This is an independent check: it does not sign or validate anything. Callers
// assembling a batch from several sources can call it before passing the batch
// to AuthorizeAll. AuthorizeAll calls it automatically before any signer runs,
// so a hardware wallet is never asked to approve a batch that cannot land.
func CheckBatchNonces(entries []xdr.SorobanAuthorizationEntry) error {
	// seen maps (address, nonce) → first entry index where it appeared.
	seen := make(map[nonceKey]int, len(entries))

	for i, entry := range entries {
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			continue
		}

		arm, err := GetArmBehavior(entry.Credentials)
		if err != nil {
			// Unsupported arm — AuthorizeAll will reject it; skip here.
			continue
		}

		address, err := arm.GetAddress(entry.Credentials)
		if err != nil {
			continue
		}

		nonce := arm.GetNonce(entry.Credentials)
		key := nonceKey{address: address, nonce: nonce}

		if first, exists := seen[key]; exists {
			return fmt.Errorf("soroauth: check batch nonces: entries %d and %d for address %s: %w",
				first, i, address, &NonceDuplicateError{
					Address:     address,
					FirstIndex:  first,
					SecondIndex: i,
					Nonce:       nonce,
				})
		}
		seen[key] = i
	}
	return nil
}
