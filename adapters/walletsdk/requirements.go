package walletsdk

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Requirement is one authorization entry of an envelope, from the point of view
// of one wallet key.
type Requirement struct {
	// OperationIndex is the position of the invokeHostFunction operation the
	// entry came from, indexing the inner transaction's operations for a
	// fee-bump envelope. It is the index soroauth.EnvelopeEntries reports.
	OperationIndex int `json:"operation_index"`

	// EntryIndex is the position of the entry within that operation's auth
	// vector.
	EntryIndex int `json:"entry_index"`

	// EntryInfo is the entry's structure: credential arm, address, nonce,
	// expiration ledger, which nodes carry signatures, and the invocation
	// shape. It is structural only, exactly as soroauth.Inspect reports it.
	soroauth.EntryInfo

	// Wanted is true when the entry names the wallet's address at some
	// credential node, so this wallet is one of the signers it asks for.
	Wanted bool `json:"wanted"`

	// Signed is true when every node naming the wallet's address already
	// carries a signature. It is false for an entry that does not name the
	// address at all, so read it together with Wanted.
	Signed bool `json:"signed"`
}

// Requirements reports what an envelope asks of one address: one Requirement
// per authorization entry it carries, in operation order.
//
// A wallet's to-do list is the entries that are Wanted and not yet Signed, and
// the entries that are both are the ones VerifyEnvelope can check before
// submission. soroauth.Inspect reports the same structure without reference to
// a key; this is that information asked as the wallet's question.
//
// An envelope with no invokeHostFunction operation is refused with
// soroauth.ErrNoInvokeOperation, the same as soroauth.EnvelopeEntries.
func Requirements(env xdr.TransactionEnvelope, address string) ([]Requirement, error) {
	entries, err := soroauth.EnvelopeEntries(env)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: requirements: %w", err)
	}

	requirements := make([]Requirement, 0, len(entries))
	for _, located := range entries {
		info, err := soroauth.Inspect(located.Entry)
		if err != nil {
			return nil, fmt.Errorf("walletsdk: requirements: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}

		nodes, err := signatureNodes(located.Entry, address)
		if err != nil {
			return nil, fmt.Errorf("walletsdk: requirements: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}

		signed := len(nodes) > 0
		for _, node := range nodes {
			if node.Type == xdr.ScValTypeScvVoid {
				signed = false
			}
		}

		requirements = append(requirements, Requirement{
			OperationIndex: located.OperationIndex,
			EntryIndex:     located.EntryIndex,
			EntryInfo:      info,
			Wanted:         len(nodes) > 0,
			Signed:         signed,
		})
	}
	return requirements, nil
}
