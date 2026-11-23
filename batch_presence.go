package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// PresenceBatcher is an optional extension of [Signer] for hardware wallets
// and passkey signers that can batch several signing requests into one
// user-confirmation prompt.
//
// # What the user is confirming
//
// A PresenceBatcher MUST clearly state to the user how many distinct entries
// they are approving. One prompt for N entries must present N authorizations,
// not one. Collapsing them into a single "approve everything" prompt defeats
// the purpose of hardware presence entirely.
//
// # What is lost compared with per-entry prompts
//
// Per-entry signing lets the user read each authorization individually.
// Batching trades that granularity for fewer interruptions. Callers should
// offer a per-entry fallback for high-value operations.
//
// # Fallback
//
// Not every signer can batch. [AuthorizeBatch] checks for this interface only
// when [WithPresenceBatcher] is set. Signers that do not implement it are
// always called once per entry, so callers that mix signer types never need
// to handle the fallback themselves.
type PresenceBatcher interface {
	Signer
	// BatchSign presents all entries to the user at once and returns their
	// signatures in input order. The slice length must equal len(entries).
	//
	// All entries must share this signer's Address(); BatchSign must return
	// an error if any entry belongs to a different address, since different
	// addresses are different authorization principals.
	BatchSign(ctx context.Context, entries []BatchSignEntry) ([]xdr.ScVal, error)
}

// BatchSignEntry is one preimage-payload pair passed to [PresenceBatcher.BatchSign].
type BatchSignEntry struct {
	Preimage xdr.HashIdPreimage
	Payload  [32]byte
}

// WithPresenceBatcher enables batched user-presence confirmation.
//
// When this option is set and a signer in the batch implements [PresenceBatcher],
// [AuthorizeBatch] collects all entries matched by that signer and presents them
// in a single [PresenceBatcher.BatchSign] call instead of calling [Signer.Sign]
// once per entry.
//
// Entries whose signer does not implement [PresenceBatcher] are signed
// individually, as usual.
func WithPresenceBatcher() AuthorizeBatchOption {
	return func(c *batchConfig) {
		c.usePresenceBatcher = true
	}
}

// presenceBatch is the [WithPresenceBatcher] path for [AuthorizeBatch]. It
// groups entries by their matched [PresenceBatcher] signer, calls BatchSign
// once per such signer, then falls back to per-entry signing for everything
// else.
func presenceBatch(
	ctx context.Context,
	entries []xdr.SorobanAuthorizationEntry,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
) ([]xdr.SorobanAuthorizationEntry, error) {
	type pbGroup struct {
		batcher   PresenceBatcher
		bsEntries []BatchSignEntry
		entryIdxs []int
	}

	pbMap := map[string]*pbGroup{}
	pbOrder := []string{}
	individual := []int{}

	for i, entry := range entries {
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			individual = append(individual, i)
			continue
		}
		matched, _, err := signersForEntry(entry, signers)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize batch: entry %d: %w", i, err)
		}
		if len(matched) == 0 {
			creds, _ := addressCredentials(entry.Credentials)
			addr, _ := FormatAddress(creds.Address)
			return nil, fmt.Errorf("soroauth: authorize batch: %s: %w",
				addr, &MissingSignerError{Address: addr})
		}
		// Only a single-signer entry (non-delegate) can be batched.
		pb, ok := matched[0].(PresenceBatcher)
		if !ok || len(matched) > 1 {
			individual = append(individual, i)
			continue
		}
		preimage, err := Preimage(entry, validUntilLedger, networkPassphrase)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize batch: entry %d preimage: %w", i, err)
		}
		payload, err := Payload(preimage)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize batch: entry %d payload: %w", i, err)
		}
		addr := pb.Address()
		if _, seen := pbMap[addr]; !seen {
			pbMap[addr] = &pbGroup{batcher: pb}
			pbOrder = append(pbOrder, addr)
		}
		pbMap[addr].bsEntries = append(pbMap[addr].bsEntries, BatchSignEntry{
			Preimage: preimage,
			Payload:  payload,
		})
		pbMap[addr].entryIdxs = append(pbMap[addr].entryIdxs, i)
	}

	results := make([]xdr.SorobanAuthorizationEntry, len(entries))

	for _, addr := range pbOrder {
		group := pbMap[addr]
		sigs, err := group.batcher.BatchSign(ctx, group.bsEntries)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize batch: batcher %s: %w", addr, err)
		}
		if len(sigs) != len(group.bsEntries) {
			return nil, fmt.Errorf("soroauth: authorize batch: batcher %s returned %d signatures for %d entries",
				addr, len(sigs), len(group.bsEntries))
		}
		for j, idx := range group.entryIdxs {
			sig := sigs[j]
			// Use a precomputed signer so AuthorizeEntry handles deep-copying
			// and credential writing through its normal path.
			pre := &precomputedSigner{address: addr, sig: sig}
			signed, err := AuthorizeEntry(ctx, entries[idx], pre, validUntilLedger, networkPassphrase, ForAddress(addr))
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize batch: batcher %s entry %d: %w", addr, idx, err)
			}
			results[idx] = signed
		}
	}

	for _, i := range individual {
		signed, err := authorizeOne(ctx, entries[i], signers, validUntilLedger, networkPassphrase)
		if err != nil {
			return nil, err
		}
		results[i] = signed
	}

	return results, nil
}

// precomputedSigner is a Signer that returns a pre-computed ScVal signature.
// It is used by presenceBatch to route a BatchSign result through the existing
// AuthorizeEntry machinery without calling the actual device again.
type precomputedSigner struct {
	address string
	sig     xdr.ScVal
}

func (p *precomputedSigner) Address() string { return p.address }

func (p *precomputedSigner) Sign(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
	return p.sig, nil
}
