package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// MergeConflict describes two different non-void signatures found on the same
// credential node across the entries being merged.
type MergeConflict struct {
	Path string
	From string
	To   string
}

// MergeEntries combines two or more copies of the same authorization entry,
// each signed by a different party, into one fully signed entry.
//
// The entries must agree on every payload-affecting field: credential arm,
// address, nonce, expiration ledger and root invocation. Any disagreement is
// refused with ErrMergePayloadMismatch, naming the first field that differs,
// because a merged entry whose payload moved underneath an existing signature
// will fail on-chain (see docs/multi-party-signing.md, which explains why the
// expiration must be fixed before signing — this applies the same rule to the
// parallel case).
//
// For every credential node (the top-level node and, for the delegates arm,
// every delegate at every depth), the merge collects signatures across all
// copies. A node that is unsigned (Void or empty vector) on one copy and
// signed on another takes the signed value. Two different non-void signatures
// for the same node are refused with ErrMergeSignatureConflict: picking a
// winner silently would yield an entry that looks complete but fails on-chain.
// The operation is all-or-nothing: on any disagreement, no entry is returned.
//
// The returned entry is byte-identical to the same signatures applied
// sequentially to a single copy, because the merge writes each collected
// signature onto the matching node of a deep copy of the first entry without
// touching any payload field.
//
// Source-account entries are refused with ErrSourceAccountCredentials: they
// carry no signature payload of their own, so there is nothing to merge.
//
// MergeEntries does not modify any of the input entries.
func MergeEntries(entries ...xdr.SorobanAuthorizationEntry) (xdr.SorobanAuthorizationEntry, error) {
	var zero xdr.SorobanAuthorizationEntry

	if len(entries) < 2 {
		return zero, fmt.Errorf("soroauth: merge entries: need at least 2 entries, got %d", len(entries))
	}

	if entries[0].Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return zero, fmt.Errorf("soroauth: merge entries: %w", ErrSourceAccountCredentials)
	}

	base := entries[0]

	for i := 1; i < len(entries); i++ {
		diff, err := DiffEntries(base, entries[i])
		if err != nil {
			return zero, fmt.Errorf("soroauth: merge entries: comparing entry 0 with entry %d: %w", i, err)
		}
		if diff.PayloadChanged {
			change := firstPayloadChange(diff.Changes)
			return zero, fmt.Errorf(
				"soroauth: merge entries: entry %d differs from entry 0 at %s (%s -> %s): %w",
				i, change.Path, change.From, change.To, ErrMergePayloadMismatch)
		}
	}

	merged, err := xdrcopy.Copy(base)
	if err != nil {
		return zero, fmt.Errorf("soroauth: merge entries: copying base: %w", err)
	}

	// credentialNodes returns pointers into merged, so writing through them
	// fills the merged entry in place.
	mergedCreds, err := credentialNodes(&merged)
	if err != nil {
		return zero, fmt.Errorf("soroauth: merge entries: walking merged nodes: %w", err)
	}

	// diffNodes gives us paths but no mutable pointers; we pair them with
	// mergedCreds by index — both walk the tree in the same order (top-level
	// first, then delegates depth-first).
	mergedDiff, err := diffNodes(merged)
	if err != nil {
		return zero, fmt.Errorf("soroauth: merge entries: walking merged diff nodes: %w", err)
	}

	pathToIndex := make(map[string]int, len(mergedDiff))
	for i, n := range mergedDiff {
		pathToIndex[n.path] = i
	}

	for i := 1; i < len(entries); i++ {
		entryDiffNodes, err := diffNodes(entries[i])
		if err != nil {
			return zero, fmt.Errorf("soroauth: merge entries: walking entry %d nodes: %w", i, err)
		}

		for _, node := range entryDiffNodes {
			if !isSigned(node.signature) {
				continue
			}

			idx, ok := pathToIndex[node.path]
			if !ok {
				continue
			}
			existing := *mergedCreds[idx].signature

			if !isSigned(existing) {
				*mergedCreds[idx].signature = node.signature
				continue
			}

			same, err := xdrEqual(existing, node.signature)
			if err != nil {
				return zero, fmt.Errorf("soroauth: merge entries: comparing signatures: %w", err)
			}
			if !same {
				return zero, fmt.Errorf(
					"soroauth: merge entries: node %s: %s vs %s: %w",
					mergedDiff[idx].path,
					renderSignature(existing),
					renderSignature(node.signature),
					ErrMergeSignatureConflict)
			}
		}
	}

	return merged, nil
}

// firstPayloadChange returns the first payload-affecting change. There is
// always at least one when PayloadChanged is true.
func firstPayloadChange(changes []Change) Change {
	for _, c := range changes {
		if c.AffectsPayload {
			return c
		}
	}
	return Change{Path: "unknown"}
}
