package soroauth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// NodeState records the signing status of one credential node.
type NodeState struct {
	Address string `json:"address"`
	Signed  bool   `json:"signed"`
	Depth   int    `json:"depth"`
}

// SessionState is the serialisable representation of a coordination
// session. It can be persisted or sent across process boundaries
// without exposing any secret material — it carries only addresses
// and boolean signing flags.
type SessionState struct {
	CredentialType   string      `json:"credential_type"`
	TopLevel         string      `json:"top_level_address"`
	ValidUntilLedger uint32      `json:"valid_until_ledger"`
	Nodes            []NodeState `json:"nodes"`
	SignedCount      int         `json:"signed_count"`
	TotalNodes       int         `json:"total_nodes"`
}

// Coordinator tracks the signing progress of a delegate tree, reporting
// which parties have signed, what remains, and when the entry is complete.
//
// It is transport-agnostic: no HTTP, queue, or any other transport
// assumption is made. Callers provide the Signers and drive the signing
// loop themselves; the coordinator only tracks state and validates
// the shared-expiration rule that AuthorizeEntry enforces.
//
// The coordinator never holds a secret. SessionState contains only
// addresses and boolean flags, and a test asserts that no secret material
// can reach it (see TestCoordinatorStateContainsNoSecrets).
type Coordinator struct {
	entry             xdr.SorobanAuthorizationEntry
	validUntilLedger  uint32
	networkPassphrase string
	nodes             []trackedNode
	signedMap         map[string]bool // encoded address -> signed
}

// trackedNode is an internal representation of a delegate node with
// its depth in the tree.
type trackedNode struct {
	node    xdr.SorobanDelegateSignature
	encoded []byte
	depth   int
}

// NewCoordinator creates a coordinator for entry, which must be a
// delegates-arm entry. The validUntilLedger and networkPassphrase are
// stored so the coordinator can validate the shared-expiration rule
// before each signing call.
//
// Returns ErrUnsupportedCredentials if entry is not a delegates-arm
// entry, or ErrInvalidExpiration if validUntilLedger is zero.
func NewCoordinator(entry xdr.SorobanAuthorizationEntry, validUntilLedger uint32, networkPassphrase string) (*Coordinator, error) {
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		return nil, fmt.Errorf("soroauth: new coordinator: %w", ErrUnsupportedCredentials)
	}
	if validUntilLedger == 0 {
		return nil, fmt.Errorf("soroauth: new coordinator: %w", ErrInvalidExpiration)
	}
	if entry.Credentials.AddressWithDelegates == nil {
		return nil, fmt.Errorf("soroauth: new coordinator: address_with_delegates credentials arm is empty: %w", ErrUnsupportedCredentials)
	}

	c := &Coordinator{
		entry:             entry,
		validUntilLedger:  validUntilLedger,
		networkPassphrase: networkPassphrase,
		signedMap:         make(map[string]bool),
	}

	if err := c.buildNodes(); err != nil {
		return nil, fmt.Errorf("soroauth: new coordinator: %w", err)
	}

	return c, nil
}

// buildNodes flattens the delegate tree into tracked nodes with depth info.
func (c *Coordinator) buildNodes() error {
	c.nodes = c.flattenDelegates(c.entry.Credentials.AddressWithDelegates.Delegates, 0)
	for _, n := range c.nodes {
		c.signedMap[string(n.encoded)] = false
	}
	return nil
}

// flattenDelegates recursively collects delegate nodes with their depth.
func (c *Coordinator) flattenDelegates(nodes []xdr.SorobanDelegateSignature, depth int) []trackedNode {
	var out []trackedNode
	for i := range nodes {
		encoded, err := addressBytes(nodes[i].Address)
		if err != nil {
			continue
		}
		out = append(out, trackedNode{
			node:    nodes[i],
			encoded: encoded,
			depth:   depth,
		})
		out = append(out, c.flattenDelegates(nodes[i].NestedDelegates, depth+1)...)
	}
	return out
}

// State returns the current session state. The result is serialisable
// and contains no secret material — only addresses and boolean flags.
//
// This is the key property for cross-process coordination: the state
// can be JSON-marshalled, stored, or sent over a transport, and the
// receiving party can use it to know what still needs signing without
// ever having access to a private key.
func (c *Coordinator) State() SessionState {
	nodeStates := make([]NodeState, 0, len(c.nodes))
	signedCount := 0
	for _, n := range c.nodes {
		address, _ := FormatAddress(n.node.Address)
		signed := c.signedMap[string(n.encoded)]
		if signed {
			signedCount++
		}
		nodeStates = append(nodeStates, NodeState{
			Address: address,
			Signed:  signed,
			Depth:   n.depth,
		})
	}

	// Sort nodes by address string for deterministic output.
	sort.Slice(nodeStates, func(i, j int) bool {
		return nodeStates[i].Address < nodeStates[j].Address
	})

	topAddress, _ := FormatAddress(c.entry.Credentials.AddressWithDelegates.AddressCredentials.Address)

	return SessionState{
		CredentialType:   "address_with_delegates",
		TopLevel:         topAddress,
		ValidUntilLedger: c.validUntilLedger,
		Nodes:            nodeStates,
		SignedCount:      signedCount,
		TotalNodes:       len(c.nodes),
	}
}

// IsComplete reports whether every node in the tree has been signed.
func (c *Coordinator) IsComplete() bool {
	for _, signed := range c.signedMap {
		if !signed {
			return false
		}
	}
	return len(c.nodes) > 0
}

// Remaining returns the addresses that have not yet signed, sorted
// by address ascending.
func (c *Coordinator) Remaining() []string {
	var out []string
	for _, n := range c.nodes {
		address, _ := FormatAddress(n.node.Address)
		if !c.signedMap[string(n.encoded)] {
			out = append(out, address)
		}
	}
	sort.Strings(out)
	return out
}

// Record records that the given signer has signed the node whose
// address matches target. It is a thin wrapper around AuthorizeEntry
// that also updates the coordinator's tracking state.
//
// The shared-expiration rule is enforced here: if any node has already
// been signed, the validUntilLedger must match what was previously
// committed to. This mirrors AuthorizeEntry's guard so the coordinator
// cannot be used to bypass it.
//
// ctx is checked and passed to AuthorizeEntry.
func (c *Coordinator) Record(ctx context.Context, target string, signer Signer) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("soroauth: coordinator record: %w", err)
	}

	signed, err := xdrcopy.Copy(c.entry)
	if err != nil {
		return fmt.Errorf("soroauth: coordinator record: %w", err)
	}

	existingCredentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		return fmt.Errorf("soroauth: coordinator record: %w", err)
	}

	stored := uint32(existingCredentials.SignatureExpirationLedger)
	if stored != c.validUntilLedger {
		for _, n := range c.nodes {
			if c.signedMap[string(n.encoded)] && stored != c.validUntilLedger {
				return fmt.Errorf("soroauth: coordinator record: the entry already carries signatures over expiration %d, "+
					"but %d was requested: %w",
					stored, c.validUntilLedger, ErrInvalidExpiration)
			}
		}
	}

	_, err = AuthorizeEntry(ctx, signed, signer, c.validUntilLedger, c.networkPassphrase, ForAddress(target))
	if err != nil {
		return fmt.Errorf("soroauth: coordinator record: %w", err)
	}

	targetEncoded, err := addressBytesFromStr(target)
	if err != nil {
		return fmt.Errorf("soroauth: coordinator record: %w", err)
	}
	c.signedMap[string(targetEncoded)] = true
	c.entry = signed

	return nil
}

// addressBytesFromStr is a helper to get encoded bytes from a string address.
func addressBytesFromStr(addr string) ([]byte, error) {
	parsed, err := ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	return addressBytes(parsed)
}

// MarshalState returns the session state as JSON, ready to be
// persisted or sent across process boundaries.
func (c *Coordinator) MarshalState() ([]byte, error) {
	return json.Marshal(c.State())
}

// UnmarshalState reconstructs a session state from previously marshalled
// data. This is used by a receiving party to know what still needs
// signing without holding any secret material.
func UnmarshalState(data []byte) (*SessionState, error) {
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("soroauth: unmarshal state: %w", err)
	}
	return &state, nil
}

// ValidateExpirationConsistency checks that every already-signed node
// in the entry uses the same expiration ledger as validUntilLedger.
// This is the shared-expiration rule surfaced from AuthorizeEntry.
func (c *Coordinator) ValidateExpirationConsistency() error {
	existingCredentials, err := addressCredentials(c.entry.Credentials)
	if err != nil {
		return err
	}
	stored := uint32(existingCredentials.SignatureExpirationLedger)
	if stored != c.validUntilLedger {
		for _, n := range c.nodes {
			if isSigned(n.node.Signature) && stored != c.validUntilLedger {
				return fmt.Errorf("soroauth: coordinator: expiration mismatch: %w", ErrInvalidExpiration)
			}
		}
	}
	return nil
}

// SignedCount returns the number of nodes that have been signed.
func (c *Coordinator) SignedCount() int {
	count := 0
	for _, v := range c.signedMap {
		if v {
			count++
		}
	}
	return count
}

// TotalCount returns the total number of nodes in the tree.
func (c *Coordinator) TotalCount() int { return len(c.nodes) }

// TopLevelAddress returns the top-level account address.
func (c *Coordinator) TopLevelAddress() (string, error) {
	if c.entry.Credentials.AddressWithDelegates == nil {
		return "", fmt.Errorf("soroauth: coordinator: not a delegates entry")
	}
	return FormatAddress(c.entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
}

// Entry returns a copy of the underlying entry, with signatures
// recorded so far.
func (c *Coordinator) Entry() (xdr.SorobanAuthorizationEntry, error) {
	return xdrcopy.Copy(c.entry)
}
