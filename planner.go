package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// DelegatePolicy describes one delegate in a declarative policy.
type DelegatePolicy struct {
	Address string           `json:"address"`
	Nested  []DelegatePolicy `json:"nested,omitempty"`
}

// SignerRegistration maps an address to a signer for validation
// against known registered signers.
type SignerRegistration struct {
	Address string
	Signer  Signer
}

// PlannedTree is the output of a policy build, ready to be
// wrapped with WithDelegates and signed.
type PlannedTree struct {
	Delegates        []Delegate
	ValidUntilLedger uint32
}

// Plan builds a correctly ordered, validated delegate tree from
// a declarative description.
//
// The policy is converted into Delegate descriptors, each level
// is sorted by address XDR bytes (the same order WithDelegates
// enforces), and duplicates within a level are rejected. The
// result always passes ValidateDelegateOrder.
//
// If registrations is provided, each delegate address is validated
// against the known registered signers. An address not found in
// registrations is reported as an error.
//
// The output of Plan can be described again by inspecting the
// resulting entry after wrapping (see the round-trip test).
func Plan(validUntilLedger uint32, policy []DelegatePolicy, registrations ...SignerRegistration) (PlannedTree, error) {
	if validUntilLedger == 0 {
		return PlannedTree{}, fmt.Errorf("soroauth: plan: %w", ErrInvalidExpiration)
	}

	// Build a registration lookup if registrations are provided.
	regMap := make(map[string]bool)
	for _, r := range registrations {
		if _, err := ParseAddress(r.Address); err != nil {
			return PlannedTree{}, fmt.Errorf("soroauth: plan: invalid registration %s: %w", r.Address, err)
		}
		regMap[r.Address] = true
	}

	delegates, err := buildDelegatePolicies(policy)
	if err != nil {
		return PlannedTree{}, err
	}

	// Validate against registered signers if registrations provided.
	if len(registrations) > 0 {
		for _, d := range delegates {
			if err := validateAgainstRegistrations(d, regMap); err != nil {
				return PlannedTree{}, err
			}
		}
	}

	// Sort and validate at each level. Depth starts at 1, matching the
	// top-level call in WithDelegates, so buildDelegateNodes' own
	// MaxDecodeDepth guard covers a policy that nests past the limit.
	nodes, err := buildDelegateNodes(delegates, 1)
	if err != nil {
		return PlannedTree{}, err
	}

	// Round-trip: build the tree and verify it passes ValidateDelegateOrder.
	testEntry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   xdr.ScAddress{}, // will be set properly
					Nonce:                     0,
					SignatureExpirationLedger: xdr.Uint32(validUntilLedger),
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: nodes,
			},
		},
	}
	if err := ValidateDelegateOrder(testEntry); err != nil {
		return PlannedTree{}, fmt.Errorf("soroauth: plan: output does not pass ValidateDelegateOrder: %w", err)
	}

	return PlannedTree{
		Delegates:        delegates,
		ValidUntilLedger: validUntilLedger,
	}, nil
}

// buildDelegatePolicies converts policy descriptions into Delegate
// descriptors, recursively.
func buildDelegatePolicies(policy []DelegatePolicy) ([]Delegate, error) {
	if len(policy) == 0 {
		return nil, nil
	}

	delegates := make([]Delegate, 0, len(policy))
	for _, p := range policy {
		d := Delegate{
			Address: p.Address,
			Nested:  nil,
		}
		if len(p.Nested) > 0 {
			nested, err := buildDelegatePolicies(p.Nested)
			if err != nil {
				return nil, err
			}
			d.Nested = nested
		}
		delegates = append(delegates, d)
	}
	return delegates, nil
}

// validateAgainstRegistrations checks that every delegate address
// appears in the registration map.
func validateAgainstRegistrations(d Delegate, regMap map[string]bool) error {
	if !regMap[d.Address] {
		return fmt.Errorf("soroauth: plan: %s is not a registered signer: %w", d.Address, ErrMissingSigner)
	}
	for _, child := range d.Nested {
		if err := validateAgainstRegistrations(child, regMap); err != nil {
			return err
		}
	}
	return nil
}

// Wrap converts the planned tree into a fully-formed delegates
// entry using WithDelegates.
func (p *PlannedTree) Wrap(entry xdr.SorobanAuthorizationEntry, topSignature *xdr.ScVal) (xdr.SorobanAuthorizationEntry, error) {
	return WithDelegates(entry, p.ValidUntilLedger, p.Delegates, topSignature)
}

// Describe returns a declarative description of the planned tree,
// satisfying the round-trip requirement: a built tree can be
// described again.
func (p *PlannedTree) Describe() []DelegatePolicy {
	return describeDelegates(p.Delegates)
}

// describeDelegates converts Delegate descriptors back into
// policy descriptions.
func describeDelegates(delegates []Delegate) []DelegatePolicy {
	if len(delegates) == 0 {
		return nil
	}
	policy := make([]DelegatePolicy, 0, len(delegates))
	for _, d := range delegates {
		pp := DelegatePolicy{
			Address: d.Address,
			Nested:  describeDelegates(d.Nested),
		}
		policy = append(policy, pp)
	}
	return policy
}
