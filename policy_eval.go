package soroauth

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// AccountPolicy describes the signing requirements that an account contract
// enforces. EvaluateAccountPolicy checks whether an entry's current signatures
// satisfy the policy, without connecting to the network.
//
// This is an offline model the caller supplies. It evaluates a policy the
// caller describes and is not evidence about the deployed contract: a pass
// here does not prove the transaction will succeed on-chain, only that the
// entry matches the caller's understanding of what the account requires.
//
// Implementations are composable: combine RequiredSigner, ThresholdOfSigners,
// and AllSigners to match the fixture contracts' actual rules.
type AccountPolicy interface {
	// evaluate reports whether the set of signed addresses (a map from address
	// to true when signed) satisfies the policy. It appends any violations it
	// finds to violations and returns the extended slice.
	evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation
	// describe returns a human-readable label for this policy, used in
	// PolicyViolation.Requirement.
	describe() string
}

// PolicyViolation describes one unsatisfied requirement.
type PolicyViolation struct {
	// Requirement is a human-readable description of the requirement that
	// was not met, such as "required signer G..." or "threshold 2-of-3".
	Requirement string
	// Node is the address or policy node where the requirement was not met,
	// or "policy" when the violation does not anchor to a single address.
	Node string
}

// PolicyEvalResult is the outcome of EvaluateAccountPolicy.
type PolicyEvalResult struct {
	// Satisfied is true when every requirement in the policy is met by the
	// entry's current signatures.
	Satisfied bool
	// Violations lists each unsatisfied requirement. It is empty when
	// Satisfied is true.
	Violations []PolicyViolation
}

// EvaluateAccountPolicy checks whether the authorization entry's current
// signatures satisfy policy.
//
// It reads the credential nodes in the entry and treats each one as signed
// or unsigned based on whether it carries a signature (the same test Inspect
// uses). The result names every unsatisfied requirement and the node it
// anchors to.
//
// Source-account entries carry no credential nodes and are considered to
// satisfy any policy, because authentication comes from the transaction
// envelope itself.
//
// This is a structural check only: it does not verify that any signature is
// cryptographically correct. Use VerifyEntry for that.
func EvaluateAccountPolicy(entry xdr.SorobanAuthorizationEntry, policy AccountPolicy) PolicyEvalResult {
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return PolicyEvalResult{Satisfied: true}
	}

	signed := make(map[string]bool)
	var walkErr error
	for node, err := range CredentialNodes(entry) {
		if err != nil {
			walkErr = err
			break
		}
		signed[node.Address] = node.Signed
	}
	if walkErr != nil {
		return PolicyEvalResult{
			Satisfied: false,
			Violations: []PolicyViolation{{
				Requirement: "readable credential nodes",
				Node:        "entry",
			}},
		}
	}

	violations := policy.evaluate(signed, nil)
	return PolicyEvalResult{
		Satisfied:  len(violations) == 0,
		Violations: violations,
	}
}

// RequiredSigner returns a policy that is satisfied only when the given
// address is present in the entry and its credential node carries a signature.
func RequiredSigner(address string) AccountPolicy {
	return &requiredSignerPolicy{address: address}
}

type requiredSignerPolicy struct{ address string }

func (p *requiredSignerPolicy) describe() string {
	return "required signer " + p.address
}

func (p *requiredSignerPolicy) evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation {
	if !signed[p.address] {
		violations = append(violations, PolicyViolation{
			Requirement: p.describe(),
			Node:        p.address,
		})
	}
	return violations
}

// ThresholdOfSigners returns a policy that is satisfied when at least n of
// the given addresses are present and signed in the entry. n must be between
// 1 and len(addresses); values outside that range always produce a violation.
func ThresholdOfSigners(n int, addresses ...string) AccountPolicy {
	return &thresholdPolicy{n: n, addresses: addresses}
}

type thresholdPolicy struct {
	n         int
	addresses []string
}

func (p *thresholdPolicy) describe() string {
	return fmt.Sprintf("threshold %d-of-%d (%s)",
		p.n, len(p.addresses), strings.Join(p.addresses, ", "))
}

func (p *thresholdPolicy) evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation {
	if p.n < 1 || p.n > len(p.addresses) {
		violations = append(violations, PolicyViolation{
			Requirement: p.describe(),
			Node:        "policy",
		})
		return violations
	}
	count := 0
	for _, addr := range p.addresses {
		if signed[addr] {
			count++
		}
	}
	if count < p.n {
		violations = append(violations, PolicyViolation{
			Requirement: p.describe(),
			Node:        "policy",
		})
	}
	return violations
}

// AllSigners returns a policy that is satisfied only when every given address
// is present and signed in the entry. This is equivalent to
// ThresholdOfSigners(len(addresses), addresses...) but reads more naturally
// for accounts whose contract calls delegate_account_auth for every signer.
func AllSigners(addresses ...string) AccountPolicy {
	return &allSignersPolicy{addresses: addresses}
}

type allSignersPolicy struct{ addresses []string }

func (p *allSignersPolicy) describe() string {
	return fmt.Sprintf("all signers (%s)", strings.Join(p.addresses, ", "))
}

func (p *allSignersPolicy) evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation {
	for _, addr := range p.addresses {
		if !signed[addr] {
			violations = append(violations, PolicyViolation{
				Requirement: "required signer " + addr,
				Node:        addr,
			})
		}
	}
	return violations
}

// RequiresAll returns a policy that is satisfied only when every sub-policy is
// satisfied. Use it to combine requirements that all must hold at once.
func RequiresAll(policies ...AccountPolicy) AccountPolicy {
	return &allPolicy{policies: policies}
}

type allPolicy struct{ policies []AccountPolicy }

func (p *allPolicy) describe() string { return "all requirements" }

func (p *allPolicy) evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation {
	for _, sub := range p.policies {
		violations = sub.evaluate(signed, violations)
	}
	return violations
}

// RequiresAny returns a policy that is satisfied when at least one sub-policy
// is satisfied. It appends a single violation if no sub-policy passes.
func RequiresAny(policies ...AccountPolicy) AccountPolicy {
	return &anyPolicy{policies: policies}
}

type anyPolicy struct{ policies []AccountPolicy }

func (p *anyPolicy) describe() string { return "any requirement" }

func (p *anyPolicy) evaluate(signed map[string]bool, violations []PolicyViolation) []PolicyViolation {
	for _, sub := range p.policies {
		if len(sub.evaluate(signed, nil)) == 0 {
			return violations // at least one satisfied
		}
	}
	descriptions := make([]string, len(p.policies))
	for i, sub := range p.policies {
		descriptions[i] = sub.describe()
	}
	return append(violations, PolicyViolation{
		Requirement: fmt.Sprintf("any of: %s", strings.Join(descriptions, "; ")),
		Node:        "policy",
	})
}
