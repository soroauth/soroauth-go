package soroauth

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ProtocolVerdict is the answer CheckProtocolCompatibility gives for one entry
// against one target protocol version.
//
// The middle two verdicts are deliberately distinct. "Rejected" means the
// protocol cannot carry the entry at all, which a caller can act on. "Accepted
// with different semantics" means the entry is structurally valid and would be
// accepted, but the host does something different with it than it does on an
// earlier protocol. That second case is the dangerous one: a transaction that
// applies cleanly on one network and not another, while every local check
// passes, is exactly what a mixed-version rollout produces.
type ProtocolVerdict string

const (
	// ProtocolVerdictAccepted means the entry's credential arm exists at the
	// target protocol and the host's rules for it are those that introduced
	// it.
	ProtocolVerdictAccepted ProtocolVerdict = "accepted"

	// ProtocolVerdictRejected means the target protocol predates the
	// credential arm the entry uses. The wire type does not exist there, so
	// the transaction cannot be decoded, let alone applied.
	ProtocolVerdictRejected ProtocolVerdict = "rejected"

	// ProtocolVerdictDifferentSemantics means the entry is accepted at the
	// target protocol, but the host resolves it differently than on a
	// protocol that predates the rule named in the finding.
	ProtocolVerdictDifferentSemantics ProtocolVerdict = "accepted_with_different_semantics"

	// ProtocolVerdictUnknown means no cited rule decides the question. It is
	// never collapsed into accepted: an unknown combination is reported as
	// unknown so a caller can refuse it, which is the fail-closed reading.
	ProtocolVerdictUnknown ProtocolVerdict = "unknown"
)

// The protocol sources this file cites. Every decided verdict carries one of
// these, and the finding's Reason quotes the sentence it relies on. An
// uncited claim about what a protocol version does is a guess, and a guess is
// not an acceptable basis for submitting a transaction.
const (
	cap4611Source = "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-11.md"
	cap7101Source = "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-01.md"
	cap7102Source = "https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-02.md"
)

// CompatibilityFinding is one rule applied to one part of the entry.
//
// Path locates the part in the entry using the XDR field names, in the same
// style DiffEntries uses: "credentials", "credentials.delegates[G…]",
// "rootInvocation.function.type". A delegate node is keyed by address, because
// the protocol sorts each delegate array by address and an index would shift.
type CompatibilityFinding struct {
	// Path is the part of the entry this finding is about.
	Path string `json:"path"`

	// Verdict is what the cited rule says about that part at the target
	// protocol.
	Verdict ProtocolVerdict `json:"verdict"`

	// Reason states the rule in words and quotes the sentence it comes from.
	Reason string `json:"reason"`

	// Source is the URL of the protocol document the rule is read from. It is
	// empty only for findings whose verdict is unknown, which by definition
	// have no source to cite.
	Source string `json:"source,omitempty"`
}

// CompatibilityReport is the result of CheckProtocolCompatibility.
//
// Verdict is the whole-entry answer and the field to switch on; Findings is
// the evidence, one entry per rule applied, in walk order: the credential arm
// first, then every delegate node at every depth, then the root invocation's
// function type. A rejected or unknown finding anywhere makes the whole entry
// rejected or unknown, because a transaction is refused if any part of it is.
type CompatibilityReport struct {
	// ProtocolVersion is the target version the entry was checked against.
	ProtocolVersion int `json:"protocol_version"`

	// CredentialType is the stable arm name, the same string Inspect reports,
	// or empty when the arm is not one this build knows.
	CredentialType string `json:"credential_type,omitempty"`

	// Verdict is the whole-entry answer: the worst finding wins, in the order
	// rejected, unknown, accepted-with-different-semantics, accepted.
	Verdict ProtocolVerdict `json:"verdict"`

	// Findings is every rule applied, each with its citation.
	Findings []CompatibilityFinding `json:"findings,omitempty"`

	// Summary is the one-line answer, verdict first.
	Summary string `json:"summary"`
}

// credentialArmName names an arm without consulting the behavior table, so a
// report can be produced for an arm value this build does not implement.
func credentialArmName(t xdr.SorobanCredentialsType) (string, bool) {
	switch t {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return CredentialTypeSourceAccount, true
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		return CredentialTypeAddress, true
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		return CredentialTypeAddressV2, true
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		return CredentialTypeAddressWithDelegates, true
	default:
		return "", false
	}
}

// armRule is the rule that governs one credential arm across protocol
// versions.
type armRule struct {
	reason string
	source string
}

// armRuleFor returns the rule for a known arm. The minimum version itself is
// read from ArmProtocolVersion rather than restated here, so there is one
// place that records it.
func armRuleFor(arm string) (armRule, bool) {
	switch arm {
	case CredentialTypeSourceAccount:
		return armRule{
			reason: "CAP-46-11 defines SOROBAN_CREDENTIALS_SOURCE_ACCOUNT and states \"Protocol version: 20\" in its preamble.",
			source: cap4611Source,
		}, true
	case CredentialTypeAddress:
		return armRule{
			reason: "CAP-46-11 defines SOROBAN_CREDENTIALS_ADDRESS and states \"Protocol version: 20\" in its preamble. CAP-71-02, \"No deprecation of SOROBAN_CREDENTIALS_ADDRESS\", keeps it valid: \"we keep the existing credential type and preimage type valid\".",
			source: cap7102Source,
		}, true
	case CredentialTypeAddressV2:
		return armRule{
			reason: "CAP-71-02 states \"Protocol version: 27\" in its preamble and \"Including it into a transaction before protocol 27 will invalidate the transaction.\"",
			source: cap7102Source,
		}, true
	case CredentialTypeAddressWithDelegates:
		return armRule{
			reason: "CAP-71-01 states \"Protocol version: 27\" in its preamble and \"The new credential type will also only be available starting from protocol 27, otherwise including it into transaction will invalidate the transaction.\"",
			source: cap7101Source,
		}, true
	default:
		return armRule{}, false
	}
}

// armVerdict applies the arm's rule at one protocol version.
func armVerdict(arm string, rule armRule, protocolVersion int) ProtocolVerdict {
	if protocolVersion < ArmProtocolVersion[arm] {
		return ProtocolVerdictRejected
	}
	// The one cross-version semantic change in this library's scope, and it is
	// narrow. A legacy SOROBAN_CREDENTIALS_ADDRESS entry stays accepted after
	// protocol 27 (CAP-71-02 above), but CAP-71-01's delegation algorithm
	// resolves delegates for it too: "For top level call, define
	// current_delegate_list as the value of delegates inside
	// SorobanAddressCredentialsWithDelegates in A's auth entry, or an empty
	// list if SorobanAddressCredentials is used." The observation channel for
	// that list, get_delegated_signers_for_current_auth_check, is declared
	// `min_supported_protocol: 27` in CAP-71-01's env.json diff. So the same
	// bytes mean the same authorization on both sides of 27, and additionally
	// expose an empty delegate list to __check_auth from 27 on.
	if arm == CredentialTypeAddress && protocolVersion >= 27 {
		return ProtocolVerdictDifferentSemantics
	}
	return ProtocolVerdictAccepted
}

// compatDelegateFindings walks a delegate tree and returns one finding per
// node, each inheriting the arm-level verdict, so a nested delegate is covered
// by a rule of its own rather than only by the top-level arm.
//
// The protocol's delegate rules are per array, at every level (CAP-71-01,
// "SorobanAddressCredentialsWithDelegates validation"), so the walk covers
// every level. depth bounds the recursion through the same limit Inspect
// uses, because the entry may have come from somewhere this library did not
// decode.
func compatDelegateFindings(nodes []xdr.SorobanDelegateSignature, prefix string, verdict ProtocolVerdict, reason, source string, depth int) ([]CompatibilityFinding, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return nil, err
	}
	var out []CompatibilityFinding
	for i := range nodes {
		address, err := FormatAddress(nodes[i].Address)
		if err != nil {
			return nil, err
		}
		path := fmt.Sprintf("%s[%s]", prefix, address)
		out = append(out, CompatibilityFinding{
			Path:    path,
			Verdict: verdict,
			Reason:  reason,
			Source:  source,
		})
		nested, err := compatDelegateFindings(nodes[i].NestedDelegates, path+".nested", verdict, reason, source, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, nested...)
	}
	return out, nil
}

// worstVerdict folds findings into the report's single verdict. Order of
// severity: rejected, unknown, accepted-with-different-semantics, accepted.
func worstVerdict(findings []CompatibilityFinding) ProtocolVerdict {
	verdict := ProtocolVerdictAccepted
	rank := func(v ProtocolVerdict) int {
		switch v {
		case ProtocolVerdictRejected:
			return 3
		case ProtocolVerdictUnknown:
			return 2
		case ProtocolVerdictDifferentSemantics:
			return 1
		default:
			return 0
		}
	}
	for _, finding := range findings {
		if rank(finding.Verdict) > rank(verdict) {
			verdict = finding.Verdict
		}
	}
	return verdict
}

// CheckProtocolCompatibility reports whether an entry would be accepted at a
// target Stellar protocol version, rejected there, or accepted with semantics
// that differ from an earlier protocol.
//
// Why this exists: an entry can be structurally valid on two protocol versions
// and mean something different on each, and nothing else in this library (or
// in the SDK) answers that question. Protocol 27 is exactly that kind of
// change: it added address-bound V2 credentials and delegated signers as new
// wire types rather than changing the legacy one (CAP-71-02, "No deprecation
// of SOROBAN_CREDENTIALS_ADDRESS"), so an operator rotating a deployment
// across versions has to know both which arms the target network can carry
// and which of them change meaning.
//
// Every decided finding cites the CAP sentence it rests on, and Reason quotes
// it. The minimum protocol per arm comes from ArmProtocolVersion, so this
// file does not keep a second copy of that fact.
//
// Unknown combinations are reported as ProtocolVerdictUnknown, never as
// accepted: an arm or function type this build does not implement, and a
// non-positive target version, are all unknown. The function returns an error
// only when the entry itself cannot be read (an unformattable delegate
// address, or a delegate tree nested past MaxDecodeDepth).
//
// What this deliberately does not do: it does not contact a network, so it
// cannot tell you which protocol the network you are about to submit to is
// running. It answers "if the target were protocol N", and the caller supplies
// N. It also does not decide whether the account's own __check_auth accepts
// the entry: that is contract policy, not protocol compatibility.
func CheckProtocolCompatibility(entry xdr.SorobanAuthorizationEntry, protocolVersion int) (CompatibilityReport, error) {
	report := CompatibilityReport{ProtocolVersion: protocolVersion}

	if protocolVersion <= 0 {
		report.Verdict = ProtocolVerdictUnknown
		report.Findings = []CompatibilityFinding{{
			Path:    "protocolVersion",
			Verdict: ProtocolVerdictUnknown,
			Reason:  "a target protocol version must be positive; there is no protocol to check against zero or a negative number",
		}}
		report.Summary = "unknown: no target protocol version was given"
		return report, nil
	}

	arm, known := credentialArmName(entry.Credentials.Type)
	if !known {
		report.Verdict = ProtocolVerdictUnknown
		report.Findings = []CompatibilityFinding{{
			Path:    "credentials.type",
			Verdict: ProtocolVerdictUnknown,
			Reason:  fmt.Sprintf("credentials type %d is not one of the four arms this build implements, so no protocol rule applies to it here", entry.Credentials.Type),
		}}
		report.Summary = fmt.Sprintf("unknown on protocol %d: unrecognised credentials type", protocolVersion)
		return report, nil
	}
	report.CredentialType = arm

	rule, ok := armRuleFor(arm)
	if !ok {
		// credentialArmName and armRuleFor cover the same set; this is the
		// fail-closed branch if one is ever extended without the other.
		report.Verdict = ProtocolVerdictUnknown
		report.Findings = []CompatibilityFinding{{
			Path:    "credentials",
			Verdict: ProtocolVerdictUnknown,
			Reason:  fmt.Sprintf("no protocol rule is recorded for credentials arm %q", arm),
		}}
		report.Summary = fmt.Sprintf("unknown on protocol %d: no rule for %s", protocolVersion, arm)
		return report, nil
	}

	armResult := armVerdict(arm, rule, protocolVersion)
	findings := []CompatibilityFinding{{
		Path:    "credentials",
		Verdict: armResult,
		Reason:  rule.reason,
		Source:  rule.source,
	}}

	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		if entry.Credentials.AddressWithDelegates == nil {
			return CompatibilityReport{}, fmt.Errorf("soroauth: check protocol compatibility: %w",
				fmt.Errorf("address_with_delegates credentials arm is empty"))
		}
		delegateReason := "CAP-71-01's protocol-27 requirement applies to every node of the delegate tree, not only its top level."
		delegateSource := cap7101Source
		if armResult == ProtocolVerdictAccepted {
			delegateReason = "Accepted at this protocol as part of the address_with_delegates arm; CAP-71-01 validates every delegates and nestedDelegates array by the same rules."
		}
		nested, err := compatDelegateFindings(
			entry.Credentials.AddressWithDelegates.Delegates,
			"credentials.delegates",
			armResult,
			delegateReason,
			delegateSource,
			1,
		)
		if err != nil {
			return CompatibilityReport{}, fmt.Errorf("soroauth: check protocol compatibility: %w", err)
		}
		findings = append(findings, nested...)
	}

	// The invocation's function type decides nothing about the credential
	// arm's version, so a known arm produces no finding here. An unknown type
	// does, because this checker cannot say what protocol implements it.
	switch entry.RootInvocation.Function.Type {
	case xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
		xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
		xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractV2HostFn:
		// Known invocation types: no version claim is made about them, so
		// they neither raise nor lower the verdict.
	default:
		findings = append(findings, CompatibilityFinding{
			Path:    "rootInvocation.function.type",
			Verdict: ProtocolVerdictUnknown,
			Reason:  fmt.Sprintf("invocation function type %d is not one this build implements, so its protocol availability is unknown", entry.RootInvocation.Function.Type),
		})
	}

	report.Findings = findings
	report.Verdict = worstVerdict(findings)
	report.Summary = compatSummary(report)
	return report, nil
}

// compatSummary renders the one-line answer, ending in the sentence the
// verdict rests on so a terminal reader does not have to go looking.
func compatSummary(report CompatibilityReport) string {
	var b strings.Builder
	switch report.Verdict {
	case ProtocolVerdictRejected:
		fmt.Fprintf(&b, "rejected on protocol %d", report.ProtocolVersion)
	case ProtocolVerdictDifferentSemantics:
		fmt.Fprintf(&b, "accepted with different semantics on protocol %d", report.ProtocolVersion)
	case ProtocolVerdictUnknown:
		fmt.Fprintf(&b, "unknown on protocol %d", report.ProtocolVersion)
	default:
		fmt.Fprintf(&b, "accepted on protocol %d", report.ProtocolVersion)
	}
	if report.CredentialType != "" {
		fmt.Fprintf(&b, ": %s", report.CredentialType)
	}
	// The most severe finding carries the reason the verdict was reached.
	worst := -1
	rank := map[ProtocolVerdict]int{
		ProtocolVerdictAccepted:           0,
		ProtocolVerdictDifferentSemantics: 1,
		ProtocolVerdictUnknown:            2,
		ProtocolVerdictRejected:           3,
	}
	for i := range report.Findings {
		if worst == -1 || rank[report.Findings[i].Verdict] > rank[report.Findings[worst].Verdict] {
			worst = i
		}
	}
	if worst >= 0 && report.Findings[worst].Reason != "" {
		b.WriteString("; ")
		b.WriteString(report.Findings[worst].Reason)
	}
	return b.String()
}
