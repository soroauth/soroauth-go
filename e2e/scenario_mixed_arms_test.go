//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// The mixed-arm scenarios put all four credential arms in one transaction. The
// other scenarios each prove one arm; the host checks the arms together, and an
// ordering or nonce interaction that only appears when all four are present
// would pass every single-arm test.
//
// The fixture is the modular-account contract itself. Its `require_all`
// function calls `require_auth` on each address it is given and does nothing
// else, so the target contract is not the authorizer: the payer is the
// source-account arm, two classic accounts are the legacy and V2 arms, and a
// second modular-account instance is the delegates arm.

// mixedArms is one scenario's accounts and contracts.
type mixedArms struct {
	payer  *keypair.Full
	legacy *keypair.Full
	v2     *keypair.Full
	d1     *keypair.Full
	d2     *keypair.Full

	fixture string
	account string
}

func mixedArmsSetup(t *testing.T, h *harness) *mixedArms {
	t.Helper()

	m := &mixedArms{
		payer:  h.newAccount(t, "payer P"),
		legacy: h.newAccount(t, "legacy A"),
		v2:     h.newAccount(t, "v2 B"),
		d1:     h.newAccount(t, "delegate D1"),
		d2:     h.newAccount(t, "delegate D2"),
	}

	// The called contract. It needs no delegates of its own; it only calls
	// require_auth on the accounts it is handed.
	m.fixture = h.deployModularAccount(t, m.payer, nil).ContractAddress
	// The account that authenticates by delegating to D1 and D2.
	m.account = h.deployModularAccount(t, m.payer, []string{m.d1.Address(), m.d2.Address()}).ContractAddress

	t.Logf("fixture contract: %s", m.fixture)
	t.Logf("delegating account: %s", m.account)
	return m
}

// requireAllOp calls fixture.require_all([payer, legacy, v2, account]).
func (m *mixedArms) requireAllOp(t *testing.T, h *harness) txnbuild.InvokeHostFunction {
	t.Helper()

	accounts := xdr.ScVec{
		scAddressVal(scAddressOf(t, m.payer.Address())),
		scAddressVal(scAddressOf(t, m.legacy.Address())),
		scAddressVal(scAddressOf(t, m.v2.Address())),
		scAddressVal(scAddressOf(t, m.account)),
	}

	return txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
			InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: scAddressOf(t, m.fixture),
				FunctionName:    xdr.ScSymbol("require_all"),
				Args:            xdr.ScVec{scVecVal(accounts)},
			},
		},
		SourceAccount: m.payer.Address(),
	}
}

// prepareMixedArms turns the recorded entries into one of each arm:
//
//   - the payer's source-account entry, added if simulation omitted it;
//   - the legacy account's entry, downgraded if the host recorded V2;
//   - the V2 account's entry, upgraded if the host recorded legacy;
//   - the delegating account's entry, wrapped with D1 and D2.
func (m *mixedArms) prepareMixedArms(t *testing.T, entries []xdr.SorobanAuthorizationEntry, validUntil uint32) []xdr.SorobanAuthorizationEntry {
	t.Helper()

	out := make([]xdr.SorobanAuthorizationEntry, 0, len(entries)+1)
	sawSource := false
	haveRoot := false
	var rootInvocation xdr.SorobanAuthorizedInvocation

	for _, entry := range entries {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting a recorded entry: %v", err)
		}
		if !haveRoot {
			rootInvocation = entry.RootInvocation
			haveRoot = true
		}

		switch info.CredentialType {
		case soroauth.CredentialTypeSourceAccount:
			sawSource = true
			out = append(out, entry)

		case soroauth.CredentialTypeAddress, soroauth.CredentialTypeAddressV2:
			switch info.Address {
			case m.legacy.Address():
				out = append(out, downgradeToLegacy(t, entry))
			case m.v2.Address():
				upgraded, err := soroauth.UpgradeToV2(entry)
				if err != nil {
					t.Fatalf("upgrading the V2 entry: %v", err)
				}
				out = append(out, upgraded)
			case m.account:
				wrapped, err := soroauth.WithDelegates(entry, validUntil, []soroauth.Delegate{
					{Address: m.d1.Address()},
					{Address: m.d2.Address()},
				}, nil)
				if err != nil {
					t.Fatalf("wrapping the delegating account's entry: %v", err)
				}
				out = append(out, wrapped)
			default:
				out = append(out, entry)
			}

		default:
			out = append(out, entry)
		}
	}

	// The host may omit an entry for the transaction source, because the
	// envelope's own signature authenticates it. The scenario is about all
	// four arms appearing in the submitted transaction, so make the
	// source-account arm explicit when it was implicit.
	if !sawSource {
		out = append(out, xdr.SorobanAuthorizationEntry{
			Credentials: xdr.SorobanCredentials{
				Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
			},
			RootInvocation: rootInvocation,
		})
	}

	return out
}

// downgradeToLegacy converts a V2 entry to the legacy address arm with the same
// fields. The payload changes with the arm, so this runs before signing; a
// signature produced for V2 would not verify here.
func downgradeToLegacy(t *testing.T, entry xdr.SorobanAuthorizationEntry) xdr.SorobanAuthorizationEntry {
	t.Helper()
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddress {
		return entry
	}
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 ||
		entry.Credentials.AddressV2 == nil {
		t.Fatalf("cannot downgrade credential type %s", entry.Credentials.Type)
	}
	v2 := entry.Credentials.AddressV2
	entry.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		Address: &xdr.SorobanAddressCredentials{
			Address:                   v2.Address,
			Nonce:                     v2.Nonce,
			SignatureExpirationLedger: v2.SignatureExpirationLedger,
			Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		},
	}
	return entry
}

// emptySignature is the unsigned form both the host and soroauth treat as "no
// signature yet".
func emptySignature() xdr.ScVal {
	vec := xdr.ScVec{}
	ptr := &vec
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &ptr}
}

func (m *mixedArms) signers() []soroauth.Signer {
	return []soroauth.Signer{
		soroauth.NewEd25519Signer(m.legacy),
		soroauth.NewEd25519Signer(m.v2),
		soroauth.NewEd25519Signer(m.d1),
		soroauth.NewEd25519Signer(m.d2),
	}
}

// TestScenarioMixedArms submits one transaction carrying a source-account, a
// legacy address, a V2 and a delegates entry, and decodes the submitted
// envelope back to observe all four arms.
func TestScenarioMixedArms(t *testing.T) {
	h := newHarness(t)
	m := mixedArmsSetup(t, h)
	op := m.requireAllOp(t, h)

	result := runScenario(t, h, scenarioSpec{
		payer:        m.payer,
		op:           op,
		upgradedAuth: false, // ask for legacy entries; B is upgraded in prepare
		signers:      m.signers(),
		prepare:      m.prepareMixedArms,
	})

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arms:    %s", result.Arm)
	t.Logf("link:    %s%s", runExplorerBase, result.Hash)

	observed := mixedArmsOf(t, result.Arm)
	record(scenarioResult{
		ID:        "R",
		Name:      "all four credential arms in one transaction are accepted",
		Proves:    "A source-account, legacy address, V2 and delegates entry compose in one invocation; the host accepts the four together, which no single-arm scenario proves.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"Observed arms on the submitted envelope: " + result.Arm,
			"Payer (source account): " + m.payer.Address(),
			"Legacy account:         " + m.legacy.Address(),
			"V2 account:             " + m.v2.Address(),
			"Delegating account:     " + m.account,
			"Delegates:              " + m.d1.Address() + ", " + m.d2.Address(),
			"Fixture contract:       " + m.fixture,
			"The submitted envelope was decoded back; the four arms are observed, not assumed.",
		},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("the mixed-arm submission failed (status %s):\n%s", result.Status, result.RawError)
	}
	if len(observed) != 4 {
		t.Errorf("the submitted envelope carried %d credential arms, want 4: %s", len(observed), result.Arm)
	}
	for _, want := range []string{"SourceAccount", "Address", "AddressV2", "AddressWithDelegates"} {
		if !observed[want] {
			t.Errorf("the submitted envelope did not carry the %s arm: %s", want, result.Arm)
		}
	}
}

// TestScenarioMixedArmsNegative is the control. The same transaction goes out
// with the V2 entry's signature removed; the host must refuse it, and the raw
// error is recorded. Without this, R could pass while the V2 arm was never
// actually checked.
func TestScenarioMixedArmsNegative(t *testing.T) {
	h := newHarness(t)
	m := mixedArmsSetup(t, h)
	op := m.requireAllOp(t, h)

	result := runScenario(t, h, scenarioSpec{
		payer:         m.payer,
		op:            op,
		upgradedAuth:  false,
		signers:       m.signers(),
		prepare:       m.prepareMixedArms,
		expectFailure: true,
		afterSign: func(t *testing.T, entries []xdr.SorobanAuthorizationEntry) []xdr.SorobanAuthorizationEntry {
			t.Helper()
			for i := range entries {
				info, err := soroauth.Inspect(entries[i])
				if err != nil {
					t.Fatalf("inspecting a signed entry: %v", err)
				}
				if info.Address == m.v2.Address() {
					entries[i].Credentials.AddressV2.Signature = emptySignature()
				}
			}
			return entries
		},
	})

	t.Logf("tx hash: %s", result.Hash)
	t.Logf("ledger:  %d", result.Ledger)
	t.Logf("arms:    %s", result.Arm)
	t.Logf("error:   %s", result.RawError)

	record(scenarioResult{
		ID:              "R-control",
		Name:            "a mixed transaction with the V2 signature removed is refused",
		Proves:          "The host checks the V2 arm in the mixed transaction; removing its signature is refused, so R's acceptance is not the host ignoring that entry.",
		TxHash:          result.Hash,
		Ledger:          result.Ledger,
		Arm:             result.Arm,
		Succeeded:       result.Status == rpc.TransactionStatusSuccess,
		ExpectRejection: true,
		RawError:        result.RawError,
		Notes: []string{
			"The V2 entry's signature was replaced with an empty vector after signing.",
			"Observed arms on the submitted envelope: " + result.Arm,
			"Raw host error is recorded verbatim above.",
		},
	})

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted a mixed transaction with the V2 signature removed")
	}

	details := hostErrorDetails(t, result.Diagnostics)
	var sawAuth bool
	for _, detail := range details {
		if detail.ErrorType == int32(xdr.ScErrorTypeSceAuth) {
			sawAuth = true
		}
	}
	if !sawAuth {
		t.Errorf("the refusal was not an auth error; diagnostics: %s", result.RawError)
	}
}

// mixedArmsOf reports which arms appear in the comma-separated arm string
// credentialArmOf produces from a submitted envelope.
func mixedArmsOf(t *testing.T, arms string) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	for _, arm := range strings.Split(arms, ", ") {
		switch {
		case strings.Contains(arm, "SourceAccount"):
			seen["SourceAccount"] = true
		case strings.Contains(arm, "AddressWithDelegates"):
			seen["AddressWithDelegates"] = true
		case strings.Contains(arm, "AddressV2"):
			seen["AddressV2"] = true
		case strings.Contains(arm, "Address"):
			seen["Address"] = true
		}
	}
	return seen
}
