package soroauth

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-k1")
	kp2 := testKeypair(t, "soroauth-plan-k2")
	kp3 := testKeypair(t, "soroauth-plan-k3")

	policy := []DelegatePolicy{
		{Address: kp1.Address()},
		{Address: kp2.Address(), Nested: []DelegatePolicy{
			{Address: kp3.Address()},
		}},
	}

	tree, err := Plan(testValidUntilLedger, policy)
	require.NoError(t, err)
	assert.Equal(t, testValidUntilLedger, tree.ValidUntilLedger)
	assert.Len(t, tree.Delegates, 2)

	described := tree.Describe()
	assert.Len(t, described, 2)
	assert.Equal(t, kp1.Address(), described[0].Address)
	assert.Len(t, described[1].Nested, 1)
	assert.Equal(t, kp3.Address(), described[1].Nested[0].Address)
}

func TestPlanEmptyPolicy(t *testing.T) {
	tree, err := Plan(testValidUntilLedger, nil)
	require.NoError(t, err)
	assert.Empty(t, tree.Delegates)
}

func TestPlanZeroExpiration(t *testing.T) {
	policy := []DelegatePolicy{
		{Address: testKeypair(t, "soroauth-plan-ze").Address()},
	}
	_, err := Plan(0, policy)
	assert.ErrorIs(t, err, ErrInvalidExpiration)
}

func TestPlanWithRegistrations(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-reg-1")
	kp2 := testKeypair(t, "soroauth-plan-reg-2")
	kp3 := testKeypair(t, "soroauth-plan-reg-3")

	policy := []DelegatePolicy{
		{Address: kp1.Address()},
		{Address: kp2.Address()},
	}

	registrations := []SignerRegistration{
		{Address: kp1.Address(), Signer: NewEd25519Signer(kp1)},
		{Address: kp2.Address(), Signer: NewEd25519Signer(kp2)},
	}
	tree, err := Plan(testValidUntilLedger, policy, registrations...)
	require.NoError(t, err)
	assert.Len(t, tree.Delegates, 2)

	policy2 := []DelegatePolicy{
		{Address: kp1.Address()},
		{Address: kp3.Address()},
	}
	_, err = Plan(testValidUntilLedger, policy2, registrations...)
	assert.Error(t, err)
}

func TestPlanDuplicateDelegate(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-dup")

	policy := []DelegatePolicy{
		{Address: kp1.Address()},
		{Address: kp1.Address()},
	}

	_, err := Plan(testValidUntilLedger, policy)
	assert.Error(t, err)
}

func TestPlanValidateOrder(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-vo-1")
	kp2 := testKeypair(t, "soroauth-plan-vo-2")
	kp3 := testKeypair(t, "soroauth-plan-vo-3")

	policy := []DelegatePolicy{
		{Address: kp2.Address()},
		{Address: kp1.Address()},
		{Address: kp3.Address()},
	}

	tree, err := Plan(testValidUntilLedger, policy)
	require.NoError(t, err)

	// Use a non-delegates entry since WithDelegates wraps a non-delegates entry.
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	wrapped, err := tree.Wrap(entry, nil)
	require.NoError(t, err)
	assert.NoError(t, ValidateDelegateOrder(wrapped))
}

func TestPlannedTreeWrap(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-wrap")
	kp2 := testKeypair(t, "soroauth-plan-wrap-2")

	policy := []DelegatePolicy{
		{Address: kp1.Address()},
		{Address: kp2.Address()},
	}

	tree, err := Plan(testValidUntilLedger, policy)
	require.NoError(t, err)

	// Use a non-delegates entry since WithDelegates wraps a non-delegates entry.
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	wrapped, err := tree.Wrap(entry, nil)
	require.NoError(t, err)
	assert.Equal(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, wrapped.Credentials.Type)
}

func TestDescribeDelegatesRoundTrip(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-plan-desc-1")
	kp2 := testKeypair(t, "soroauth-plan-desc-2")
	kp3 := testKeypair(t, "soroauth-plan-desc-3")

	delegates := []Delegate{
		{Address: kp1.Address(), Nested: []Delegate{
			{Address: kp2.Address()},
		}},
		{Address: kp3.Address()},
	}

	policies := describeDelegates(delegates)
	assert.Len(t, policies, 2)
	assert.Equal(t, kp1.Address(), policies[0].Address)
	assert.Len(t, policies[0].Nested, 1)
	assert.Equal(t, kp2.Address(), policies[0].Nested[0].Address)
}
