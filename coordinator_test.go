package soroauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoordinator(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-coord-k1")
	kp2 := testKeypair(t, "soroauth-coord-k2")
	kp3 := testKeypair(t, "soroauth-coord-k3")

	address1, _ := ParseAddress(kp1.Address())
	address2, _ := ParseAddress(kp2.Address())
	address3, _ := ParseAddress(kp3.Address())

	delegate1 := xdr.SorobanDelegateSignature{
		Address:   address1,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		NestedDelegates: []xdr.SorobanDelegateSignature{{
			Address:   address2,
			Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
		}},
	}
	delegate2 := xdr.SorobanDelegateSignature{
		Address:   address3,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   address1,
					Nonce:                     42,
					SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: []xdr.SorobanDelegateSignature{delegate1, delegate2},
			},
		},
	}

	_, err := NewCoordinator(entry, 0, network.TestNetworkPassphrase)
	assert.ErrorIs(t, err, ErrInvalidExpiration)

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	assert.False(t, coord.IsComplete())
	assert.Equal(t, 0, coord.SignedCount())
	assert.Equal(t, 3, coord.TotalCount())

	remaining := coord.Remaining()
	assert.Equal(t, 3, len(remaining))

	state := coord.State()
	assert.Equal(t, "address_with_delegates", state.CredentialType)
	assert.Equal(t, 3, state.TotalNodes)
	assert.Equal(t, 0, state.SignedCount)

	stateJSON, _ := json.Marshal(state)
	assert.NotContains(t, string(stateJSON), "secret")
}

func TestCoordinatorStateContainsNoSecrets(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-coord-secrets-1")
	kp2 := testKeypair(t, "soroauth-coord-secrets-2")

	address1, _ := ParseAddress(kp1.Address())
	address2, _ := ParseAddress(kp2.Address())

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   address1,
					Nonce:                     1,
					SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: []xdr.SorobanDelegateSignature{{
					Address:   address2,
					Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				}},
			},
		},
	}

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	state := coord.State()
	stateJSON, _ := json.Marshal(state)
	assert.NotContains(t, string(stateJSON), "secret")
}

func TestCoordinatorMarshalUnmarshal(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-coord-marshal-1")
	kp2 := testKeypair(t, "soroauth-coord-marshal-2")

	address1, _ := ParseAddress(kp1.Address())
	address2, _ := ParseAddress(kp2.Address())

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   address1,
					Nonce:                     1,
					SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: []xdr.SorobanDelegateSignature{{
					Address:   address2,
					Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				}},
			},
		},
	}

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	data, err := coord.MarshalState()
	require.NoError(t, err)

	state, err := UnmarshalState(data)
	require.NoError(t, err)

	assert.Equal(t, "address_with_delegates", state.CredentialType)
	assert.Equal(t, 1, state.TotalNodes)
	assert.Equal(t, 0, state.SignedCount)
}

func TestCoordinatorContextCancellation(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-ctx").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	addr, _ := FormatAddress(address1)
	err = coord.Record(ctx, addr, NewEd25519Signer(testKeypair(t, "soroauth-coord-ctx")))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestCoordinatorValidateExpirationConsistency(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-exp").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)
	assert.NoError(t, coord.ValidateExpirationConsistency())
}

func TestCoordinatorTopLevelAddress(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-tl").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	addr, err := coord.TopLevelAddress()
	require.NoError(t, err)
	expected, _ := FormatAddress(address1)
	assert.Equal(t, expected, addr)
}

func TestCoordinatorEntry(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-entry").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	copied, err := coord.Entry()
	require.NoError(t, err)
	assert.Equal(t, entry.Credentials.Type, copied.Credentials.Type)
}

func TestCoordinatorSignAndComplete(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-sign-1").Address())
	address2, _ := ParseAddress(testKeypair(t, "soroauth-coord-sign-2").Address())
	address3, _ := ParseAddress(testKeypair(t, "soroauth-coord-sign-3").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1
	entry.Credentials.AddressWithDelegates.Delegates = []xdr.SorobanDelegateSignature{
		{Address: address1, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		{Address: address2, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		{Address: address3, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
	}

	coord, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	assert.False(t, coord.IsComplete())
	assert.Equal(t, 0, coord.SignedCount())
	assert.Equal(t, 3, coord.TotalCount())
}

func TestCoordinatorInvalidExpirationOnRecord(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 1)
	address1, _ := ParseAddress(testKeypair(t, "soroauth-coord-inv-exp").Address())
	entry.Credentials.AddressWithDelegates.AddressCredentials.Address = address1

	ctx := context.Background()
	signer := NewEd25519Signer(testKeypair(t, "soroauth-coord-inv-exp"))
	addr, _ := FormatAddress(address1)
	signedEntry, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(addr))
	assert.NoError(t, err)

	coord, err := NewCoordinator(signedEntry, testValidUntilLedger+1, network.TestNetworkPassphrase)
	require.NoError(t, err)
	err = coord.Record(ctx, addr, signer)
	assert.ErrorIs(t, err, ErrInvalidExpiration)
}

func TestCoordinatorNonDelegatesEntry(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}

	_, err := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	assert.ErrorIs(t, err, ErrUnsupportedCredentials)
}
