package soroauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditRecord_Signed(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	var captured AuditRecord
	sink := AuditSinkFunc(func(ctx context.Context, r AuditRecord) error {
		captured = r
		return nil
	})

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
		WithAudit(sink),
	)
	require.NoError(t, err)

	assert.Equal(t, AuditDecisionSigned, captured.Decision)
	assert.Equal(t, kp.Address(), captured.TargetAddress)
	assert.Equal(t, uint32(100), captured.ValidUntilLedger)
	assert.Equal(t, network.TestNetworkPassphrase, captured.NetworkPassphrase)
	assert.NotEmpty(t, captured.PayloadHash)
	assert.NotEmpty(t, captured.RootInvocationHash)
	assert.NotEmpty(t, captured.CredentialArm)
	assert.False(t, captured.Timestamp.IsZero())
	assert.Empty(t, captured.Error)
	assert.Equal(t, 1, captured.NodeCount)
}

func TestAuditRecord_Refused(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())

	var captured AuditRecord
	sink := AuditSinkFunc(func(ctx context.Context, r AuditRecord) error {
		captured = r
		return nil
	})

	failSigner := SignerFunc(kp.Address(), func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		return xdr.ScVal{}, fmt.Errorf("deliberately refused: %w", ErrPolicyRefusal)
	})

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		failSigner,
		100,
		network.TestNetworkPassphrase,
		WithAudit(sink),
	)
	require.Error(t, err)

	assert.Equal(t, AuditDecisionRefused, captured.Decision)
	assert.Contains(t, captured.Error, "refused")
}

func TestAuditRecord_NoSecrets(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)
	seed := kp.Seed()

	var captured AuditRecord
	sink := AuditSinkFunc(func(ctx context.Context, r AuditRecord) error {
		captured = r
		return nil
	})

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
		WithAudit(sink),
	)
	require.NoError(t, err)

	recordJSON, err := json.Marshal(captured)
	require.NoError(t, err)

	recordStr := string(recordJSON)
	assert.NotContains(t, recordStr, seed, "audit record must not contain the seed")
}

func TestAuditRecord_SinkErrorFailsSigning(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	sinkErr := errors.New("audit sink failed")
	sink := AuditSinkFunc(func(ctx context.Context, r AuditRecord) error {
		return sinkErr
	})

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
		WithAudit(sink),
	)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "audit"))
}

func TestAuditRecord_StableSerialization(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	var captured AuditRecord
	sink := AuditSinkFunc(func(ctx context.Context, r AuditRecord) error {
		captured = r
		return nil
	})

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
		WithAudit(sink),
	)
	require.NoError(t, err)

	data, err := json.Marshal(captured)
	require.NoError(t, err)

	var decoded AuditRecord
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, captured.Decision, decoded.Decision)
	assert.Equal(t, captured.PayloadHash, decoded.PayloadHash)
	assert.Equal(t, captured.TargetAddress, decoded.TargetAddress)
}

func TestAuditRecord_NoAuditSinkIsNoOp(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	_, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)
}

// testAddressEntry builds a minimal address-arm entry for testing.
func testAddressEntry(t *testing.T, address string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	parsed, err := ParseAddress(address)
	require.NoError(t, err)
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address: parsed,
				Nonce:   42,
				Signature: xdr.ScVal{
					Type: xdr.ScValTypeScvVoid,
				},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: parsed,
					FunctionName:    "transfer",
				},
			},
		},
	}
}
