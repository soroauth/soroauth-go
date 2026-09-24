package soroauth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trackingHook records events for testing.
type trackingHook struct {
	events []HookEvent
}

func (h *trackingHook) Event(ctx context.Context, e HookEvent) error {
	h.events = append(h.events, e)
	return nil
}

func TestHookNoOp(t *testing.T) {
	hook := NoOpHook{}
	err := hook.Event(context.Background(), HookEvent{Phase: HookPhaseSign})
	assert.NoError(t, err)
}

func TestHookReceivesEvents(t *testing.T) {
	hook := &trackingHook{}
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(hook))
	require.NoError(t, err)

	assert.True(t, len(hook.events) > 0, "hook should have received events")

	phases := make(map[HookPhase]bool)
	for _, e := range hook.events {
		phases[e.Phase] = true
	}
	assert.True(t, phases[HookPhasePreimage], "preimage event missing")
	assert.True(t, phases[HookPhaseSign], "sign event missing")
	assert.True(t, phases[HookPhaseWrite], "write event missing")
	assert.True(t, phases[HookPhasePostSign], "post_sign event missing")
}

func TestHookNoSecrets(t *testing.T) {
	hook := &trackingHook{}
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(hook))
	require.NoError(t, err)

	for _, e := range hook.events {
		assert.NotContains(t, e.TargetAddress, "secret")
	}
}

func TestHookContextCancellation(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	address := testKeypair(t, "soroauth-preimage-signer").Address()
	_, err := AuthorizeEntry(ctx, entry, NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer")), testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(&trackingHook{}))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestHookNoOpWhenUnset(t *testing.T) {
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address))
	require.NoError(t, err)
}

func TestHookNilHookDoesNotPanic(t *testing.T) {
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(nil))
	_ = err
}

func TestHookEventFields(t *testing.T) {
	hook := &trackingHook{}
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(hook))
	require.NoError(t, err)

	require.True(t, len(hook.events) > 0)
	lastEvent := hook.events[len(hook.events)-1]
	assert.Equal(t, "address", lastEvent.CredentialType)
	assert.Equal(t, uint32(testValidUntilLedger), lastEvent.ValidUntilLedger)
	assert.NoError(t, lastEvent.Error)
}

func TestHookErrorFromImpl(t *testing.T) {
	hook := errHook{}
	kp := testKeypair(t, "soroauth-preimage-signer")
	signer := NewEd25519Signer(kp)

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	_, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
		ForAddress(signer.Address()), WithHook(hook))
	_ = err
}

// errHook is a hook that always returns an error.
type errHook struct{}

func (errHook) Event(ctx context.Context, e HookEvent) error {
	return errors.New("hook error")
}

func TestHookErrorPropagated(t *testing.T) {
	hook := &trackingHook{}
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	address := signer.Address()

	_, err := AuthorizeEntry(context.Background(), entry, signer, 0, network.TestNetworkPassphrase,
		ForAddress(address), WithHook(hook))
	assert.Error(t, err)
}
