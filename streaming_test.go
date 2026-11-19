package soroauth

import (
	"context"
	"runtime"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamingSign_IdenticalToAuthorizeEntry(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	authorized, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	streamed, err := StreamingSign(
		context.Background(),
		entry,
		func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return signer.Sign(ctx, preimage, payload)
		},
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	authorizedBytes, err := authorized.MarshalBinary()
	require.NoError(t, err)
	streamedBytes, err := streamed.MarshalBinary()
	require.NoError(t, err)

	assert.Equal(t, authorizedBytes, streamedBytes, "streaming sign must produce identical bytes")
}

func TestStreamingSign_CancellationLeavesEntryUntouched(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := StreamingSign(
		ctx,
		entry,
		func(ctx context.Context, address string, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
			t.Fatal("visitor should not be called after cancellation")
			return xdr.ScVal{}, nil
		},
		100,
		network.TestNetworkPassphrase,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestStreamingSign_SourceAccountPassthrough(t *testing.T) {
	kp := keypair.MustRandom()
	parsed, err := ParseAddress(kp.Address())
	require.NoError(t, err)

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
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

	result, err := StreamingSign(
		context.Background(),
		entry,
		func(ctx context.Context, address string, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
			t.Fatal("visitor should not be called for source-account entries")
			return xdr.ScVal{}, nil
		},
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)
	assert.Equal(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, result.Credentials.Type)
}

func TestStreamingSign_NilVisitorRefused(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())

	_, err := StreamingSign(
		context.Background(),
		entry,
		nil,
		100,
		network.TestNetworkPassphrase,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingSigner)
}

func TestStreamingSign_ZeroExpiration(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())

	_, err := StreamingSign(
		context.Background(),
		entry,
		func(ctx context.Context, address string, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
			return xdr.ScVal{}, nil
		},
		0,
		network.TestNetworkPassphrase,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidExpiration)
}

func TestStreamingSign_AlreadySignedRefused(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	signed, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	_, err = StreamingSign(
		context.Background(),
		signed,
		func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return signer.Sign(ctx, preimage, payload)
		},
		100,
		network.TestNetworkPassphrase,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadySigned)
}

func TestStreamingSign_AllowResign(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	signed, err := AuthorizeEntry(
		context.Background(),
		entry,
		signer,
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	_, err = StreamingSign(
		context.Background(),
		signed,
		func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return signer.Sign(ctx, preimage, payload)
		},
		100,
		network.TestNetworkPassphrase,
		StreamingAllowResign(),
	)
	require.NoError(t, err)
}

func BenchmarkStreamingSign_FlatAlloc(b *testing.B) {
	kp := keypair.MustRandom()
	entry := testAddressEntryB(b, kp.Address())
	signer := NewEd25519Signer(kp)

	visitor := func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		return signer.Sign(ctx, preimage, payload)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := StreamingSign(
			context.Background(),
			entry,
			visitor,
			100,
			network.TestNetworkPassphrase,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorizeEntry_Baseline(b *testing.B) {
	kp := keypair.MustRandom()
	entry := testAddressEntryB(b, kp.Address())
	signer := NewEd25519Signer(kp)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := AuthorizeEntry(
			context.Background(),
			entry,
			signer,
			100,
			network.TestNetworkPassphrase,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func testAddressEntryB(b *testing.B, address string) xdr.SorobanAuthorizationEntry {
	b.Helper()
	parsed, err := ParseAddress(address)
	require.NoError(b, err)
	runtime.KeepAlive(parsed)
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

func TestStreamingSign_InputPreserved(t *testing.T) {
	kp := keypair.MustRandom()
	entry := testAddressEntry(t, kp.Address())
	signer := NewEd25519Signer(kp)

	entryBefore, err := entry.MarshalBinary()
	require.NoError(t, err)

	_, err = StreamingSign(
		context.Background(),
		entry,
		func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return signer.Sign(ctx, preimage, payload)
		},
		100,
		network.TestNetworkPassphrase,
	)
	require.NoError(t, err)

	entryAfter, err := entry.MarshalBinary()
	require.NoError(t, err)

	assert.Equal(t, entryBefore, entryAfter, "StreamingSign must not mutate the input entry")
}
