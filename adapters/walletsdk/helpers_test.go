package walletsdk

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// testValidUntilLedger is the expiration the tests commit to. It is the ledger
// the host compares the signature's expiration against, which is a different
// clock from the validity window a contract checks for itself; see VerifyEntry
// and the session-keys fixture.
const testValidUntilLedger = uint32(1234567)

// testPassphrase is the network passphrase the tests sign and verify under.
const testPassphrase = network.TestNetworkPassphrase

// testKeypair derives a deterministic ed25519 keypair from a label. The keys
// are public by construction and must never be funded on mainnet.
func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

// testContractAddress derives a deterministic C… address from a label.
func testContractAddress(t *testing.T, label string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(label))
	address, err := strkey.Encode(strkey.VersionByteContract, sum[:])
	if err != nil {
		t.Fatalf("encoding contract address for %q: %v", label, err)
	}
	return address
}

// testScAddress parses an address into the ScAddress a credential carries.
func testScAddress(t *testing.T, address string) xdr.ScAddress {
	t.Helper()
	parsed, err := soroauth.ParseAddress(address)
	if err != nil {
		t.Fatalf("parsing %q: %v", address, err)
	}
	return parsed
}

// testInvocation builds a small but non-trivial call tree, so the payloads the
// tests sign are not bare leaves.
func testInvocation(t *testing.T) xdr.SorobanAuthorizedInvocation {
	t.Helper()

	contract := testScAddress(t, testContractAddress(t, "walletsdk-contract"))
	subContract := testScAddress(t, testContractAddress(t, "walletsdk-subcontract"))
	amount := xdr.Int64(100)

	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contract,
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: &amount}},
			},
		},
		SubInvocations: []xdr.SorobanAuthorizedInvocation{{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: subContract,
					FunctionName:    xdr.ScSymbol("approve"),
					Args:            []xdr.ScVal{},
				},
			},
		}},
	}
}

// testEntry builds an address-credential entry owned by address, carrying the
// void signature an unsigned entry from a record-mode simulation carries.
func testEntry(t *testing.T, address string, nonce int64) xdr.SorobanAuthorizationEntry {
	t.Helper()
	return testEntryWithSignature(t, address, nonce, xdr.ScVal{Type: xdr.ScValTypeScvVoid})
}

// testEntryWithSignature is testEntry with the credential node's signature
// field set to something specific.
func testEntryWithSignature(
	t *testing.T,
	address string,
	nonce int64,
	signature xdr.ScVal,
) xdr.SorobanAuthorizationEntry {
	t.Helper()
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   testScAddress(t, address),
				Nonce:                     xdr.Int64(nonce),
				SignatureExpirationLedger: 0,
				Signature:                 signature,
			},
		},
		RootInvocation: testInvocation(t),
	}
}

// invokeOperation builds an invokeHostFunction operation carrying entries.
func invokeOperation(t *testing.T, entries ...xdr.SorobanAuthorizationEntry) xdr.Operation {
	t.Helper()

	contract := testScAddress(t, testContractAddress(t, "walletsdk-envelope-contract"))
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{},
				},
			},
			Auth: entries,
		},
	}}
}

// paymentOperation is a valid operation that is not an invokeHostFunction, so
// the tests can prove operation indices count the operations in between.
func paymentOperation(t *testing.T) xdr.Operation {
	t.Helper()
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypePayment,
		PaymentOp: &xdr.PaymentOp{
			Destination: xdr.MustMuxedAddress(testKeypair(t, "walletsdk-recipient").Address()),
			Asset:       xdr.Asset{Type: xdr.AssetTypeAssetTypeNative},
			Amount:      1,
		},
	}}
}

// testEnvelope wraps operations in an envelope_type_tx.
func testEnvelope(t *testing.T, operations ...xdr.Operation) xdr.TransactionEnvelope {
	t.Helper()
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(testKeypair(t, "walletsdk-source").Address()),
			Fee:           100,
			SeqNum:        1,
			Cond:          xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
			Memo:          xdr.Memo{Type: xdr.MemoTypeMemoNone},
			Operations:    operations,
			Ext:           xdr.TransactionExt{V: 0},
		}},
	}
}

// feeBumpEnvelope wraps an envelope_type_tx envelope in a fee bump, the way a
// sponsor does. The inner transaction is where the host looks for the entries.
func feeBumpEnvelope(t *testing.T, inner xdr.TransactionEnvelope) xdr.TransactionEnvelope {
	t.Helper()
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			FeeSource: xdr.MustMuxedAddress(testKeypair(t, "walletsdk-fee-source").Address()),
			Fee:       200,
			InnerTx: xdr.FeeBumpTransactionInnerTx{
				Type: xdr.EnvelopeTypeEnvelopeTypeTx,
				V1:   inner.V1,
			},
			Ext: xdr.FeeBumpTransactionExt{V: 0},
		}},
	}
}

// encode marshals an envelope to base64, for the byte-for-byte comparisons.
func encode(t *testing.T, env xdr.TransactionEnvelope) string {
	t.Helper()
	encoded, err := xdr.MarshalBase64(env)
	if err != nil {
		t.Fatalf("encoding the envelope: %v", err)
	}
	return encoded
}

// stubKeypair is a Keypair whose three methods each test sets, so the refusals
// NewSigner and VerifyEntry promise can be provoked without a real key.
type stubKeypair struct {
	address string
	sign    func(input []byte) ([]byte, error)
	verify  func(input, signature []byte) error
}

func (s stubKeypair) Address() string { return s.address }

func (s stubKeypair) Sign(input []byte) ([]byte, error) {
	if s.sign == nil {
		return nil, errors.New("stub: Sign was not configured")
	}
	return s.sign(input)
}

func (s stubKeypair) Verify(input, signature []byte) error {
	if s.verify == nil {
		return nil
	}
	return s.verify(input, signature)
}

// entryOf returns the only authorization entry in an envelope.
func entryOf(t *testing.T, env xdr.TransactionEnvelope) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entries, err := soroauth.EnvelopeEntries(env)
	if err != nil {
		t.Fatalf("reading the envelope's entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	return entries[0].Entry
}

// testSourceAccountEntry builds a source-account entry. It carries no
// signature of its own: the envelope's own signature covers it, so soroauth
// has nothing to sign and nothing to verify here.
func testSourceAccountEntry(t *testing.T) xdr.SorobanAuthorizationEntry {
	t.Helper()
	return xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount},
		RootInvocation: testInvocation(t),
	}
}

// reencode returns a deep copy of an entry, by way of its XDR encoding, so a
// test can damage a signed entry without touching the original.
func reencode(t *testing.T, entry xdr.SorobanAuthorizationEntry) xdr.SorobanAuthorizationEntry {
	t.Helper()
	encoded, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding the entry: %v", err)
	}
	var out xdr.SorobanAuthorizationEntry
	if err := out.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("decoding the entry: %v", err)
	}
	return out
}
