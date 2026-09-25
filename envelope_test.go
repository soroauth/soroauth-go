package soroauth

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testHostFunction builds a valid invoke-contract host function, so an envelope
// built for a test survives the XDR round-trip xdrcopy performs.
func testHostFunction(t *testing.T) xdr.HostFunction {
	t.Helper()

	contract, err := ParseAddress(testContractAddress(t, "soroauth-envelope-contract"))
	if err != nil {
		t.Fatalf("parsing the test contract address: %v", err)
	}
	return xdr.HostFunction{
		Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{
			ContractAddress: contract,
			FunctionName:    xdr.ScSymbol("transfer"),
			Args:            []xdr.ScVal{},
		},
	}
}

// invokeOperation builds an invokeHostFunction operation carrying the given
// authorization entries.
func invokeOperation(t *testing.T, entries ...xdr.SorobanAuthorizationEntry) xdr.Operation {
	t.Helper()
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypeInvokeHostFunction,
		InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: testHostFunction(t),
			Auth:         entries,
		},
	}}
}

// paymentOperation is a valid operation that is not an invokeHostFunction, so
// the tests can prove the operation indices they report count the operations
// that are not invoke calls too.
func paymentOperation(t *testing.T) xdr.Operation {
	t.Helper()
	return xdr.Operation{Body: xdr.OperationBody{
		Type: xdr.OperationTypePayment,
		PaymentOp: &xdr.PaymentOp{
			Destination: xdr.MustMuxedAddress(testKeypair(t, "soroauth-envelope-recipient").Address()),
			Asset:       xdr.Asset{Type: xdr.AssetTypeAssetTypeNative},
			Amount:      1,
		},
	}}
}

// transactionEnvelope wraps operations in an envelope_type_tx.
func transactionEnvelope(t *testing.T, operations ...xdr.Operation) xdr.TransactionEnvelope {
	t.Helper()
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTx,
		V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
			SourceAccount: xdr.MustMuxedAddress(testKeypair(t, "soroauth-envelope-source").Address()),
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
// sponsor does.
func feeBumpEnvelope(t *testing.T, inner xdr.TransactionEnvelope) xdr.TransactionEnvelope {
	t.Helper()
	return xdr.TransactionEnvelope{
		Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
		FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
			FeeSource: xdr.MustMuxedAddress(testKeypair(t, "soroauth-envelope-fee-source").Address()),
			Fee:       200,
			InnerTx: xdr.FeeBumpTransactionInnerTx{
				Type: xdr.EnvelopeTypeEnvelopeTypeTx,
				V1:   inner.V1,
			},
			Ext: xdr.FeeBumpTransactionExt{V: 0},
		}},
	}
}

// entryAddress formats an entry's credential address, for the assertions that
// check which entry ended up where.
func entryAddress(t *testing.T, entry xdr.SorobanAuthorizationEntry) string {
	t.Helper()
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading the entry's credentials: %v", err)
	}
	address, err := FormatAddress(credentials.Address)
	if err != nil {
		t.Fatalf("formatting the entry's address: %v", err)
	}
	return address
}

// assertEntrySignatureVerifies checks that the signature stored on an entry
// really signs the payload the entry commits to, and that it comes from the
// keypair named by label. This is the property that decides whether the host
// accepts the entry.
func assertEntrySignatureVerifies(
	t *testing.T,
	entry xdr.SorobanAuthorizationEntry,
	label string,
	validUntilLedger uint32,
	passphrase string,
) {
	t.Helper()

	preimage, err := Preimage(entry, validUntilLedger, passphrase)
	if err != nil {
		t.Fatalf("rebuilding the preimage: %v", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("rehashing the preimage: %v", err)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading the entry's credentials: %v", err)
	}
	parts := decodeAccountSignature(t, credentials.Signature)
	if len(parts) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parts))
	}

	keypair := testKeypair(t, label)
	raw, err := rawEd25519Key(keypair.Address())
	if err != nil {
		t.Fatalf("decoding %s: %v", label, err)
	}
	if !bytes.Equal(parts[0].publicKey, raw) {
		t.Errorf("the signature is from %x, but %s is %x", parts[0].publicKey, label, raw)
	}
	if err := keypair.Verify(payload[:], parts[0].signature); err != nil {
		t.Errorf("the stored signature does not verify against the entry's own payload: %v", err)
	}
}

func TestEnvelopeEntriesLocatesEveryEntry(t *testing.T) {
	first := entryForSigner(t, "soroauth-envelope-a", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	second := entryForSigner(t, "soroauth-envelope-b", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)
	third := entryForSigner(t, "soroauth-envelope-c", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 3)

	envelope := transactionEnvelope(t,
		paymentOperation(t),
		invokeOperation(t, first, second),
		paymentOperation(t),
		invokeOperation(t, third),
	)

	entries, err := EnvelopeEntries(envelope)
	if err != nil {
		t.Fatalf("EnvelopeEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	want := []struct {
		operationIndex int
		entryIndex     int
		label          string
	}{
		{1, 0, "soroauth-envelope-a"},
		{1, 1, "soroauth-envelope-b"},
		{3, 0, "soroauth-envelope-c"},
	}
	for i, w := range want {
		if entries[i].OperationIndex != w.operationIndex || entries[i].EntryIndex != w.entryIndex {
			t.Errorf("entry %d is at operation %d entry %d, want operation %d entry %d",
				i, entries[i].OperationIndex, entries[i].EntryIndex, w.operationIndex, w.entryIndex)
		}
		if got := entryAddress(t, entries[i].Entry); got != testKeypair(t, w.label).Address() {
			t.Errorf("entry %d belongs to %s, want %s", i, got, testKeypair(t, w.label).Address())
		}
	}
}

func TestEnvelopeEntriesReadsThroughAFeeBump(t *testing.T) {
	entry := entryForSigner(t, "soroauth-envelope-fee-bump", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 7)
	inner := transactionEnvelope(t, paymentOperation(t), invokeOperation(t, entry))

	entries, err := EnvelopeEntries(feeBumpEnvelope(t, inner))
	if err != nil {
		t.Fatalf("EnvelopeEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	// The operation index is an index into the inner transaction, which is
	// where the invoke operation actually is.
	if entries[0].OperationIndex != 1 || entries[0].EntryIndex != 0 {
		t.Errorf("the entry is reported at operation %d entry %d, want operation 1 entry 0",
			entries[0].OperationIndex, entries[0].EntryIndex)
	}
}

func TestEnvelopeEntriesHandlesAnInvokeOperationWithNoEntries(t *testing.T) {
	entries, err := EnvelopeEntries(transactionEnvelope(t, invokeOperation(t)))
	if err != nil {
		t.Fatalf("an invoke operation with no entries is not an error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d entries, want none", len(entries))
	}
}

func TestEnvelopeEntriesRejects(t *testing.T) {
	entry := entryForSigner(t, "soroauth-envelope-reject", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	emptyInvokeArm := xdr.Operation{Body: xdr.OperationBody{Type: xdr.OperationTypeInvokeHostFunction}}

	tests := []struct {
		name     string
		envelope xdr.TransactionEnvelope
		want     error
		contains string
	}{
		{
			name:     "an envelope with no invoke operation",
			envelope: transactionEnvelope(t, paymentOperation(t)),
			want:     ErrNoInvokeOperation,
		},
		{
			name:     "an envelope with no operations at all",
			envelope: transactionEnvelope(t),
			want:     ErrNoInvokeOperation,
		},
		{
			name: "an unsupported envelope type",
			envelope: xdr.TransactionEnvelope{
				Type: xdr.EnvelopeType(99),
				V1:   transactionEnvelope(t, invokeOperation(t, entry)).V1,
			},
			want: ErrUnsupportedEnvelope,
		},
		{
			name:     "an envelope_type_tx arm that is empty",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx},
			contains: "envelope_type_tx arm is empty",
		},
		{
			name:     "an envelope_type_tx_v0 arm that is empty",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxV0},
			contains: "envelope_type_tx_v0 arm is empty",
		},
		{
			name:     "a fee-bump arm that is empty",
			envelope: xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump},
			contains: "envelope_type_tx_fee_bump arm is empty",
		},
		{
			name: "a fee-bump whose inner transaction is empty",
			envelope: xdr.TransactionEnvelope{
				Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
				FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
					InnerTx: xdr.FeeBumpTransactionInnerTx{Type: xdr.EnvelopeTypeEnvelopeTypeTx},
				}},
			},
			contains: "fee-bump inner envelope_type_tx arm is empty",
		},
		{
			name: "a fee-bump whose inner arm is not a transaction",
			envelope: xdr.TransactionEnvelope{
				Type: xdr.EnvelopeTypeEnvelopeTypeTxFeeBump,
				FeeBump: &xdr.FeeBumpTransactionEnvelope{Tx: xdr.FeeBumpTransaction{
					InnerTx: xdr.FeeBumpTransactionInnerTx{Type: xdr.EnvelopeTypeEnvelopeTypeTxV0},
				}},
			},
			contains: "want envelope_type_tx",
		},
		{
			name:     "an invoke operation whose arm is empty",
			envelope: transactionEnvelope(t, emptyInvokeArm),
			contains: "invokeHostFunction arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EnvelopeEntries(tt.envelope)
			if err == nil {
				t.Fatal("EnvelopeEntries returned no error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("got %v, want it to wrap %v", err, tt.want)
			}
			if tt.contains != "" && !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("got %q, want it to mention %q", err, tt.contains)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: envelope entries: ") {
				t.Errorf("error %q does not carry the operation prefix", err)
			}
		})
	}
}

func TestInspectEnvelopeReportsPositionAndStructure(t *testing.T) {
	first := entryForSigner(t, "soroauth-envelope-inspect-a", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 4)
	source := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 5)

	envelope := transactionEnvelope(t,
		invokeOperation(t, first),
		paymentOperation(t),
		invokeOperation(t, source),
	)

	infos, err := InspectEnvelope(envelope)
	if err != nil {
		t.Fatalf("InspectEnvelope: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d reports, want 2", len(infos))
	}

	if infos[0].OperationIndex != 0 || infos[0].EntryIndex != 0 {
		t.Errorf("the first report is at operation %d entry %d, want operation 0 entry 0",
			infos[0].OperationIndex, infos[0].EntryIndex)
	}
	if infos[0].CredentialType != CredentialTypeAddressV2 {
		t.Errorf("the first report names credential type %q, want %q",
			infos[0].CredentialType, CredentialTypeAddressV2)
	}
	if infos[0].Address != testKeypair(t, "soroauth-envelope-inspect-a").Address() {
		t.Errorf("the first report names address %q, want the entry's own", infos[0].Address)
	}
	if infos[0].RootFunction != "transfer" {
		t.Errorf("the first report names function %q, want transfer", infos[0].RootFunction)
	}
	if infos[0].Nonce != 4 {
		t.Errorf("the first report names nonce %d, want 4", infos[0].Nonce)
	}

	if infos[1].OperationIndex != 2 || infos[1].EntryIndex != 0 {
		t.Errorf("the second report is at operation %d entry %d, want operation 2 entry 0",
			infos[1].OperationIndex, infos[1].EntryIndex)
	}
	if infos[1].CredentialType != CredentialTypeSourceAccount {
		t.Errorf("the second report names credential type %q, want %q",
			infos[1].CredentialType, CredentialTypeSourceAccount)
	}
}

func TestAuthorizeEnvelopeSignsEveryEntry(t *testing.T) {
	labels := []string{"soroauth-envelope-sign-a", "soroauth-envelope-sign-b", "soroauth-envelope-sign-c"}

	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(labels))
	signers := make([]Signer, 0, len(labels))
	for i, label := range labels {
		entries = append(entries, entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, int64(i+1)))
		signers = append(signers, NewEd25519Signer(testKeypair(t, label)))
	}

	envelope := transactionEnvelope(t,
		invokeOperation(t, entries[0]),
		paymentOperation(t),
		invokeOperation(t, entries[1], entries[2]),
	)

	before, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("encoding the input envelope: %v", err)
	}

	signed, err := AuthorizeEnvelope(context.Background(), envelope, signers,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEnvelope: %v", err)
	}

	after, err := xdr.MarshalBase64(envelope)
	if err != nil {
		t.Fatalf("re-encoding the input envelope: %v", err)
	}
	if before != after {
		t.Error("AuthorizeEnvelope mutated its input envelope")
	}

	signedEntries, err := EnvelopeEntries(signed)
	if err != nil {
		t.Fatalf("reading the signed envelope's entries: %v", err)
	}
	if len(signedEntries) != len(labels) {
		t.Fatalf("got %d signed entries, want %d", len(signedEntries), len(labels))
	}

	wantPosition := []struct{ operation, entry int }{{0, 0}, {2, 0}, {2, 1}}
	for i, located := range signedEntries {
		w := wantPosition[i]
		if located.OperationIndex != w.operation || located.EntryIndex != w.entry {
			t.Errorf("entry %d is at operation %d entry %d, want operation %d entry %d",
				i, located.OperationIndex, located.EntryIndex, w.operation, w.entry)
		}
		assertEntrySignatureVerifies(t, located.Entry, labels[i], testValidUntilLedger, network.TestNetworkPassphrase)
	}
}

func TestAuthorizeEnvelopeSignsThroughAFeeBump(t *testing.T) {
	label := "soroauth-envelope-fee-bump-sign"
	entry := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 9)

	inner := transactionEnvelope(t, invokeOperation(t, entry))
	envelope := feeBumpEnvelope(t, inner)

	signed, err := AuthorizeEnvelope(context.Background(), envelope,
		[]Signer{NewEd25519Signer(testKeypair(t, label))}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEnvelope: %v", err)
	}
	if signed.FeeBump == nil || signed.FeeBump.Tx.InnerTx.V1 == nil {
		t.Fatal("the fee-bump structure was lost")
	}
	if len(signed.FeeBump.Tx.InnerTx.V1.Tx.Operations) != 1 {
		t.Fatalf("got %d inner operations, want 1", len(signed.FeeBump.Tx.InnerTx.V1.Tx.Operations))
	}

	auth := signed.FeeBump.Tx.InnerTx.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.Auth
	if len(auth) != 1 {
		t.Fatalf("got %d inner entries, want 1", len(auth))
	}
	assertEntrySignatureVerifies(t, auth[0], label, testValidUntilLedger, network.TestNetworkPassphrase)
}

func TestAuthorizeEnvelopePassesSourceAccountEntriesThrough(t *testing.T) {
	label := "soroauth-envelope-source-account"
	addressEntry := entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 3)
	sourceEntry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 4)

	envelope := transactionEnvelope(t, invokeOperation(t, addressEntry, sourceEntry))

	signed, err := AuthorizeEnvelope(context.Background(), envelope,
		[]Signer{NewEd25519Signer(testKeypair(t, label))}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEnvelope: %v", err)
	}

	entries, err := EnvelopeEntries(signed)
	if err != nil {
		t.Fatalf("reading the signed envelope's entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	assertEntrySignatureVerifies(t, entries[0].Entry, label, testValidUntilLedger, network.TestNetworkPassphrase)

	want, err := xdr.MarshalBase64(sourceEntry)
	if err != nil {
		t.Fatalf("encoding the source-account entry: %v", err)
	}
	got, err := xdr.MarshalBase64(entries[1].Entry)
	if err != nil {
		t.Fatalf("encoding the returned source-account entry: %v", err)
	}
	if got != want {
		t.Error("a source-account entry was modified, want it passed through unchanged")
	}
}

func TestAuthorizeEnvelopeRejectsAnUnsignedEntry(t *testing.T) {
	present := "soroauth-envelope-present"
	absent := "soroauth-envelope-absent"

	envelope := transactionEnvelope(t,
		invokeOperation(t, entryForSigner(t, present, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)),
		invokeOperation(t, entryForSigner(t, absent, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2)),
	)

	signed, err := AuthorizeEnvelope(context.Background(), envelope,
		[]Signer{NewEd25519Signer(testKeypair(t, present))}, testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrMissingSigner)
	}
	if !strings.Contains(err.Error(), testKeypair(t, absent).Address()) {
		t.Errorf("the error %q does not name the entry with no signer", err)
	}
	if !strings.Contains(err.Error(), "operation 1") {
		t.Errorf("the error %q does not name the operation the entry is in", err)
	}

	if !reflect.DeepEqual(signed, xdr.TransactionEnvelope{}) {
		t.Error("a failed AuthorizeEnvelope returned a partial envelope, want the zero value")
	}
}

func TestAuthorizeEnvelopeRejectsAnEnvelopeWithNoInvokeOperation(t *testing.T) {
	_, err := AuthorizeEnvelope(context.Background(), transactionEnvelope(t, paymentOperation(t)), nil,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrNoInvokeOperation) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrNoInvokeOperation)
	}
}

func TestAuthorizeEnvelopeHonoursContextCancellation(t *testing.T) {
	label := "soroauth-envelope-cancelled"
	envelope := transactionEnvelope(t, invokeOperation(t,
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)))

	// The probe fails the test if Sign is reached at all, so this covers the
	// structural validation and the copy as well as the signing loop.
	_, err := AuthorizeEnvelope(cancelledContext(t), envelope, []Signer{mustNotSign(t, testKeypair(t, label).Address())},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want it to wrap %v", err, context.Canceled)
	}
}

func TestEnvelopePayloadsMatchTheEntries(t *testing.T) {
	addressEntry := entryForSigner(t, "soroauth-envelope-payload", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 6)
	sourceEntry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 7)

	envelope := transactionEnvelope(t,
		invokeOperation(t, addressEntry),
		paymentOperation(t),
		invokeOperation(t, sourceEntry),
	)

	payloads, err := EnvelopePayloads(envelope, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("EnvelopePayloads: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("got %d payloads, want 2", len(payloads))
	}

	if payloads[0].OperationIndex != 0 || payloads[0].EntryIndex != 0 || payloads[0].SourceAccount {
		t.Errorf("the first payload is reported as operation %d entry %d source_account=%v",
			payloads[0].OperationIndex, payloads[0].EntryIndex, payloads[0].SourceAccount)
	}

	wantPreimage, err := Preimage(addressEntry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the expected preimage: %v", err)
	}
	wantPayload, err := Payload(wantPreimage)
	if err != nil {
		t.Fatalf("hashing the expected preimage: %v", err)
	}
	gotPreimage, err := xdr.MarshalBase64(payloads[0].Preimage)
	if err != nil {
		t.Fatalf("encoding the reported preimage: %v", err)
	}
	encodedWant, err := xdr.MarshalBase64(wantPreimage)
	if err != nil {
		t.Fatalf("encoding the expected preimage: %v", err)
	}
	if gotPreimage != encodedWant {
		t.Error("the reported preimage is not the entry's own preimage")
	}
	if payloads[0].Payload != wantPayload {
		t.Error("the reported payload hash is not the entry's own payload")
	}

	if payloads[1].OperationIndex != 2 || payloads[1].EntryIndex != 0 || !payloads[1].SourceAccount {
		t.Errorf("the second payload is reported as operation %d entry %d source_account=%v, want operation 2 entry 0 source_account=true",
			payloads[1].OperationIndex, payloads[1].EntryIndex, payloads[1].SourceAccount)
	}
	if payloads[1].Payload != ([32]byte{}) {
		t.Error("a source-account entry was given a payload hash, but it has none of its own")
	}
}

func TestEnvelopePayloadsRejectsAnEnvelopeWithNoInvokeOperation(t *testing.T) {
	_, err := EnvelopePayloads(transactionEnvelope(t, paymentOperation(t)), testValidUntilLedger, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrNoInvokeOperation) {
		t.Fatalf("got %v, want it to wrap %v", err, ErrNoInvokeOperation)
	}
}
