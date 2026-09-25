package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// EnvelopeEntry locates one authorization entry inside a transaction envelope.
//
// OperationIndex is the position of the invokeHostFunction operation that
// carries the entry. For a fee-bump envelope it indexes the operations of the
// inner transaction, because a fee-bump transaction has none of its own and it
// is the inner transaction whose authorization entries the host checks.
//
// EntryIndex is the position of the entry within that operation's auth vector.
type EnvelopeEntry struct {
	OperationIndex int
	EntryIndex     int

	// Entry is the authorization entry itself. It aliases the envelope it was
	// read from; it is for reading and for passing to the entry-shaped
	// functions, all of which copy before writing.
	Entry xdr.SorobanAuthorizationEntry
}

// EnvelopeEntryInfo is one entry's structural summary together with where in
// the envelope it sits.
//
// EntryInfo is embedded, so the JSON form is the EntryInfo object with
// operation_index and entry_index added to it.
type EnvelopeEntryInfo struct {
	OperationIndex int `json:"operation_index"`
	EntryIndex     int `json:"entry_index"`

	EntryInfo
}

// EnvelopePayload is what a signer would have to approve for one entry of an
// envelope.
//
// SourceAccount is true when the entry's credentials arm is
// SOROBAN_CREDENTIALS_SOURCE_ACCOUNT. Such an entry has no payload of its own -
// the envelope's own signature covers it — so Preimage and Payload are left
// zero and the entry is reported rather than quietly dropped, which is the
// same reading AuthorizeEntry and AuthorizeAll take.
type EnvelopePayload struct {
	OperationIndex int

	EntryIndex int

	SourceAccount bool

	Preimage xdr.HashIdPreimage

	Payload [32]byte
}

// envelopeOperations returns the operations of the transaction an envelope
// carries, following a fee-bump envelope into the inner transaction that holds
// the operations the host will actually execute.
//
// xdr.TransactionEnvelope.Operations() does the same for the common cases, but
// it panics on an unrecognised envelope type and on a fee-bump envelope whose
// inner arm is empty (xdr/transaction_envelope.go:226-238). A panic is not one
// of the refusals this library promises, so the unwrapping is done here where
// every failure mode can be an error.
func envelopeOperations(env xdr.TransactionEnvelope) ([]xdr.Operation, error) {
	switch env.Type {
	case xdr.EnvelopeTypeEnvelopeTypeTx:
		if env.V1 == nil {
			return nil, fmt.Errorf("the envelope_type_tx arm is empty")
		}
		return env.V1.Tx.Operations, nil

	case xdr.EnvelopeTypeEnvelopeTypeTxV0:
		if env.V0 == nil {
			return nil, fmt.Errorf("the envelope_type_tx_v0 arm is empty")
		}
		return env.V0.Tx.Operations, nil

	case xdr.EnvelopeTypeEnvelopeTypeTxFeeBump:
		if env.FeeBump == nil {
			return nil, fmt.Errorf("the envelope_type_tx_fee_bump arm is empty")
		}
		inner := env.FeeBump.Tx.InnerTx
		if inner.Type != xdr.EnvelopeTypeEnvelopeTypeTx {
			return nil, fmt.Errorf("fee-bump inner transaction is %s, want envelope_type_tx", inner.Type)
		}
		if inner.V1 == nil {
			return nil, fmt.Errorf("the fee-bump inner envelope_type_tx arm is empty")
		}
		return inner.V1.Tx.Operations, nil

	default:
		return nil, ErrUnsupportedEnvelope
	}
}

// EnvelopeEntries returns every authorization entry carried by a transaction
// envelope, in operation order, each with the operation index and entry index
// it came from.
//
// A fee-bump envelope is read through to its inner transaction, because that is
// where the invokeHostFunction operation and its auth vector live. The entries
// a wallet has to sign are the inner transaction's, and the operation index
// reported is an index into the inner transaction's operations, since a
// fee-bump transaction has none of its own (CAP-15).
//
// An envelope with no invokeHostFunction operation at all is refused with
// ErrNoInvokeOperation rather than reported as an empty result. An envelope
// that has an invokeHostFunction operation which carries no authorization
// entries is not an error: it returns an empty slice, because there genuinely
// is nothing there. The distinction matters, because a caller that reads an
// empty result as "nothing to do" would otherwise submit a transaction whose
// entries it never authorized.
func EnvelopeEntries(env xdr.TransactionEnvelope) ([]EnvelopeEntry, error) {
	operations, err := envelopeOperations(env)
	if err != nil {
		return nil, fmt.Errorf("soroauth: envelope entries: %w", err)
	}

	var entries []EnvelopeEntry
	invokeOperations := 0
	for i := range operations {
		body := operations[i].Body
		if body.Type != xdr.OperationTypeInvokeHostFunction {
			continue
		}
		if body.InvokeHostFunctionOp == nil {
			return nil, fmt.Errorf("soroauth: envelope entries: operation %d: the invokeHostFunction arm is empty", i)
		}
		invokeOperations++

		auth := body.InvokeHostFunctionOp.Auth
		for j := range auth {
			entries = append(entries, EnvelopeEntry{
				OperationIndex: i,
				EntryIndex:     j,
				Entry:          auth[j],
			})
		}
	}

	if invokeOperations == 0 {
		return nil, fmt.Errorf("soroauth: envelope entries: %w", ErrNoInvokeOperation)
	}
	return entries, nil
}

// InspectEnvelope reports the structure of every authorization entry an
// envelope carries, each with the operation index and entry index it came
// from.
//
// It is Inspect applied entry by entry, so what it reports — and what it
// deliberately does not — is described there. The one thing it adds is
// position: a caller inspecting an envelope needs to know which entry belongs
// to which operation, because that is what it has to line up with when it
// writes a signed entry back.
//
// A fee-bump envelope is read through to its inner transaction, so the entries
// reported are the ones the host will check, and the operation indices are
// indices into the inner transaction.
//
// Like Inspect, this is structural only: it says which contract and function
// each entry authorizes, not what that call does.
func InspectEnvelope(env xdr.TransactionEnvelope) ([]EnvelopeEntryInfo, error) {
	entries, err := EnvelopeEntries(env)
	if err != nil {
		return nil, fmt.Errorf("soroauth: inspect envelope: %w", err)
	}

	infos := make([]EnvelopeEntryInfo, 0, len(entries))
	for _, located := range entries {
		info, err := Inspect(located.Entry)
		if err != nil {
			return nil, fmt.Errorf("soroauth: inspect envelope: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}
		infos = append(infos, EnvelopeEntryInfo{
			OperationIndex: located.OperationIndex,
			EntryIndex:     located.EntryIndex,
			EntryInfo:      info,
		})
	}
	return infos, nil
}

// AuthorizeEnvelope signs every authorization entry in a transaction envelope
// and returns a new envelope, leaving the input untouched.
//
// It is AuthorizeAll applied to each invokeHostFunction operation in turn:
// every address-arm entry must have a signer whose address appears in it, or
// the whole call fails with ErrMissingSigner naming the entry, and nothing is
// returned. Source-account entries pass through unchanged, so a caller can hand
// over exactly what simulation returned without sorting the entries by arm
// first. What "signed" means for a delegates entry, including the nodes a
// missing signer leaves unsigned, is described on AuthorizeAll.
//
// A fee-bump envelope is read through to its inner transaction; the entries
// that get signed are the inner transaction's, which is where the host looks
// for them.
//
// Only the authorization entries are signed. The envelope's own signatures -
// the source account's, and a fee-bump fee source's — are not this library's
// to produce: soroauth signs HashIdPreimage values, not transaction envelopes,
// so the caller signs the returned envelope with its own key the same way it
// signs any other transaction.
//
// The two-pass simulation requirement is not hidden. Signing entries changes
// what the transaction costs to run, so the caller must simulate again in
// enforce mode after this returns and submit what that second pass produced: a
// transaction assembled from the record-mode simulation carries too small a
// resource fee and will be rejected. That step belongs to the caller's RPC
// client, which this library does not wrap.
//
// ctx is checked before any work, including the structural validation, so a
// cancelled context fails closed even on an envelope that holds nothing to
// sign. The same ctx is passed unchanged to AuthorizeAll and from there to
// Signer.Sign.
func AuthorizeEnvelope(
	ctx context.Context,
	env xdr.TransactionEnvelope,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
) (xdr.TransactionEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return xdr.TransactionEnvelope{}, fmt.Errorf("soroauth: authorize envelope: %w", err)
	}

	// Validated before anything is copied or signed: an envelope with no
	// invoke operation is a caller error, not an empty success.
	if _, err := EnvelopeEntries(env); err != nil {
		return xdr.TransactionEnvelope{}, fmt.Errorf("soroauth: authorize envelope: %w", err)
	}

	signed, err := xdrcopy.Copy(env)
	if err != nil {
		return xdr.TransactionEnvelope{}, fmt.Errorf("soroauth: authorize envelope: %w", err)
	}

	operations, err := envelopeOperations(signed)
	if err != nil {
		return xdr.TransactionEnvelope{}, fmt.Errorf("soroauth: authorize envelope: %w", err)
	}

	for i := range operations {
		body := operations[i].Body
		if body.Type != xdr.OperationTypeInvokeHostFunction || body.InvokeHostFunctionOp == nil {
			continue
		}

		auth, err := AuthorizeAll(ctx, body.InvokeHostFunctionOp.Auth, signers, validUntilLedger, networkPassphrase)
		if err != nil {
			return xdr.TransactionEnvelope{}, fmt.Errorf("soroauth: authorize envelope: operation %d: %w", i, err)
		}

		// The slice header was copied out of the operation above, so the new
		// one has to be written back through it. InvokeHostFunctionOp is a
		// pointer, so this writes into the copied envelope and not the
		// caller's.
		body.InvokeHostFunctionOp.Auth = auth
	}

	return signed, nil
}

// EnvelopePayloads returns the preimage and payload hash of every authorization
// entry an envelope carries, in operation order, each with the position it came
// from.
//
// This is the read-only half of the signing flow, for the callers that never
// hand soroauth a key: an offline signer deciding what to approve, a hardware
// device being audited, a verification pass checking that a signature commits
// to the entry it is stored on. Preimage and Payload are exactly what
// AuthorizeEntry signs over, computed from the entry rather than from anything
// the caller passed alongside it.
//
// Entries on the source-account arm are reported with SourceAccount set and
// zero Preimage and Payload, because they have no payload of their own; see
// Preimage for why. An envelope with no invokeHostFunction operation is refused
// with ErrNoInvokeOperation, the same way EnvelopeEntries refuses it.
func EnvelopePayloads(
	env xdr.TransactionEnvelope,
	validUntilLedger uint32,
	networkPassphrase string,
) ([]EnvelopePayload, error) {
	entries, err := EnvelopeEntries(env)
	if err != nil {
		return nil, fmt.Errorf("soroauth: envelope payloads: %w", err)
	}

	payloads := make([]EnvelopePayload, 0, len(entries))
	for _, located := range entries {
		payload := EnvelopePayload{
			OperationIndex: located.OperationIndex,
			EntryIndex:     located.EntryIndex,
		}

		if located.Entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			payload.SourceAccount = true
			payloads = append(payloads, payload)
			continue
		}

		preimage, err := Preimage(located.Entry, validUntilLedger, networkPassphrase)
		if err != nil {
			return nil, fmt.Errorf("soroauth: envelope payloads: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}
		hash, err := Payload(preimage)
		if err != nil {
			return nil, fmt.Errorf("soroauth: envelope payloads: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}

		payload.Preimage = preimage
		payload.Payload = hash
		payloads = append(payloads, payload)
	}
	return payloads, nil
}
