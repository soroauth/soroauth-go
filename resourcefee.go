package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// SignatureSizeEstimate holds the per-entry size analysis for a signing operation.
//
// The byte delta is exact: it is derived entirely from the XDR lengths of the
// placeholder and signature values and does not depend on any network setting.
// The fee formula is a function of that delta and a network parameter that this
// library cannot know offline (the write fee per byte of ledger data). It is
// expressed as:
//
//	fee_stroops = NetDeltaBytes × fee_per_byte
//
// where fee_per_byte comes from the most recent SimulateTransaction response or
// from the network configuration ledger entry. The write fee is one component
// of the total resource fee; the CPU and ledger-access components do not change
// with signature size and are not represented here.
//
// This is cited from the Stellar protocol resource-fee specification:
// https://github.com/stellar/stellar-protocol/blob/master/core/cap-0046-04.md
// (specifically the "write_fee_per_1kb" / "fee_write_1kb" parameter).
type SignatureSizeEstimate struct {
	// UnsignedNodes is the number of credential nodes that will receive a
	// signature: nodes whose current signature is ScvVoid or an empty ScvVec.
	// This is 0 for a source-account entry.
	UnsignedNodes int

	// PlaceholderBytes is the total XDR size of all placeholder values that
	// will be replaced, summed across every unsigned node. It is subtracted from
	// SignatureBytes to yield NetDeltaBytes.
	PlaceholderBytes int

	// SignatureBytes is the total XDR size that all signatures will occupy,
	// assuming every unsigned node receives a signature of the given shape.
	// This is exact.
	SignatureBytes int

	// NetDeltaBytes is the exact net increase in XDR bytes: SignatureBytes −
	// PlaceholderBytes. It is the value to multiply by the network's
	// fee_write_1kb / 1024 to obtain the write-fee component of the resource fee.
	NetDeltaBytes int
}

// FeeEstimate computes the write-fee component of the resource fee that the
// network will charge for the additional bytes, given the network's current
// write fee per byte.
//
// feePerByte should be:
//
//	networkConfig.feeWrite1KB / 1024
//
// or equivalently, the "fee_write_1kb" value from the network config ledger
// entry divided by 1024. It is available from SimulateTransaction's
// MinResourceFee or from the network configuration.
//
// The result is in stroops. It is a minimum estimate: the enforcing pass will
// also charge for CPU instructions and ledger accesses that this library
// cannot predict without running the contract.
//
// A feePerByte of 0 returns 0 without error; callers who do not have the
// network config can still use the byte delta directly.
func (e SignatureSizeEstimate) FeeEstimate(feePerByte int64) int64 {
	return int64(e.NetDeltaBytes) * feePerByte
}

// EstimateEntrySignatureDelta estimates the XDR size change when every
// unsigned credential node in entry is filled with a signature of the given shape.
//
// signatureShape is an example ScVal whose marshalled length is representative
// of every signature that will be written. For a classic ed25519 single-signer
// built by NewEd25519Signer or Ed25519SignatureScVal, the shape is identical for
// every signing key (all ed25519 signatures are 64 bytes and all G… addresses
// are 32 bytes), so any valid example works. For a multi-signer the shape must
// carry the right number of keys. For a custom account the caller supplies
// whatever ScVal that account's __check_auth decodes.
//
// The byte count is exact for every unsigned node of the given entry: a node
// that already holds a signature (non-Void, non-empty-Vec) is not counted,
// because AuthorizeEntry would not overwrite it unless AllowResign is passed,
// and AllowResign replaces without adding.
//
// Source-account entries carry no signature of their own. EstimateEntrySignatureDelta
// returns a zero estimate for them, not an error.
func EstimateEntrySignatureDelta(entry xdr.SorobanAuthorizationEntry, signatureShape xdr.ScVal) (SignatureSizeEstimate, error) {
	// Source-account entries have no signature node.
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return SignatureSizeEstimate{}, nil
	}

	sigBytes, err := signatureShape.MarshalBinary()
	if err != nil {
		return SignatureSizeEstimate{}, fmt.Errorf("soroauth: estimate entry signature delta: marshal signature shape: %w", err)
	}
	sigLen := len(sigBytes)

	// Enumerate unsigned nodes.
	nodes, err := credentialNodes(&entry)
	if err != nil {
		return SignatureSizeEstimate{}, fmt.Errorf("soroauth: estimate entry signature delta: %w", err)
	}

	var est SignatureSizeEstimate
	for _, node := range nodes {
		if isSigned(*node.signature) {
			continue
		}
		placeholderBytes, err := node.signature.MarshalBinary()
		if err != nil {
			return SignatureSizeEstimate{}, fmt.Errorf("soroauth: estimate entry signature delta: marshal placeholder: %w", err)
		}
		est.UnsignedNodes++
		est.PlaceholderBytes += len(placeholderBytes)
		est.SignatureBytes += sigLen
	}

	est.NetDeltaBytes = est.SignatureBytes - est.PlaceholderBytes
	return est, nil
}

// Ed25519SignatureByteSize is the exact number of XDR bytes a classic single-key
// ed25519 signature occupies: a ScvVec containing one ScvMap with two entries —
// "public_key" (32 bytes) and "signature" (64 bytes).
//
// This constant exists for callers who want to avoid constructing a dummy
// signature just to measure it. It is verified in TestEd25519SignatureByteSize
// against an actual ScVal built by Ed25519SignatureScVal.
//
// The encoding is (all values big-endian per RFC 4506):
//
//	ScvVec discriminant:            4 bytes
//	  ScVec presence flag:          4 bytes (1 = present)
//	  ScVec array length:           4 bytes (n=1)
//	  ScvMap discriminant:          4 bytes
//	    ScMap presence flag:        4 bytes (1 = present)
//	    ScMap array length:         4 bytes (n=2)
//	    entry 0 key ("public_key"): 4 (ScvSymbol) + 4 (len=10) + 12 (10 chars padded)
//	    entry 0 val (32 bytes):     4 (ScvBytes) + 4 (len=32) + 32
//	    entry 1 key ("signature"):  4 (ScvSymbol) + 4 (len=9)  + 12 (9 chars padded)
//	    entry 1 val (64 bytes):     4 (ScvBytes) + 4 (len=64) + 64
//	Total:                          176 bytes
const Ed25519SignatureByteSize = 176
