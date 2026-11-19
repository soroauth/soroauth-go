package soroauth

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestEd25519SignatureByteSize verifies the documented constant against
// an actual ScVal built by Ed25519SignatureScVal.
func TestEd25519SignatureByteSize(t *testing.T) {
	// Use the same label entryForArm uses so the keypair address matches the entry.
	kp := testKeypair(t, "soroauth-preimage-signer")
	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	// Ed25519 signatures are always 64 bytes.
	fakeSig := make([]byte, 64)
	scval, err := Ed25519SignatureScVal(raw, fakeSig)
	if err != nil {
		t.Fatalf("Ed25519SignatureScVal: %v", err)
	}
	encoded, err := scval.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(encoded) != Ed25519SignatureByteSize {
		t.Errorf("Ed25519SignatureByteSize = %d, actual encoded size = %d",
			Ed25519SignatureByteSize, len(encoded))
	}
}

// TestEstimateEntrySignatureDelta_SourceAccount checks that source-account
// entries yield a zero estimate.
func TestEstimateEntrySignatureDelta_SourceAccount(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 0)
	kp := testKeypair(t, "soroauth-preimage-signer")
	raw, _ := rawEd25519Key(kp.Address())
	sigShape, _ := Ed25519SignatureScVal(raw, make([]byte, 64))

	est, err := EstimateEntrySignatureDelta(entry, sigShape)
	if err != nil {
		t.Fatalf("EstimateEntrySignatureDelta: %v", err)
	}
	if est.UnsignedNodes != 0 || est.PlaceholderBytes != 0 || est.SignatureBytes != 0 || est.NetDeltaBytes != 0 {
		t.Errorf("source-account entry: expected zero estimate, got %+v", est)
	}
}

// TestEstimateEntrySignatureDelta_AddressArms checks the legacy and v2 arms:
// the predicted NetDeltaBytes matches the actual change in marshalled entry size.
func TestEstimateEntrySignatureDelta_AddressArms(t *testing.T) {
	// Use the same label entryForArm uses ("soroauth-preimage-signer") so the
	// signer's address matches the credential node in the entry.
	kp := testKeypair(t, "soroauth-preimage-signer")

	tests := []struct {
		name         string
		arm          xdr.SorobanCredentialsType
		wantUnsigned int
	}{
		{"legacy", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1},
		{"address_v2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1},
	}

	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	fakeSig := make([]byte, 64)
	sigShape, err := Ed25519SignatureScVal(raw, fakeSig)
	if err != nil {
		t.Fatalf("Ed25519SignatureScVal: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsigned := entryForArm(t, tt.arm, 42)

			est, err := EstimateEntrySignatureDelta(unsigned, sigShape)
			if err != nil {
				t.Fatalf("EstimateEntrySignatureDelta: %v", err)
			}
			if est.UnsignedNodes != tt.wantUnsigned {
				t.Errorf("UnsignedNodes = %d, want %d", est.UnsignedNodes, tt.wantUnsigned)
			}

			// Sign the entry so we can measure the actual size change.
			signed, err := AuthorizeEntry(context.Background(), unsigned, NewEd25519Signer(kp), testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry: %v", err)
			}

			unsignedBytes, err := unsigned.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal unsigned: %v", err)
			}
			signedBytes, err := signed.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal signed: %v", err)
			}

			actualDelta := len(signedBytes) - len(unsignedBytes)
			if est.NetDeltaBytes != actualDelta {
				t.Errorf("NetDeltaBytes = %d, actual signed-entry delta = %d (unsigned=%d, signed=%d)",
					est.NetDeltaBytes, actualDelta, len(unsignedBytes), len(signedBytes))
			}

			// FeeEstimate with feePerByte=5 should be 5*delta.
			const feePerByte = int64(5)
			wantFee := feePerByte * int64(actualDelta)
			if got := est.FeeEstimate(feePerByte); got != wantFee {
				t.Errorf("FeeEstimate(%d) = %d, want %d", feePerByte, got, wantFee)
			}

			// FeeEstimate with 0 returns 0.
			if got := est.FeeEstimate(0); got != 0 {
				t.Errorf("FeeEstimate(0) = %d, want 0", got)
			}
		})
	}
}

// TestEstimateEntrySignatureDelta_Delegates checks that the delegates arm counts
// every unsigned node (top-level + each delegate) and that the total byte delta
// matches the actual change after signing all nodes.
func TestEstimateEntrySignatureDelta_Delegates(t *testing.T) {
	kpSigner := testKeypair(t, "soroauth-preimage-signer")
	kpDelegate := testKeypair(t, "soroauth-preimage-delegate")

	unsigned := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)

	raw, err := rawEd25519Key(kpSigner.Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	fakeSig := make([]byte, 64)
	sigShape, err := Ed25519SignatureScVal(raw, fakeSig)
	if err != nil {
		t.Fatalf("Ed25519SignatureScVal: %v", err)
	}

	est, err := EstimateEntrySignatureDelta(unsigned, sigShape)
	if err != nil {
		t.Fatalf("EstimateEntrySignatureDelta: %v", err)
	}
	// entryForArm delegates arm: top-level (Void or empty-vec) + 1 delegate (Void).
	if est.UnsignedNodes != 2 {
		t.Errorf("UnsignedNodes = %d, want 2", est.UnsignedNodes)
	}

	// Sign both nodes.
	signed, err := AuthorizeEntry(context.Background(), unsigned, NewEd25519Signer(kpSigner), testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry top-level: %v", err)
	}
	signed, err = AuthorizeEntry(context.Background(), signed, NewEd25519Signer(kpDelegate), testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry delegate: %v", err)
	}

	unsignedBytes, err := unsigned.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal unsigned: %v", err)
	}
	signedBytes, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal signed: %v", err)
	}

	actualDelta := len(signedBytes) - len(unsignedBytes)
	if est.NetDeltaBytes != actualDelta {
		t.Errorf("delegates: NetDeltaBytes = %d, actual delta = %d", est.NetDeltaBytes, actualDelta)
	}
}

// TestEstimateEntrySignatureDelta_AlreadySigned checks that nodes that are
// already signed are not counted.
func TestEstimateEntrySignatureDelta_AlreadySigned(t *testing.T) {
	kp := testKeypair(t, "soroauth-preimage-signer")
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	// Pre-sign the entry.
	signed, err := AuthorizeEntry(context.Background(), entry, NewEd25519Signer(kp), testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	raw, _ := rawEd25519Key(kp.Address())
	sigShape, _ := Ed25519SignatureScVal(raw, make([]byte, 64))

	est, err := EstimateEntrySignatureDelta(signed, sigShape)
	if err != nil {
		t.Fatalf("EstimateEntrySignatureDelta on already-signed entry: %v", err)
	}
	if est.UnsignedNodes != 0 {
		t.Errorf("already-signed entry: UnsignedNodes = %d, want 0", est.UnsignedNodes)
	}
	if est.NetDeltaBytes != 0 {
		t.Errorf("already-signed entry: NetDeltaBytes = %d, want 0", est.NetDeltaBytes)
	}
}

// TestEstimateEntrySignatureDelta_CustomShape tests that the function handles
// signature shapes other than classic ed25519.
func TestEstimateEntrySignatureDelta_CustomShape(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	// A custom ScvBytes shape (e.g. a passkey signature).
	customSig := xdr.ScBytes(make([]byte, 96))
	sigShape := xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &customSig}

	est, err := EstimateEntrySignatureDelta(entry, sigShape)
	if err != nil {
		t.Fatalf("EstimateEntrySignatureDelta with custom shape: %v", err)
	}
	if est.UnsignedNodes != 1 {
		t.Errorf("UnsignedNodes = %d, want 1", est.UnsignedNodes)
	}

	// Verify the byte delta is non-zero and positive.
	if est.NetDeltaBytes <= 0 {
		t.Errorf("NetDeltaBytes = %d, want > 0", est.NetDeltaBytes)
	}

	// Verify the signature bytes equal the shape's encoded length.
	shapeEncoded, err := sigShape.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal custom shape: %v", err)
	}
	if est.SignatureBytes != len(shapeEncoded) {
		t.Errorf("SignatureBytes = %d, want %d", est.SignatureBytes, len(shapeEncoded))
	}
}
