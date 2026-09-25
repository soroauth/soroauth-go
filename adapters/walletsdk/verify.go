package walletsdk

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// VerifyEntry checks that every credential node in entry that names kp's
// address carries a valid signature by kp over the payload the entry signs.
//
// soroauth has no verification arm: it produces signatures, and Inspect reports
// which nodes carry one, but nothing checks that a stored signature is the one
// the key would produce. That is what this does, and it is the check a wallet
// wants before submitting an entry it did not just sign itself — one coming back
// from a co-signer, or one read back off disk.
//
// The payload is recomputed from the entry and validUntilLedger through
// soroauth.Preimage and soroauth.Payload, so there is no way to verify against a
// number other than the one the entry commits to. On the source-account arm
// there is no payload of its own and Preimage refuses with
// soroauth.ErrSourceAccountCredentials: the envelope's own signature covers that
// arm, and this package does not verify envelope signatures.
//
// A node left unsigned fails with ErrUnreadableSignature, a node whose stored
// public key is not kp's fails with ErrSignatureNotByKey, and an entry naming no
// node for kp's address fails with ErrSignatureNotFound. Every matching node is
// checked, so a tree where one node was filled in and another was not is a
// failure.
func VerifyEntry(
	entry xdr.SorobanAuthorizationEntry,
	kp Keypair,
	validUntilLedger uint32,
	networkPassphrase string,
) error {
	if isNilKeypair(kp) {
		return fmt.Errorf("walletsdk: verify entry: %w", soroauth.ErrMissingSigner)
	}

	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		return fmt.Errorf("walletsdk: verify entry: %w", err)
	}

	preimage, err := soroauth.Preimage(entry, validUntilLedger, networkPassphrase)
	if err != nil {
		return fmt.Errorf("walletsdk: verify entry: %w", err)
	}
	payload, err := soroauth.Payload(preimage)
	if err != nil {
		return fmt.Errorf("walletsdk: verify entry: %w", err)
	}

	nodes, err := signatureNodes(entry, kp.Address())
	if err != nil {
		return fmt.Errorf("walletsdk: verify entry: %w", err)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("walletsdk: verify entry: %s: %w", kp.Address(), ErrSignatureNotFound)
	}

	for i, node := range nodes {
		publicKey, signature, err := parseAccountSignature(node)
		if err != nil {
			return fmt.Errorf("walletsdk: verify entry: node %d: %w", i, err)
		}
		if !bytes.Equal(publicKey, raw) {
			return fmt.Errorf("walletsdk: verify entry: node %d: stored public key %x is not %s's: %w",
				i, publicKey, kp.Address(), ErrSignatureNotByKey)
		}
		if err := kp.Verify(payload[:], signature); err != nil {
			return fmt.Errorf("walletsdk: verify entry: node %d: %s: %w",
				i, kp.Address(), ErrSignatureNotByKey)
		}
	}
	return nil
}

// VerifyEnvelope checks every signature in env that kp is responsible for.
//
// It is VerifyEntry over each entry soroauth.EnvelopeEntries reports, skipping
// the two cases that have nothing to verify: source-account entries, which the
// envelope's own signature covers, and entries that name no node for kp's
// address, which are somebody else's to sign. An entry that does name the
// address at some node must verify at every one of them, or the call fails
// naming the operation and entry.
//
// An envelope with no invokeHostFunction operation is refused with
// soroauth.ErrNoInvokeOperation, the same as soroauth.EnvelopeEntries.
func VerifyEnvelope(
	env xdr.TransactionEnvelope,
	kp Keypair,
	validUntilLedger uint32,
	networkPassphrase string,
) error {
	entries, err := soroauth.EnvelopeEntries(env)
	if err != nil {
		return fmt.Errorf("walletsdk: verify envelope: %w", err)
	}

	for _, located := range entries {
		if located.Entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			continue
		}

		err := VerifyEntry(located.Entry, kp, validUntilLedger, networkPassphrase)
		if errors.Is(err, ErrSignatureNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("walletsdk: verify envelope: operation %d entry %d: %w",
				located.OperationIndex, located.EntryIndex, err)
		}
	}
	return nil
}
