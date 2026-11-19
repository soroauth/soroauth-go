package soroauth

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// NodeVisitor is called once for each credential node in a delegate tree,
// in depth-first pre-order. It receives the node's address and the payload
// that must be signed, and returns the signature ScVal to write onto the
// node. An error from the visitor cancels the walk.
//
// The visit order is documented and stable: the top-level node first, then
// each delegate and its nested delegates recursively, the same order
// credentialNodes returns.
type NodeVisitor func(ctx context.Context, address string, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)

// StreamingSignOption configures StreamingSign.
type StreamingSignOption func(*streamingSignConfig)

type streamingSignConfig struct {
	allowResign bool
}

// StreamingAllowResign permits overwriting existing signatures during
// streaming sign, mirroring AllowResign for AuthorizeEntry.
func StreamingAllowResign() StreamingSignOption {
	return func(c *streamingSignConfig) {
		c.allowResign = true
	}
}

// StreamingSign signs a delegate tree one node at a time, calling visitor
// for each credential node instead of materialising every signature up front.
// Memory stays flat as the tree grows because only one node's signing context
// is live at a time.
//
// The entry is deep-copied before any work. Cancellation is honoured between
// nodes: if the context is cancelled mid-walk, the entry is not returned
// partly signed — the error path returns the zero entry. The visitor is never
// called after cancellation.
//
// Output bytes are identical to AuthorizeEntry for every golden vector,
// proven by test.
func StreamingSign(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	visitor NodeVisitor,
	validUntilLedger uint32,
	networkPassphrase string,
	opts ...StreamingSignOption,
) (xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}

	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		copied, err := xdrcopy.Copy(entry)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
		}
		return copied, nil
	}

	var config streamingSignConfig
	for _, opt := range opts {
		opt(&config)
	}

	if visitor == nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", ErrMissingSigner)
	}

	if validUntilLedger == 0 {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
			"soroauth: streaming sign: expiration ledger is zero: %w", ErrInvalidExpiration)
	}

	signed, err := xdrcopy.Copy(entry)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}

	isDelegates := signed.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates
	if isDelegates {
		if err := ValidateDelegateOrder(signed); err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
		}
	}

	nodes, err := credentialNodes(&signed)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}

	if !config.allowResign {
		for _, node := range nodes {
			if isSigned(*node.signature) {
				addr, _ := formatAddressBytes(node.encoded)
				return xdr.SorobanAuthorizationEntry{}, fmt.Errorf(
					"soroauth: streaming sign: %s: %w", addr, ErrAlreadySigned)
			}
		}
	}

	preimage, err := Preimage(signed, validUntilLedger, networkPassphrase)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}

	payload, err := Payload(preimage)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}

	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
		}

		address, err := formatAddressBytes(node.encoded)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
		}

		sig, err := visitor(ctx, address, preimage, payload)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: node %s: %w", address, err)
		}

		*node.signature = sig
	}

	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: streaming sign: %w", err)
	}
	credentials.SignatureExpirationLedger = xdr.Uint32(validUntilLedger)

	return signed, nil
}
