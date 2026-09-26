package readmesnippets

import (
	"context"
	"net/http"
	"os"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/remote"
)

// RemoteSigner is never called; it exists only to be compiled and to back the
// README's "Remote signing over HTTP" section. Its parameters stand in for the
// values a real caller already has: the entry simulation returned, the
// expiration to sign over, and the key the reference server holds.
func RemoteSigner(ctx context.Context, unsigned xdr.SorobanAuthorizationEntry, validUntil uint32, signerKey *keypair.Full) (xdr.SorobanAuthorizationEntry, error) {
	// snippet:start remotesigner
	server := remote.NewServer(soroauth.NewEd25519Signer(signerKey))
	server.Approver = remote.LogApprover(os.Stderr) // record what is approved
	http.Handle(remote.Path, server)

	signer := remote.NewSigner("http://127.0.0.1:8080", signerKey.Address())
	return soroauth.AuthorizeEntry(ctx, unsigned, signer, validUntil, network.TestNetworkPassphrase)
	// snippet:end remotesigner
}
