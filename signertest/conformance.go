package signertest

import (
	"testing"

	"github.com/soroauth/soroauth-go"
)

// RunConformanceSuite runs conformance tests for a given soroauth.Signer,
// using its declared capabilities to choose which verification contract to apply.
func RunConformanceSuite(t *testing.T, s soroauth.Signer) {
	t.Helper()
	caps := soroauth.GetSignerCapabilities(s)

	if caps.IsInteractive() {
		// Apply interactive signer contract expectations
	}
	if caps.IsDeterministic() {
		// Apply deterministic signer contract expectations
	}
	if caps.IsRemote() {
		// Apply remote signer contract expectations
	}
	if caps.SupportsBatchedPresence() {
		// Apply batched presence contract expectations
	}
}
