// Package pkcs11 signs Soroban authorization entries with an Ed25519 key
// held in any PKCS#11 token: on-premise HSMs, smartcards such as YubiKey PIV,
// or SoftHSM2 for local testing.
//
// # Why a separate module
//
// CGO is the reason this adapter cannot live in the root module. Most PKCS#11
// bindings (including github.com/miekg/pkcs11, the most widely used one) wrap
// the PKCS#11 C library via CGO, which forces CGO on every consumer. This
// adapter avoids that by defining a pure-Go [P11Ctx] interface: the caller
// provides a P11Ctx implementation — which may be a CGO binding — while this
// module itself has no CGO dependency.
//
// # Session and PIN handling
//
// Each call to [signer.Sign] opens a fresh PKCS#11 session, logs in, signs,
// and immediately logs out and closes the session. The PIN is never stored in
// a struct field: it is requested on every call via the [PINFunc] the caller
// supplies at construction. This design minimises the window in which the PIN
// is held in memory and ensures it cannot appear in a log through the struct's
// stringer or a reflect-based logger.
//
// Error messages returned by this package never contain the PIN value. The
// test [TestSignErrorsNeverContainPIN] asserts this property against every
// error path.
//
// # Hardware evidence
//
// The following has been tested:
//   - SoftHSM2 v2.6.1 with Ed25519 keys: unit tests pass in this module's
//     fake transport and have been verified manually against a SoftHSM2 slot.
//
// The following has NOT been tested against real hardware in this repository:
//   - YubiKey 5 series (PIV interface over CKM_EDDSA)
//   - Thales Luna HSM
//   - AWS CloudHSM
//
// Do not deploy this adapter to production without your own end-to-end
// verification, and record what you tested in your operations runbook.
package pkcs11
