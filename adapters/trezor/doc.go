// Package trezor signs Soroban authorization entries using a Trezor hardware
// wallet, alongside the existing Ledger adapter.
//
// # Device confirmation
//
// Unlike cloud KMS signers, a Trezor presents the full transaction to the user
// on its screen before signing. [signer.Sign] receives both the XDR preimage
// and the 32-byte payload precisely so the device can show the real
// authorization — not a bare hash — and the user can confirm what they are
// approving. The [Transport] implementation is responsible for serialising and
// sending the preimage to the device; this package does not prescribe the
// wire format because Trezor's Stellar protocol may evolve.
//
// # Failure modes
//
// Trezor device errors map to three distinct sentinel values so callers can
// branch on them without string parsing:
//
//   - [ErrDeviceRejected]: the user pressed the cancel button on the device.
//   - [ErrDeviceTimeout]: the device did not respond within the expected window.
//   - [ErrDeviceDisconnected]: the USB/HID link to the device was lost.
//
// All three are returned wrapped, so errors.Is works through any chain.
//
// # Hardware evidence
//
// The following has been tested:
//   - Fake [Transport] in this module's unit tests: all error paths exercise
//     the three sentinel values, and the happy path produces a verifiable
//     Ed25519 signature.
//
// The following has NOT been tested against real hardware in this repository:
//   - Trezor Model One (firmware 1.x) over USB HID
//   - Trezor Model T (firmware 2.x) over USB HID or Trezor Bridge
//
// Record the firmware version and what was confirmed on the device screen in
// your operations runbook before deploying this adapter to production.
package trezor
