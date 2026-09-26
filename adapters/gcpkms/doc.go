// Package gcpkms signs Soroban authorization entries with an ed25519 key held
// in Google Cloud KMS.
//
// It is the GCP counterpart to the AWS KMS signer, and follows the same shape:
// a soroauth.Signer built over a Cloud KMS key version whose public key is the
// account being authorized. The address passed to NewSigner is the G… account
// address, which is what the credential node carries; the key version is the
// Cloud KMS resource name (for example
// "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1").
//
// This package is a module of its own, so `go get` of soroauth does not pull a
// cloud SDK into every application that signs a Soroban entry. The root module
// stays free of it, the same way it stays free of the wallet SDK in
// adapters/walletsdk.
//
// The KMS call is behind the AsymmetricSigner interface, so the signing path is
// tested against a fake and never touches live GCP. Only ed25519 keys
// (GOOGLE_SYMMETRIC / EC_SIGN_ED25519) are supported: a signature any other
// algorithm produces does not have the 64-byte shape a classic Stellar account
// expects, and is refused rather than written into the entry.
package gcpkms
