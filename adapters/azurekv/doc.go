// Package azurekv signs Soroban authorization entries with an Ed25519 key
// held in Azure Key Vault or Azure Managed HSM.
//
// It is the Azure counterpart to the GCP and AWS KMS signers and follows the
// same shape: a soroauth.Signer built over an Azure Key Vault key whose public
// key is the account being authorized. The address passed to NewSigner is the
// G… account address, which is what the credential node carries; keyName and
// keyVersion are the name and version components of the Azure Key Vault key
// identifier (for example keyName = "my-stellar-key", keyVersion = "abc123…").
// Pass an empty keyVersion to target the most recent version.
//
// Only OKP / Ed25519 keys are supported. RSA, EC, and symmetric keys produce
// signatures that are not 64 bytes and are refused rather than written into the
// entry. Ed25519 keys require the Premium or Managed HSM tier of Azure Key
// Vault; the Standard tier supports only RSA and EC keys.
//
// This package is a module of its own, so `go get` of soroauth does not pull
// the Azure SDK into every application that signs a Soroban entry. The root
// module stays free of it, the same way it stays free of the wallet SDK in
// adapters/walletsdk.
//
// The KMS call is behind the SignerClient interface, so the signing path is
// tested against a fake and never touches live Azure. The caller is responsible
// for constructing a *azkeys.Client with the appropriate credential and vault
// URL, and for authorising the managed identity or service principal with the
// "Sign" key operation permission.
package azurekv
