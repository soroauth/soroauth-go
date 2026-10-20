# Signers

`soroauth` defines a single interface for producing signatures:

This repository ships several signer modes. It currently includes the root
signing API plus three adapter modules (`adapters/awskms`, `adapters/gcpkms`,
and `adapters/walletsdk`), and they are all built on the same signing API, but
they do not carry the same threat model or the same level of evidence.
```

## Choosing a signer

| Signer                  | Threat model it addresses | Evidence and caveats | Recommendation |
|-------------------------|---------------------------|----------------------|----------------|
| `NewEd25519Signer`      | Local private key signing for classic accounts | Golden vectors and live testnet scenarios prove wire format and signature validity | Standard local signer for development and secure environments |
| `NewAccountMultiSigner` | Multi-signature classic accounts | Unit-tested and live testnet scenario C proves a 2-of-2 threshold works | Use for multi-party classic accounts |
| `NewPasskeySigner`      | Passkey / WebAuthn contract authentication | Unit tests and passkey vector checks prove the built-in shape | Use for passkey wallet contracts |
| `NewLedgerSigner`       | Hardware-backed ed25519 signing via Ledger | Unit tests cover the APDU protocol; **no live transaction proof in this repo** | Use for hardware wallet integration |

## Short answer

For standard local usage, `NewEd25519Signer` wrapping a `keypair.Full` is the primary entry point. Note that `remote.NewSigner`'s shipped example is intentionally a local reference, not production network security.

## Memory Hygiene & Key Material

Key material (seeds, private keys, secret environment variables) held in memory presents exposure risks via memory dumps, swapping, and garbage collection.

### Key Material Audit

1. **`NewEd25519Signer` & `keypair.Full`**: The SDK's `keypair.Full` owns the seed/private key bytes internally. This library does not own those internals and cannot guarantee their zeroing beyond what the SDK provides.
2. **`AccountMultiSigner`**: Holds a slice of signing keys/keypairs. The slice and individual elements are managed by Go's heap and garbage collector.
3. **CLI Secret Environment Read Path**: When the CLI reads secret material from environment variables via `--secret-env`, it loads the secret into a byte slice buffer. This library now explicitly zeroes this buffer immediately after use.
4. **Adapter Modules**: AWS KMS, GCP KMS, and Wallet SDK adapters handle external signing keys or delegate calls, leaving key material outside the host process memory where possible.

### What Go Can and Cannot Guarantee
- **Explicit zeroing**: Where buffers are explicitly owned by the library (such as temporary byte slices in the CLI secret-read path or intermediate signing slices), they are overwritten with zeros (`0x00`) immediately after use.
- **`keypair.Full` internals**: The SDK's `keypair.Full` type manages its own internal representation; this library does not own those internals and cannot guarantee their zeroing beyond what the SDK provides.
- **Runtime Limits**: Go's runtime garbage collector, memory swapping, and core dumps can still copy or retain memory beyond explicit zeroing guarantees.
