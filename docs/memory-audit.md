# Memory Audit and Key Material Hygiene

This document provides an audit of where seeds, private keys, and secret buffers are held across `soroauth` and its CLI environment reader, outlining what zeroing achieves and what limitations Go imposes.

## Audit of Key Material Paths

1. **`NewEd25519Signer` & `keypair.Full`**
   - **Holding**: `keypair.Full` holds the underlying seed and private key bytes used by the Stellar SDK.
   - **Ownership**: The SDK manages `keypair.Full` internals. The library invokes `Sign` on the keypair and does not directly mutate or own the secret seed buffer inside `keypair.Full`.

2. **`AccountMultiSigner`**
   - **Holding**: Holds multiple `Signer` instances and intermediate signature slices.
   - **Ownership**: Slices of signatures are zeroed after assembly.

3. **CLI Environment-Read Path (`--secret-env`)**
   - **Holding**: Reads secret seeds from environment variables into byte slices.
   - **Ownership**: The library or CLI owns the temporary byte slice and explicitly overwrites it with zeros (`0x00`) immediately after parsing and use.

4. **Adapter Modules (`awskms`, `gcpkms`, `walletsdk`, `remote`)**
   - **Holding**: KMS keys and remote signers hold no local private key material; hardware/remote services manage the keys.

## Go Runtime Limitations

- **Garbage Collection**: Go's GC may move or copy memory during compaction, leaving copies in un-zeroed heap locations.
- **Swap and Core Dumps**: Memory pages containing keys may be swapped to disk or captured in crash core dumps.
