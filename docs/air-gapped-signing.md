# Air-Gapped Signing Procedure

An end-to-end procedure for signing on a machine that has never been networked,
with the commands, the file exchange and the verification steps on both sides.

## Overview

This custody model provides the strongest guarantees against remote adversaries:
the offline machine never receives a networked payload, and the online machine
never sees the signing key.  The procedure is designed so that a substituted
authorization entry is caught by a payload-binding check, and the operator can
verify that the entry they reviewed is the one that was signed.

## Threat model

- **Online machine**: may be fully compromised (malware, remote execution, etc.).
  It has no secret material and only handles public XDR and payload hashes.
- **Offline machine**: holds the sole signing key.  It is never connected to a
  network (no DNS, no HTTP, no package downloads).  It only processes explicitly
  provided file inputs.
- **File exchange**: the only communication channel.  Files are transferred
  between machines on removable media (USB stick, SD card, etc.).  The online
  machine writes the entry to review; the offline machine writes the signature.

## Procedure

### Offline machine (key-signing side)

1. **Prepare the entry to sign**
   - The operator copies the unsigned `SorobanAuthorizationEntry` (base64 XDR)
     from the online machine to a file, e.g. `entry-to-sign.b64`.
   - Verify the entry structure: `inspect --entry <file>` should show the
     credential arm, nonce, expiration, and root invocation.
   - **Payload-binding check**: compute the preimage and payload *before*
     signing, and record the SHA-256 hash.  The online machine must also
     compute and record this hash.  After signing, both sides must compare
     the hashes to confirm the signature covers the exact entry that was
     reviewed.

2. **Sign the entry**
   - Run the signing command, which reads the entry and the secret seed from an
     environment variable (never from a command-line argument or stdin that
     could be intercepted).
   - The command outputs the signed entry (base64 XDR) on stdout.

3. **Output the signed entry**
   - The signed entry is written to a file, e.g. `signed-entry.b64`.
   - The operator copies this file to the online machine via the file exchange.

### Online machine (review-and-submit side)

1. **Receive the signed entry**
   - Copy `signed-entry.b64` from the offline machine via the file exchange.

2. **Verify the payload binding**
   - Decode the entry and recompute the preimage and payload hash, exactly as
     the offline machine did.
   - Compare the recomputed hash with the hash recorded before signing.  If
     they differ, the entry was substituted — **refuse to submit**.
   - The recomputation uses `soroauth payload --entry <file> --valid-until <n>`
     --network <passphrase>` to derive the preimage, then `sha256` of the
     preimage bytes.

3. **Enforce-mode simulation**
   - Run the signed entry through enforce-mode simulation via the RPC client:
     `soroauth simulate --entry <file> --use-upgraded-auth`.
   - Verify the simulation succeeds and the entry is accepted by the host.

4. **Assemble and submit the transaction**
   - Assemble the transaction envelope using the signed entries.
   - Sign the transaction with the source account's seed (read from an
     environment variable, never from a command-line argument).
   - Submit the envelope and poll until the transaction is done.

## Payload-binding check details

The security property that protects against a substituted entry is the explicit
payload-binding check:

1. **Before signing** (offline machine):
   - `soroauth payload --entry entry-to-sign.b64 --valid-until 1234567 --network testnet`
   - This prints the `preimage` (base64) and `payload` (hex).
   - Record both values.  The payload is `SHA-256(preimage_bytes)`.

2. **After signing** (online machine, verification step):
   - `soroauth payload --entry signed-entry.b64 --valid-until 1234567 --network testnet --json`
   - This prints a JSON object with `preimage` and `payload`.
   - Extract the `payload` hex value and compare it with the value recorded
     before signing.
   - If the payloads differ, the entry was modified or substituted after
     signing — **do not submit**.

3. **Why this catches substitution**:
   - The payload is `SHA-256(HashIdPreimage)`, and the HashIdPreimage binds the
     credential arm, nonce, expiration, and root invocation.
   - Any change to the entry (arm type, address, nonce, expiration, invocation
     arguments) changes the preimage, which changes the payload hash.
   - The check is explicit: the operator must compare the two payload values.
   - There is no implicit "trust the offline machine" — the operator must
     verify the hash.

## What the air gap protects

- **Signature over the correct entry**: the signature was produced over the
  entry the operator reviewed on the offline machine, not over a different
  entry substituted in transit.
- **Key exposure prevention**: the signing key never leaves the offline
  machine, so even a fully compromised online machine cannot sign arbitrary
  entries.
- **Payload integrity**: the payload-binding check catches any entry
  modification, whether intentional or accidental.

## What the air gap does NOT protect

- **Compromised offline machine**: if the offline machine itself is malicious
  or has been infiltrated (e.g., via a supply chain attack on the signing
  software), it can produce a valid signature over a malicious entry.  The air
  gap assumes the offline machine's software and key are trusted.
- **Online machine input spoofing**: the online machine's operator must trust
  the file received from the offline machine.  If the file exchange channel is
  compromised (e.g., a malicious USB stick), the online machine could be
  tricked into signing a different entry.
- **Key leakage through other means**: the air gap only protects the signing
  key from remote network access.  If the key is exposed through other means
  (e.g., physical theft, malware on the offline machine that reads the seed
  from memory), the air gap does not help.

## Command reference

### Offline machine commands

```bash
# Verify the entry structure before signing
soroauth inspect --entry entry-to-sign.b64 --network testnet

# Compute the preimage and payload hash (record these!)
soroauth payload --entry entry-to-sign.b64 --valid-until 1234567 --network testnet
#   Outputs:
#     preimage: <base64>
#     payload:  <hex-encoded-SHA256>

# Sign the entry (reads seed from SOROAUTH_SECRET_ENV)
soroauth sign --entry entry-to-sign.b64 \
    --valid-until 1234567 \
    --network testnet \
    --secret-env SOROAUTH_SECRET_ENV \
    --output signed-entry.b64
```

### Online machine commands

```bash
# Verify the payload binding after receipt
soroauth payload --entry signed-entry.b64 --valid-until 1234567 --network testnet --json
#   Compare the "payload" hex value with the value recorded before signing.
#   If different, the entry was substituted — refuse to submit.

# Verify the entry structure
soroauth inspect --entry signed-entry.b64 --network testnet

# Enforce-mode simulation (must succeed)
soroauth simulate --entry signed-entry.b64 --network testnet

# Assemble and submit the transaction (using the source account's seed)
soroauth sign --entry <envelope-or-entry> \
    --valid-until 1234567 \
    --network testnet \
    --secret-env SOURCE_SECRET_ENV
```

## Checklist: did you follow the procedure?

- [ ] Entry structure verified with `inspect` before signing
- [ ] Preimage and payload hash computed and recorded *before* signing
- [ ] Signed entry transferred via file exchange (no network on offline machine)
- [ ] Payload-binding check: recomputed hash compared with pre-signing record
- [ ] Enforce-mode simulation verified after receipt
- [ ] Transaction submitted only if all checks pass

## Security considerations

- **Air gap assumption**: the offline machine is trusted for correctness of the
  signing operation but not for network exposure.  The air gap protects against
  remote key extraction and remote entry substitution.
- **File exchange channel**: assume the removable media may be inspected or
  tampered with.  Verify the payload hash on the online machine before submitting.
- **Never pass a secret on the command line**: the `--secret-env` mechanism
  reads the seed from an environment variable, which keeps it out of shell
  history and the process table.
- **Document the hash**: the operator must develop the habit of always recording
  the preimage and payload hash before signing.  Without this habit, the air
  gap provides less protection because the operator cannot verify the binding.

## References

- `soroauth payload` — prints the preimage and payload hash for an entry
- `soroauth sign` — signs an entry with a seed from an environment variable
- `soroauth inspect` — reports an entry's structure as JSON
- `soroauth simulate` — runs record-mode simulation
- CAP-46-11, CAP-71-01: credential arms and payload binding