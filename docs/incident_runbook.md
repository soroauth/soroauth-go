# Incident Runbook — Failed or Suspicious Signature

**For when a submission is rejected on-chain, a signature nobody can account for,
or a signer behaves unexpectedly.** Write this when you are under pressure: short
steps, no background reading required.

---

## 🚨 Immediate: Is this an emergency?

| Symptom | Likely cause | First step |
|---|---|---|
| Transaction **fails** on submission with `UNKNOWN_TRANSACTION` or similar | Signature invalid, expired nonce, or exceeded expiration | Halt: do not resubmit |
| Transaction **submitted** but contract reverts with `REJECTED_AUTH` | Authorization entry not accepted by host | Halt: do not resubmit |
| Transaction **appears** in explorer but contract returns `UNKNOWN_DELEGATE` | Delegate not registered in the account's signer set | Check delegate registration |
| Signature **mismatch** error from sorauth (`ErrSignatureMismatch`) | Signed payload does not match the entry's preimage | Verify the preimage was built correctly |
| Entry **inspected** and `Signed: false` for every node | Entry has `ScvVoid` or empty `ScvVec` signature | Check if this was intentional (delegates arm with Void top sig) |
| No error, but on-chain the transaction **fails after fees** | Expiration ledger was too low, or nonce was replayed | Check `validUntilLedger` and nonce uniqueness |

If any of the following appear, **stop**. Do not attempt to resubmit or adjust
the entry until the root cause is identified:

- The transaction was already **confirmed** on-chain and you are amending it.
- The `signatureExpirationLedger` is set to a value you did not explicitly
  choose.
- You did not run the **enforce‑mode simulation** after signing.

---

## 🛡️ Containment Steps

### 1. Verify the entry was signed correctly (off-chain)

Run the `soroauth inspect` CLI subcommand on the entry:

```sh
soroauth inspect --entry <base64-encoded-entry>
```

Record the output. It will tell you:

- Which credential arm was observed (source_account, address, address_v2,
  address_with_delegates).
- The `validUntilLedger` stored in the entry.
- Whether each node is `Signed: true/false` or `Void`.
- The nonce value (if address‑bound).

### 2. Check the payload hash matches the preimage

The library signs `SHA-256(XDR(HashIdPreimage))`. If the payload hash does not
match what was signed, the entry will be rejected.

You can verify with the `soroauth payload` CLI subcommand:

```sh
soroauth payload --entry <base64-encoded-entry> --valid-until <n> --network testnet
```

It will output the preimage (base64) and the payload (hex). Compare the payload
hex against what your signer received.

### 3. Confirm the signer's address matches the entry's target

- If you used `soroauth sign --for <addr>`, the signature is written only onto
  nodes whose address equals `<addr>`.
- If you did **not** specify `--for`, the signature is written onto the node
  matching `signer.Address()`.
- **Mismatch**: if the signer's address does not equal the entry's top-level
  address, the signature lands on the wrong node and the transaction will fail.

### 4. Check for nonce reuse

The host consumes one nonce per address. If two entries in the same transaction
share an address and the same nonce, the second is rejected after fees.

Run:

```sh
soroauth batch --entries <list> --valid-until <n> --network testnet
```

If `AuthorizeAll` detects a collision, it returns `ErrDuplicateNonce` naming the
address, both entry indices, and the nonce.

### 5. Verify the expiration ledger

The host rejects when `current_ledger > signatureExpirationLedger`. The
expiration ledger itself is still valid (inclusive bound, per
`verify_and_consume_nonce` in `rs-soroban-env` `auth.rs`).

Check that `validUntilLedger` is set to the intended value. If it was left at 0,
`AuthorizeEntry` returns `ErrInvalidExpiration`.

### 6. Rule out delegate tree issues

If the entry uses the `address_with_delegates` arm:

- Every delegate node must be signed (or be `ScvVoid` at the top level).
- Delegates are sorted by XDR bytes of the address, ascending.
- Duplicate addresses within one level return `ErrDuplicateDelegate`.
- If any delegate is unsigned (and it's not the top‑level Void case), the
  transaction will fail.

Run `soroauth inspect` and check the `Delegates` field in the output.

---

## ⚡ Escalation Path

| If you can ... | Then ... |
|---|---|
| **Identify the root cause** from steps 1‑6 above (wrong address, stale expiration, nonce collision, etc.) | Fix the input and re‑sign. Re‑simulate in enforce mode, re‑assemble the envelope, and resubmit. |
| **Rule out all above** but the entry was **already submitted** and confirmed | Do **not** resubmit. Record the transaction hash and error. If the entry is wrong, you must submit a new transaction from the correct key. |
| **Not able to identify the cause** after steps 1‑6 | Escalate to the maintainer or the team responsible for the signer/KMS. Provide: entry base64, transaction hash (if submitted), `soroauth inspect` output, signer type, network, and `validUntilLedger` value. |
| **The signer is a remote KMS or hardware device** and you suspect a device‑level issue | Follow the signer's own error handling and approval flow. The library's verdict is whatever the signer returned; the device may have its own logs. |
| **You need to determine on-chain behaviour** after the fact, without an audit log | Some questions **cannot** be answered. Without an audit record (#319) or a transcript of what was signed, you can only know what the transaction envelope contains. The library's `Inspect` reports the structure at sign time, but once the transaction is submitted and the envelope changes (fee bumps, inner‑transaction resolution), the original verdict may not be reproducible. |

---

## 📋 Documented Snippets (verify each command against the current CLI)

The following commands exist in the sorauth CLI and are tested:

| Command | What it does | Reference |
|---|---|---|
| `soroauth inspect --entry <base64>` | Prints `EntryInfo` JSON for one entry | `inspect.go` |
| `soroauth payload --entry <base64> --valid-until <n> --network testnet|public|<passphrase>` | Prints preimage base64 and payload hex | `cmd/soroauth/payload.go` |
| `soroauth sign --entry <base64> --valid-until <n> --network ... --secret-env <VAR> --for <addr>` | Signs an entry and prints the signed entry base64 | `cmd/soroauth/sign.go` |
| `soroauth batch --entries <list> --valid-until <n> --network ... --secret-env <VAR>` | Signs all entries or fails with `nil` slice | `cmd/soroauth/batch.go` |
| `soroauth delegates --entry <base64> --valid-until <n> --delegate <addr> [...]` | Wraps an entry with a delegate tree | `cmd/soroauth/delegates.go` |
| `soroauth upgrade --entry <base64>` | Converts a legacy entry to V2 | `cmd/soroauth/upgrade.go` |
| `soroauth doctor --signer <name>` *(if available)* | Health‑check a signer (prints address, connectivity) | `cmd/soroauth/doctor.go` (may be added) |

**Verify each command's flags before running it.** A runbook with a stale flag
is actively harmful.

---

## 🔍 Forensic limits: what the library's records can and cannot tell you

| Question | Answerable from library records? | What you need |
|---|---|---|
| "Which payload was signed for this entry?" | **Yes.** `soroauth payload` outputs the payload hex. | The entry base64. |
| "Which signer key produced this signature?" | **Yes, for ed25519.** `soroauth inspect` reports the address. | The entry base64. |
| "Was this entry signed before the key was compromised?" | **Partially.** The entry's `validUntilLedger` and nonce are recorded, but the library does not persist a history of signings. | An audit record (#319) would have this. |
| "Did this entry replay a previously used nonce?" | **Yes, if an audit record exists.** `AuthorizeAll` checks for nonce collisions within a batch. | Batch signing history. |
| "What was the host's verdict on this entry?" | **Yes, if you have the entry.** `Inspect` reports per‑node `verified`/`unsigned`/`invalid`/`cannot_check`. | The entry base64, inspected before any envelope mutation. |
| "Was the expiration inclusive or exclusive?" | **Inclusive.** The host rejects when `current_ledger > signatureExpirationLedger`; the expiration ledger itself is valid. | `rs-soroban-env` `auth.rs` `verify_and_consume_nonce`. |
| "Can I recover a signature once it's on-chain?" | **No.** The XDR `ScVal` signature field is immutable. | N/A — this is a protocol limit. |

---

## 📚 Linked References

- **[Key compromise playbook #642](key_compromise.md)**: What to do after the incident,
  per custody model.
- **[SECURITY.md](SECURITY.md)**: How to report a vulnerability in this library.
- **[Issue #319](())**: Structured audit record for every signing decision — the
  primary way to make post‑fact forensic questions answerable.
- **[Issue #331](())**: Refresh threshold shares without changing the group key.
- **[e2e/RESULTS.md](e2e/RESULTS.md)**: Live testnet proof of each scenario; useful
  to compare against when diagnosing an unexpected on-chain result.
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: The signing flow, package map, and delegate
  model.
- **[CONTRIBRIBUTING.md](CONTRIBUTING.md)**: Commit format, label conventions, and
  the PR checklist.