# Key Compromise Playbook

**What to do when a signing key is believed compromised.**

This playbook covers the three custody models supported by soroauth: classic
single-key accounts, threshold accounts (m-of-n multisig), and custom account
contracts (including session keys and delegates). The response differs for each
model because an Stellar account's address IS its public key — a compromised key
cannot be rotated like a password.

---

## 1. Classic Ed25519 Single-Key Account

### What can be recovered

- **The address cannot be recovered.** There is no "new address" for a
  classic Ed25519 account. The address is derived from the public key, and
  the private key is what signs authorizations.
- **Previously signed entries cannot be "un-signed."** Once a `SorobanAuthorizationEntry`
  has been written to the blockchain, its signature field is immutable. There is
  no mechanism to revoke or replace a signature after the fact.

### What cannot be recovered

- Any authorization entry already submitted and confirmed on-chain. The
  signature cannot be cleared or overwritten.
- The account's sequence number or sequence history.

### Immediate containment steps

1. **Stop all signing operations** that use the compromised key immediately.
   If you have a CI pipeline, a deployment script, or a hardware signer
   configured with this key, isolate it.
2. **If the key is an in-memory ed25519 key** (the library's default), simply
   remove it from wherever it is stored / environment‑variable‑configured and
   generate a new key pair.
3. **Fund a new account** with the new key pair and transfer any XLM balance
   from the old account using a standard Stellar transfer (the new account's
   address is the G… prefix derived from the new seed).
4. **Update all configuration** that references the compromised key: secret
   seeds, environment variables, KMS aliases, hardware wallet profiles.
5. **If the compromised key was used in a sorauth CLI command**, re-run any
   signed transactions with the new key after step 3 is complete.

### Preventive measures

- **Never hard‑code secret seeds** in source control or CI secrets. Use
  environment variables or a vault solution.
- **Rotate keys periodically** if the threat model demands it. Generate a new
  key pair, fund the new account, and update all signers.
- **Use an audit record** (#319) so that if a compromise is detected later,
  you can determine exactly which entries were signed with the compromised key.
- **Key separation**: use different key pairs for different environments
  (testnet vs mainnet) so a compromised testnet key does not affect mainnet
  operations.

### On-chain behaviour

- The host rejects `require_auth()` when `current_ledger >
  signatureExpirationLedger` (protocol 27, `verify_and_consume_nonce` in
  `rs-soroban-env` `auth.rs`).
- There is **no on-chain mechanism** to invalidate a previously submitted
  signature. The only on-chain action is to submit a new transaction from the
  new key.

---

## 2. Threshold Account (m-of-n Ed25519 Signers)

### What can be recovered

- **The account address stays the same.** A threshold account's address is
  derived from the group public key, which does not change when shares are
  refreshed or re‑generated.
- **Existing signatures remain valid.** Signatures already submitted on-chain
  are not invalidated by key refresh. The group public key is baked into the
  address, so no on-chain action is needed.
- **New signatures can be produced** with refreshed shares without changing
  the address.

### What cannot be recovered

- **Old shares cannot be combined with new shares** to sign the same payload
  (see preventive measure "refresh" below). If an attacker has collected shares
  over time, a refresh operation destroys the old shares' combinability.
- **Previously signed entries** cannot be retroactively re‑signed with a new
  key. The signature is bound to the entry's payload, not the key.

### Immediate containment steps

1. **Revoke or rotate shares** via the DKG refresh procedure (see preventive
   measures). This gives every participant a new share for the same group key,
   and old shares must be destroyed.
2. **If a specific participant's share is compromised**, that participant's
   share must be revoked and a new share issued. The remaining n‑1 shares plus
   the new share still form the same m‑of‑n threshold, so the account address
   does not change.
3. **Stop all signing operations** that use the compromised share immediately.
4. **Update participant configurations** (environment variables, KMS configs,
   hardware device profiles) to remove the compromised share.

### Preventive measures

- **Proactive share refresh** (#331): run a DKG ceremony periodically (e.g.
  every 30‑90 days) so that an attacker who compromises one share per period
  cannot accumulate enough shares over time to reach the threshold. After a
  refresh, old shares must be securely destroyed.
- **Key share access control**: store shares in separate HSMs or secure enclaves,
  each with its own access policy. Compromise of one physical device does not
  expose all shares.
- **Audit records** (#319): record which participant signed each entry, so a
  compromise can be traced to the specific share.
- **M‑of‑N with N > 2**: the more participants, the harder it is for an
  attacker to collect enough shares. Consider 3‑of‑5 instead of 2‑of‑3 if the
  threat model includes gradual share collection.

### On-chain behaviour

- Same as single-key: the host checks `current_ledger >
  signatureExpirationLedger`. There is no on-chain revocation mechanism.
- The group public key is derived from the shares and is fixed for the account's
  lifetime. A refresh changes the shares but not the group public key or the
  account address.

---

## 3. Custom Account Contract (including session keys, delegated signers)

### What can be recovered

- **The contract can define its own key‑revocation logic.** Unlike classic and
  threshold accounts, the on-chain contract code controls what happens when a
  key is believed compromised. The library has no visibility into the contract's
  internal state.
- **If the contract stores a "signer set" or "authorized keys,"** the contract
  can update that set without changing the account address.

### What cannot be recovered

- **The library cannot revoke a signature** from a custom account contract.
  The `SorobanAuthorizationEntry` signature is written to the transaction
  envelope by the caller; the contract decides whether to honor or reject it.
- **Any authorization entry already submitted** to a contract that does not
  support key revocation is immutable.

### Immediate containment steps

1. **Contact the contract operator or administrator.** If the modular-account
   contract (or whatever custom account is in use) has an admin key or an
   `"update signers"` function, use it to remove the compromised key from the
   stored signer set.
2. **If the contract does not have a key‑revocation pathway**, the only
   containment is to stop signing with the compromised key and, if possible,
   deploy a new version of the contract that excludes it.
3. **If the compromised key controls a session‑key delegate**, remove it from
   the delegate tree via `WithDelegates` with the remaining delegates, then
   re‑sign the entry.
4. **Fund a new account** if the contract's address itself is derived from a
   compromised key and no admin pathway exists.

### Preventive measures

- **Admin key separation:** keep an admin key or governance mechanism separate
  from the signing keys used in `require_auth()`. The admin key can revoke
  signing keys without changing the account address.
- **Key rotation via contract:** design the custom account contract to support
  a `"replace_signer(old_key, new_key)"` function that updates the signer set
  and emits an event the operator can monitor.
- **Audit records** (#319): record which address signed each entry. If the
  contract exposes signer identities, an operator can identify which entries
  were signed with the compromised key.
- **Session key windowing:** if the contract uses session keys with a ledger‑window
  validity, expiry automatically revokes keys that have passed their window
  without any on-chain action.

### On-chain behaviour

- The contract's `__check_auth` implementation decides what constitutes a valid
  signature. The library's `Inspect` and `VerifyEntry` report the host's verdict
  (`verified`, `unsigned`, `invalid`, `cannot_check`) but cannot revoke past
  decisions.
- CAP‑71‑01 §`delegate_account_auth` passes each delegate's signature to the
  host for checking. If the contract removes a delegate, future entries will
  not include that delegate's signature.

---

## Cross‑model comparison

| Custody model | Address change? | Previous entries revocable? | Immediate containment |
|---|---|---|---|
| Classic Ed25519 single key | **No** (address = public key) | **No** | Generate new key, fund new account, update config |
| Threshold (m‑of‑n) | **No** (group key = address) | **No**, but refresh destroys old shares | Revoke/rotate compromised share via DKG refresh |
| Custom contract | **Depends on contract** | **Depends on contract** | Use contract admin; if none, stop signing, possibly deploy new contract |

---

## Summary Checklist

### Immediate (within minutes)

- [ ] Stop all signing operations using the compromised key.
- [ ] Isolate the key's storage location (env vars, config files, CI secrets).
- [ ] Determine the custody model: classic, threshold, or custom contract.

### Short‑term (within hours)

- [ ] For classic: generate a new key pair, fund the new account, update all
  configurations.
- [ ] For threshold: initiate DKG refresh or revoke the compromised share.
- [ ] For custom contract: contact the contract admin; if no admin pathway,
  stop signing and plan a contract update.

### Long‑term (within days)

- [ ] Update the audit record (#319) to reflect the compromise and which
  entries were affected.
- [ ] Review preventive measures for the custody model and implement any
  that are missing.
- [ ] Communicate the compromise to all stakeholders (operators, auditors,
  users if funds are at risk).

---

## Linked References

- **[SECURITY.md](SECURITY.md)**: Reporting vulnerabilities in this library.
- **[Issue #319](())**: Structured audit record for every signing decision.
- **[Issue #331](())**: Refresh threshold shares without changing the group key.
- **[Incident runbook #641](incident_runbook.md)**: What to do when a submission
  is rejected on-chain or a signature is unexpected.