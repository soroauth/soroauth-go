//! A custom account whose delegated signers are session keys, each valid only
//! inside its own ledger window.
//!
//! This is TEST FIXTURE CODE. It exists so that CAP-71 delegated signers with
//! time bounds inside the contract can be proven against a real host on
//! testnet, and for nothing else. It is deliberately not a product: no
//! policies, no admin functions, no upgradability, and no way to change the
//! key set after construction. Do not deploy it to mainnet or treat it as a
//! smart-account starting point.
//!
//! The account carries no signature of its own. Its `__check_auth` reads the
//! delegates the client attached to the authorization entry, refuses any that
//! is not a registered session key, refuses any whose window does not contain
//! the current ledger, and otherwise forwards the authorization to each of
//! them.
//!
//! ## The two clocks
//!
//! Two different ledgers can invalidate an authorization entry here, and they
//! are checked by two different pieces of code:
//!
//! * `signature_expiration_ledger`, inside the entry's own credentials, is
//!   checked by the **host**, not by this contract.
//!   `AccountAuthorizationTracker::authorize` calls `authenticate` — which is
//!   what runs this contract's `__check_auth` — and only afterwards
//!   `verify_and_consume_nonce`, which refuses with `ScErrorType::Auth` /
//!   `ScErrorCode::InvalidInput`, message `"signature has expired"`, when
//!   `ledger_seq > live_until_ledger`
//!   (rs-soroban-env-host 27.0.1, `src/auth.rs:2492-2515` and `:2586-2602`).
//! * the session window in this contract's storage is checked by the
//!   **contract**, here in `__check_auth`, against `env.ledger().sequence()`.
//!
//! Both compare against the same number — the sequence number of the ledger
//! the transaction is executing in — but they run in that order. This
//! contract's window check happens first; the host's expiration check runs
//! only once `__check_auth` has returned `Ok`. So an expired session key is
//! reported by this contract as `SessionExpired`, while an entry whose own
//! expiration has passed is reported by the host, and only if this contract
//! let it through. A wallet that sets `signature_expiration_ledger` past the
//! end of the session window therefore sees the contract's error; one that
//! sets it short of the window's end sees the host's.
//!
//! A consequence worth stating plainly: the window is a **policy** this
//! contract enforces on its own clock, and nothing in the protocol binds the
//! two. `signature_expiration_ledger` is the only one of the two a third party
//! can verify from the submitted entry alone.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Vec,
};

/// How long to keep the instance alive, in ledgers. Roughly 30 days at 5
/// seconds per ledger, which comfortably outlives a test run.
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

/// Why a session key was refused.
///
/// The four arms are deliberately distinct. An expired key and a key that is
/// not valid yet are different operational problems — "get a new key" versus
/// "wait" — and a caller that cannot tell them apart cannot act on either.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SessionKeyError {
    /// The delegate is not a registered session key.
    UnknownSessionKey = 1,
    /// No delegate was attached at all, so nothing authenticated the account.
    NoSessionKey = 2,
    /// The key's window had not opened yet at the current ledger.
    SessionNotYetValid = 3,
    /// The key's window had already closed at the current ledger.
    SessionExpired = 4,
}

/// One session key and the ledger window it is valid in.
///
/// Both bounds are inclusive: a key with `valid_from_ledger = 100` may
/// authenticate in the ledger whose sequence number is 100, and one with
/// `valid_until_ledger = 200` may still authenticate at 200 and not at 201.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionKey {
    pub key: Address,
    pub valid_from_ledger: u32,
    pub valid_until_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    SessionKeys,
}

/// Decides whether a window contains `now`.
///
/// This is split out of `__check_auth` so it can be unit tested directly: a
/// failure inside `__check_auth` reaches a test harness as the host's
/// `(Context, InvalidAction)` wrapper, which is the same for every arm, so the
/// only way to prove *which* refusal happened is to test the decision itself.
/// The end-to-end scenario that drives the same decision against a live host
/// and asserts the contract's error code is scenario G in e2e_test.go.
pub(crate) fn require_window(
    now: u32,
    valid_from_ledger: u32,
    valid_until_ledger: u32,
) -> Result<(), SessionKeyError> {
    if now < valid_from_ledger {
        return Err(SessionKeyError::SessionNotYetValid);
    }
    if now > valid_until_ledger {
        return Err(SessionKeyError::SessionExpired);
    }
    Ok(())
}

/// Finds the session key registered for `key`, if any.
fn find_session_key(keys: &Vec<SessionKey>, key: &Address) -> Option<SessionKey> {
    for i in 0..keys.len() {
        let candidate = keys.get(i).expect("index is in range");
        if &candidate.key == key {
            return Some(candidate);
        }
    }
    None
}

#[contract]
pub struct SessionKeys;

#[contractimpl]
impl SessionKeys {
    /// Registers the session keys this account will accept, and the window
    /// each one is valid in.
    ///
    /// The set is fixed at construction. This is a test fixture, so there is
    /// deliberately no way to change it afterwards.
    pub fn __constructor(env: Env, keys: Vec<SessionKey>) {
        env.storage().instance().set(&DataKey::SessionKeys, &keys);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Returns the registered session keys, so a test can confirm what was
    /// stored.
    pub fn session_keys(env: Env) -> Vec<SessionKey> {
        env.storage()
            .instance()
            .get(&DataKey::SessionKeys)
            .unwrap_or_else(|| Vec::new(&env))
    }
}

#[contractimpl]
impl CustomAccountInterface for SessionKeys {
    /// The account verifies no signature of its own, so there is nothing to
    /// check. Authentication comes entirely from its delegates.
    type Signature = ();
    type Error = SessionKeyError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), SessionKeyError> {
        // The session keys the client attached to this entry. The host does
        // not sanitise these; checking them is this contract's job.
        let delegates = env.custom_account().get_delegated_signers();

        // Fail closed. With no key attached there is nothing authenticating
        // this account, and returning Ok would authorize the invocation on the
        // strength of nobody at all.
        if delegates.is_empty() {
            return Err(SessionKeyError::NoSessionKey);
        }

        let keys = Self::session_keys(env.clone());
        let now = env.ledger().sequence();

        // Every attached key is validated before any authorization is
        // forwarded, so a refusal names the key that was wrong rather than
        // arriving after a partial delegation has already happened.
        for i in 0..delegates.len() {
            let delegate = delegates.get(i).expect("index is in range");
            match find_session_key(&keys, &delegate) {
                None => return Err(SessionKeyError::UnknownSessionKey),
                Some(key) => {
                    require_window(now, key.valid_from_ledger, key.valid_until_ledger)?
                }
            }
        }

        for i in 0..delegates.len() {
            let delegate = delegates.get(i).expect("index is in range");
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
