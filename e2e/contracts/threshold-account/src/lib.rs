//! A custom account that requires M of its N registered signers before it will
//! authenticate anything.
//!
//! This is TEST FIXTURE CODE. It exists so that the partial-signing case
//! soroauth's `AuthorizeAll` handles can be proven against a real host on
//! testnet, and for nothing else. It is deliberately not a product: no
//! policies, no admin functions, no upgradability, and no way to change the
//! signer set or the threshold after construction. Do not deploy it to mainnet
//! or treat it as a smart-account starting point.
//!
//! ## What the contract can and cannot see
//!
//! `AuthorizeAll` does not require every delegate to be signed, because it
//! cannot know the account's policy — see `RequireAllSigned` (issue #103) in
//! the backlog. This fixture is the contract that makes the difference
//! observable: it *does* know its own policy, and refuses an entry that carries
//! fewer than `threshold` delegates.
//!
//! The contract sees the delegated signers as addresses only:
//! `CustomAccount::get_delegated_signers` returns `Vec<Address>`, not the
//! signatures (soroban-sdk 27.0.6, `src/custom_account.rs:274`). So the count it
//! enforces is the number of delegates **attached** to the entry, and it then
//! calls `delegate_auth` for each of them, which is what makes the host check
//! that each one actually signed. A delegate whose signature does not verify
//! fails there, so a signature that is present but wrong is never counted as
//! one of the M.
//!
//! ## Why the count cannot be inflated
//!
//! The tally is over the entry's own delegates array, so it would be worthless
//! if an attacker could put the same address in it M times. The host rejects
//! that before this contract runs: `DelegatedAccountAuthTracker::from_xdr`
//! hands the entry's top-level delegates array to
//! `DelegatedAccountAuthSignerTreeNode::from_xdr`, which compares each adjacent
//! pair and refuses with `ScErrorType::Auth` / `ScErrorCode::InvalidInput`,
//! "delegated signers contain duplicate address", when two are equal and
//! "... are not in sorted order" when they are descending
//! (rs-soroban-env-host 27.0.1, `src/auth.rs:2204-2217` and `:2092-2127`).
//! Strictly ascending therefore means distinct, and `delegates.len()` is a
//! count of distinct addresses.
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

/// Why a set of delegates was refused.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ThresholdError {
    /// A delegate was attached that this account has not registered.
    UnknownSigner = 1,
    /// No delegates were attached at all.
    NoSigners = 2,
    /// Fewer than `threshold` delegates were attached.
    InsufficientSignatures = 3,
}

/// The account's signer set and the number of them that must sign.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub signers: Vec<Address>,
    pub threshold: u32,
}

#[contracttype]
pub enum DataKey {
    Policy,
}

/// Decides whether `attached` distinct signers are enough.
///
/// This is split out of `__check_auth` so it can be unit tested directly: a
/// failure inside `__check_auth` reaches a test harness as the host's
/// `(Context, InvalidAction)` wrapper, which is the same for every arm, so the
/// only way to prove *which* refusal happened is to test the decision itself.
/// The end-to-end scenario that drives the same decision against a live host
/// and asserts the contract's error code is scenario I in e2e_test.go.
pub(crate) fn require_threshold(
    attached: u32,
    threshold: u32,
) -> Result<(), ThresholdError> {
    if attached < threshold {
        return Err(ThresholdError::InsufficientSignatures);
    }
    Ok(())
}

#[contract]
pub struct ThresholdAccount;

#[contractimpl]
impl ThresholdAccount {
    /// Registers the signer set and the number of them that must sign.
    ///
    /// Both are fixed at construction. This is a test fixture, so there is
    /// deliberately no way to change them afterwards.
    ///
    /// Panics on a policy that could never be satisfied (`threshold` of zero,
    /// or more than the number of signers) or a signer set with a duplicate in
    /// it, rather than deploying an account that silently accepts nothing or
    /// counts one signer twice.
    pub fn __constructor(env: Env, signers: Vec<Address>, threshold: u32) {
        assert!(threshold >= 1, "threshold must be at least 1");
        assert!(
            threshold <= signers.len(),
            "threshold exceeds the number of signers"
        );
        for i in 0..signers.len() {
            let signer = signers.get(i).expect("index is in range");
            for j in (i + 1)..signers.len() {
                assert!(
                    signer != signers.get(j).expect("index is in range"),
                    "duplicate signer"
                );
            }
        }

        env.storage().instance().set(
            &DataKey::Policy,
            &Policy {
                signers,
                threshold,
            },
        );
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Returns the stored policy, so a test can confirm what was set.
    pub fn policy(env: Env) -> Policy {
        env.storage()
            .instance()
            .get(&DataKey::Policy)
            .expect("the constructor stores a policy")
    }
}

#[contractimpl]
impl CustomAccountInterface for ThresholdAccount {
    /// The account verifies no signature of its own, so there is nothing to
    /// check. Authentication comes entirely from its delegates.
    type Signature = ();
    type Error = ThresholdError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), ThresholdError> {
        // The signers the client attached to this entry. The host has already
        // refused a duplicate or unsorted list, so these are distinct; see the
        // module documentation for where that happens.
        let delegates = env.custom_account().get_delegated_signers();
        if delegates.is_empty() {
            return Err(ThresholdError::NoSigners);
        }

        let policy = Self::policy(env.clone());

        // Every attached signer is validated before the count is applied, so
        // an unknown signer is reported as such rather than as a shortfall.
        for i in 0..delegates.len() {
            let delegate = delegates.get(i).expect("index is in range");
            if !policy.signers.contains(&delegate) {
                return Err(ThresholdError::UnknownSigner);
            }
        }

        // The shortfall is refused here, by this contract, with its own error.
        // The alternative — forwarding every delegate and letting the host
        // fail the missing one — would report an unsigned node rather than a
        // policy that was not met.
        require_threshold(delegates.len(), policy.threshold)?;

        // Each attached signer must actually have authorized; the host checks
        // that as part of delegate_auth.
        for i in 0..delegates.len() {
            let delegate = delegates.get(i).expect("index is in range");
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
