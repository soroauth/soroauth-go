//! A custom account contract enforcing per-period spending limits with CAP-71 delegates.
//!
//! This is TEST FIXTURE CODE. It exists to exercise inspectable invocation arguments
//! inside __check_auth, verifying that spending limits can be enforced per rolling period.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Symbol, Vec,
};

const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PolicyAccountError {
    UnknownDelegate = 1,
    NoDelegates = 2,
    SpendingLimitExceeded = 3,
}

#[contracttype]
pub enum DataKey {
    Signers,
    Limit,
    Period,
    Spent(u64),
}

#[contract]
pub struct PolicyAccount;

#[contractimpl]
impl PolicyAccount {
    pub fn __constructor(env: Env, signers: Vec<Address>, limit: i128, period_ledgers: u32) {
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage().instance().set(&DataKey::Limit, &limit);
        env.storage().instance().set(&DataKey::Period, &period_ledgers);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn limit(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Limit).unwrap_or(0)
    }

    pub fn period(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Period).unwrap_or(100)
    }

    pub fn spent_in_period(env: Env, period_index: u64) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Spent(period_index))
            .unwrap_or(0)
    }
}

#[contractimpl]
impl CustomAccountInterface for PolicyAccount {
    type Signature = ();
    type Error = PolicyAccountError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        auth_contexts: Vec<Context>,
    ) -> Result<(), PolicyAccountError> {
        let delegates = env.custom_account().get_delegated_signers();
        if delegates.is_empty() {
            return Err(PolicyAccountError::NoDelegates);
        }

        let registered = Self::signers(env.clone());
        for delegate in delegates.iter() {
            if !registered.contains(&delegate) {
                return Err(PolicyAccountError::UnknownDelegate);
            }
        }

        // Inspect invocation arguments for transfer amount if applicable
        let limit = Self::limit(env.clone());
        let period_ledgers = Self::period(env.clone());
        let current_ledger = env.ledger().sequence();
        let period_index = (current_ledger as u64) / (period_ledgers as u64);

        let mut requested_amount: i128 = 0;
        for ctx in auth_contexts.iter() {
            if let Context::Contract(c) = ctx {
                let fn_name = c.function;
                if fn_name == Symbol::new(&env, "transfer") {
                    let args = c.args;
                    if args.len() >= 3 {
                        if let Ok(amount) = args.get(2).unwrap().try_into() {
                            requested_amount += amount;
                        }
                    }
                }
            }
        }

        let mut spent = Self::spent_in_period(env.clone(), period_index);
        if requested_amount > 0 {
            if spent + requested_amount > limit {
                return Err(PolicyAccountError::SpendingLimitExceeded);
            }
            spent += requested_amount;
            env.storage().instance().set(&DataKey::Spent(period_index), &spent);
        }

        for delegate in delegates.iter() {
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
