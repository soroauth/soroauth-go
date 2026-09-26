#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, IntoVal, Symbol, Val, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Signer,
    Guardians,
    RecoveryTime(Address),
    PendingSigner(Address),
}

#[contract]
pub struct SocialRecoveryAccount;

#[contractimpl]
impl SocialRecoveryAccount {
    pub fn __constructor(env: Env, signer: Address, guardians: Vec<Address>) {
        env.storage().instance().set(&DataKey::Signer, &signer);
        env.storage().instance().set(&DataKey::Guardians, &guardians);
    }

    pub fn rotate_key(env: Env, new_signer: Address) {
        let current_signer: Address = env.storage().instance().get(&DataKey::Signer).unwrap();
        current_signer.require_auth();
        env.storage().instance().set(&DataKey::Signer, &new_signer);
    }

    pub fn initiate_recovery(env: Env, guardian: Address, new_signer: Address) {
        guardian.require_auth();
        let guardians: Vec<Address> = env.storage().instance().get(&DataKey::Guardians).unwrap();
        let mut found = false;
        for g in guardians.iter() {
            if g == guardian {
                found = true;
                break;
            }
        }
        if !found {
            panic!("not a guardian");
        }

        let current_ledger = env.ledger().sequence();
        let timelock = current_ledger + 10;
        env.storage().instance().set(&DataKey::RecoveryTime(new_signer.clone()), &timelock);
        env.storage().instance().set(&DataKey::PendingSigner(new_signer.clone()), &new_signer);
    }

    pub fn execute_recovery(env: Env, new_signer: Address) {
        let pending: Address = env.storage().instance().get(&DataKey::PendingSigner(new_signer.clone())).unwrap();
        let recovery_time: u32 = env.storage().instance().get(&DataKey::RecoveryTime(new_signer.clone())).unwrap();
        let current_ledger = env.ledger().sequence();
        if current_ledger < recovery_time {
            panic!("timelock not expired");
        }
        env.storage().instance().set(&DataKey::Signer, &pending);
        env.storage().instance().remove(&DataKey::PendingSigner(new_signer.clone()));
        env.storage().instance().remove(&DataKey::RecoveryTime(new_signer.clone()));
    }

    pub fn __check_auth(
        env: Env,
        signature_payload: BytesN<32>,
        signature: Val,
        _auth_entries: Vec<soroban_sdk::SorobanAuthorizationEntry>,
    ) -> Result<(), symbol_short!("auth_fail")> {
        let signer: Address = env.storage().instance().get(&DataKey::Signer).unwrap();
        signer.require_auth_for_args(Vec::from_array(&env, [signature_payload.to_val(), signature]));
        Ok(())
    }
}

#[cfg(test)]
mod test;
