//! Unit tests for the policy account fixture.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, Vec,
};

use crate::{PolicyAccount, PolicyAccountArgs, PolicyAccountClient, PolicyAccountError};

#[contract]
pub struct AlwaysApproves;

#[contractimpl]
impl CustomAccountInterface for AlwaysApproves {
    type Signature = ();
    type Error = PolicyAccountError;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), PolicyAccountError> {
        Ok(())
    }
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(_env: Env, _from: Address, _to: Address, _amount: i128) {
        // transfer logic stub
    }
}

fn register_account(env: &Env, signers: Vec<Address>, limit: i128, period: u32) -> Address {
    env.register(
        PolicyAccount,
        PolicyAccountArgs::__constructor(&signers, &limit, &period),
    )
}

#[test]
fn constructor_stores_policy_settings() {
    let env = Env::default();
    let signer = Address::generate(&env);
    let account = register_account(&env, vec![&env, signer.clone()], 500, 200);
    let client = PolicyAccountClient::new(&env, &account);

    assert_eq!(client.limit(), 500);
    assert_eq!(client.period(), 200);
    assert_eq!(client.signers().len(), 1);
}
