//! Unit tests for the policy account fixture.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, Vec,
};

use crate::{PolicyAccount, PolicyAccountClient, PolicyAccountError};
use crate::{PolicyAccount, PolicyAccountArgs, PolicyAccountClient, PolicyAccountError};


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
fn register_account(env: &Env, signers: Vec<Address>, limit: i128, period: u32) -> Address {
    env.register(
        PolicyAccount,
        (&signers, &limit, &period),
    )
}

@test
fn constructor_stores_policy_settings() {
    let env = Env::default();
    let signer = Address::generate(&env);
    let account = register_account(&env, vec![&env, signer.clone()], 500, 200);
    let client = PolicyAccountClient::new(&env, &account);

    assert_eq!(client.limit(), 500);
    assert_eq!(client.period(), 200);
    assert_eq!(client.signers().len(), 1);
}

#[test]
fn spent_in_period_tracks_usage_and_limit() {
    let env = Env::default();
    let signer = Address::generate(&env);
    let account = register_account(&env, vec![&env, signer.clone()], 100, 100);
    let client = PolicyAccountClient::new(&env, &account);

    assert_eq!(client.spent_in_period(&0), 0);
}
