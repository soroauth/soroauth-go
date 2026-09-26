#![cfg(test)]
use super::*;
use soroban_sdk::{Env, testutils::Address as _};

#[test]
fn test_social_recovery_flow() {
    let env = Env::default();
    env.mock_all_auths();

    let signer = Address::generate(&env);
    let g1 = Address::generate(&env);
    let g2 = Address::generate(&env);
    let guardians = Vec::from_array(&env, [g1.clone(), g2.clone()]);

    let contract_id = env.register(SocialRecoveryAccount, (&signer, &guardians));
    let client = SocialRecoveryAccountClient::new(&env, &contract_id);

    let new_signer = Address::generate(&env);
    client.initiate_recovery(&g1, &new_signer);

    // Rejection before timelock
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute_recovery(&new_signer);
    }));
    assert!(res.is_err());

    // Advance ledger past timelock
    env.ledger().set_sequence_number(env.ledger().sequence() + 15);

    client.execute_recovery(&new_signer);
}
