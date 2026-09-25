//! Unit tests for the threshold fixture.
//!
//! They come in two layers, because the two layers fail differently.
//!
//! `require_threshold` is a pure function, so its tests assert the *exact*
//! `ThresholdError` arm each case produces. That is where "M-1 is refused for
//! being short" is actually proven.
//!
//! The `__check_auth` tests drive the whole contract through `env.set_auths`,
//! which is the path a real transaction takes. A failure there reaches the
//! caller as the host's `(Context, InvalidAction)` wrapper, the same for every
//! arm, so these assert that the contract refused and which shape the refusal
//! had — not which arm caused it. The end-to-end scenarios that drive this
//! against a live host and assert the contract's own error code are scenarios
//! H and I in e2e_test.go.
//!
//! The delegates used here are themselves contract accounts that approve
//! anything, which keeps these tests free of real signatures: a C-address
//! delegate authenticates through its own `__check_auth`. Scenarios H and I
//! cover G-account signers with real soroauth signatures against the live host.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::Address as _,
    vec, Address, Env, Vec,
};

use crate::{
    require_threshold, ThresholdAccount, ThresholdAccountArgs, ThresholdAccountClient,
    ThresholdError,
};

/// A delegate that approves everything, so the tests can drive delegation
/// without producing real signatures.
#[contract]
pub struct AlwaysApproves;

#[contractimpl]
impl CustomAccountInterface for AlwaysApproves {
    type Signature = ();
    type Error = ThresholdError;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), ThresholdError> {
        Ok(())
    }
}

/// A contract whose operation requires the account's authorization, so the
/// delegation path is reached the way it is on-chain.
#[contract]
pub struct Protected;

#[contractimpl]
impl Protected {
    pub fn protected(_env: Env, account: Address) {
        account.require_auth();
    }
}

fn register_account(env: &Env, signers: Vec<Address>, threshold: u32) -> Address {
    env.register(
        ThresholdAccount,
        ThresholdAccountArgs::__constructor(&signers, &threshold),
    )
}

// ---------------------------------------------------------------------------
// The threshold decision itself.
// ---------------------------------------------------------------------------

#[test]
fn threshold_accepts_exactly_m_signers() {
    assert_eq!(require_threshold(2, 2), Ok(()));
}

#[test]
fn threshold_accepts_more_than_m_signers() {
    assert_eq!(require_threshold(3, 2), Ok(()));
}

#[test]
fn threshold_refuses_m_minus_one_with_its_own_error() {
    assert_eq!(
        require_threshold(1, 2),
        Err(ThresholdError::InsufficientSignatures)
    );
}

#[test]
fn threshold_refuses_zero_signers_when_any_are_required() {
    assert_eq!(
        require_threshold(0, 1),
        Err(ThresholdError::InsufficientSignatures)
    );
}

// ---------------------------------------------------------------------------
// The constructor.
// ---------------------------------------------------------------------------

#[test]
fn constructor_stores_the_policy() {
    let env = Env::default();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    let account = register_account(
        &env,
        vec![&env, first.clone(), second.clone(), third.clone()],
        2,
    );
    let policy = ThresholdAccountClient::new(&env, &account).policy();

    assert_eq!(policy.threshold, 2);
    assert_eq!(policy.signers.len(), 3);
}

#[test]
#[should_panic(expected = "threshold must be at least 1")]
fn constructor_refuses_a_zero_threshold() {
    let env = Env::default();
    register_account(&env, vec![&env, Address::generate(&env)], 0);
}

#[test]
#[should_panic(expected = "threshold exceeds the number of signers")]
fn constructor_refuses_a_threshold_it_can_never_meet() {
    let env = Env::default();
    register_account(&env, vec![&env, Address::generate(&env)], 2);
}

#[test]
#[should_panic(expected = "duplicate signer")]
fn constructor_refuses_a_duplicate_signer() {
    let env = Env::default();
    let signer = Address::generate(&env);
    register_account(&env, vec![&env, signer.clone(), signer.clone()], 2);
}

// ---------------------------------------------------------------------------
// The contract, through the path a transaction takes.
// ---------------------------------------------------------------------------

#[test]
fn check_auth_accepts_exactly_m_of_n() {
    let env = Env::default();

    let s1 = env.register(AlwaysApproves, ());
    let s2 = env.register(AlwaysApproves, ());
    let s3 = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, s1.clone(), s2.clone(), s3.clone()], 2);
    let protected = env.register(Protected, ());

    // Exactly M of N: the third signer is registered but not attached.
    let entry = threshold_entry(&env, &account, &protected, &[s1.clone(), s2.clone()]);
    env.set_auths(&[entry]);

    // The control for the refusal below: the same builder, with one more
    // signer attached, is accepted.
    ProtectedClient::new(&env, &protected).protected(&account);
}

#[test]
fn check_auth_accepts_all_n_signers() {
    let env = Env::default();

    let s1 = env.register(AlwaysApproves, ());
    let s2 = env.register(AlwaysApproves, ());
    let s3 = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, s1.clone(), s2.clone(), s3.clone()], 2);
    let protected = env.register(Protected, ());

    let entry = threshold_entry(
        &env,
        &account,
        &protected,
        &[s1.clone(), s2.clone(), s3.clone()],
    );
    env.set_auths(&[entry]);

    ProtectedClient::new(&env, &protected).protected(&account);
}

#[test]
fn check_auth_refuses_m_minus_one_signers() {
    let env = Env::default();

    let s1 = env.register(AlwaysApproves, ());
    let s2 = env.register(AlwaysApproves, ());
    let s3 = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, s1.clone(), s2.clone(), s3.clone()], 2);
    let protected = env.register(Protected, ());

    let entry = threshold_entry(&env, &account, &protected, &[s1.clone()]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "a single signer against a threshold of two");
}

#[test]
fn check_auth_refuses_an_unregistered_signer() {
    let env = Env::default();

    let s1 = env.register(AlwaysApproves, ());
    let s2 = env.register(AlwaysApproves, ());
    let stranger = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, s1.clone(), s2.clone()], 2);
    let protected = env.register(Protected, ());

    // Two delegates are attached, so the threshold is met by count; the
    // refusal has to come from the signer not being registered.
    let entry = threshold_entry(&env, &account, &protected, &[s1.clone(), stranger.clone()]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "an unregistered signer");
}

#[test]
fn check_auth_refuses_when_no_signers_are_attached() {
    let env = Env::default();

    let s1 = env.register(AlwaysApproves, ());
    let account = register_account(&env, vec![&env, s1.clone()], 1);
    let protected = env.register(Protected, ());

    let entry = threshold_entry(&env, &account, &protected, &[]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "an entry with no signers");
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Asserts the host refused the invocation because __check_auth rejected it.
///
/// A failing __check_auth surfaces to the caller as (Context, InvalidAction);
/// the contract's own error code is not visible from here, so these tests
/// assert the exact outer error rather than merely "something went wrong".
/// Which `ThresholdError` arm was returned is proven twice over: directly, by
/// the `require_threshold` tests above, and against the live host by scenario
/// I in e2e_test.go, which reports the raw error.
fn assert_auth_refused<T: core::fmt::Debug>(
    result: Result<T, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
    what: &str,
) {
    match result {
        Err(Ok(error)) => {
            let expected = soroban_sdk::Error::from_type_and_code(
                soroban_sdk::xdr::ScErrorType::Context,
                soroban_sdk::xdr::ScErrorCode::InvalidAction,
            );
            assert_eq!(error, expected, "{} failed with an unexpected error", what);
        }
        other => panic!("{} was not refused as expected: {:?}", what, other),
    }
}

/// Builds a delegates-arm authorization entry for `account` covering a call to
/// `protected.protected(account)`, naming zero or more signers.
fn threshold_entry(
    env: &Env,
    account: &Address,
    protected: &Address,
    delegates: &[Address],
) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
    use soroban_sdk::xdr::{
        InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
        SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
        SorobanDelegateSignature, StringM, VecM, WriteXdr,
    };

    let account_sc: ScAddress = account.try_into().unwrap();
    let protected_sc: ScAddress = protected.try_into().unwrap();
    let account_arg: ScVal = account.try_into().unwrap();

    let mut nodes = std::vec::Vec::new();
    for delegate in delegates {
        let delegate_sc: ScAddress = delegate.try_into().unwrap();
        nodes.push(SorobanDelegateSignature {
            address: delegate_sc,
            signature: ScVal::Void,
            nested_delegates: VecM::default(),
        });
    }
    // CAP-71-01 requires each delegates array to be in ascending address
    // order; the host refuses anything else, as the module documentation
    // quotes. Sorting by the XDR encoding is what soroauth does too.
    nodes.sort_by_key(|node| node.address.to_xdr(soroban_sdk::xdr::Limits::none()).unwrap());

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account_sc,
                    nonce: 1,
                    signature_expiration_ledger: env.ledger().sequence() + 1000,
                    // The account authenticates purely through its delegates,
                    // which CAP-71-01 permits.
                    signature: ScVal::Void,
                },
                delegates: VecM::try_from(nodes).unwrap(),
            },
        ),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: protected_sc,
                function_name: ScSymbol(StringM::try_from("protected").unwrap()),
                args: VecM::try_from(std::vec![account_arg]).unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    }
}
