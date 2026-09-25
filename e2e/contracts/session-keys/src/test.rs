//! Unit tests for the session-key fixture.
//!
//! They come in two layers, because the two layers fail differently.
//!
//! `require_window` is a pure function, so its tests assert the *exact*
//! `SessionKeyError` arm each case produces. That is where "an expired key is
//! refused for being expired" is actually proven.
//!
//! The `__check_auth` tests drive the whole contract through
//! `env.set_auths`, which is the path a real transaction takes. A failure
//! there reaches the caller as the host's `(Context, InvalidAction)` wrapper,
//! the same for every arm, so these assert that the contract refused and
//! which shape the refusal had — not which arm caused it. The end-to-end
//! scenario that drives this against a live host and asserts the contract's
//! own error code is scenario G in e2e_test.go.
//!
//! The delegates used here are themselves contract accounts that approve
//! anything, which keeps these tests free of real signatures: a C-address
//! delegate authenticates through its own `__check_auth`. Scenario F in
//! e2e_test.go covers G-account session keys with real soroauth signatures
//! against the live host.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, Vec,
};

use crate::{
    require_window, SessionKey, SessionKeyError, SessionKeys, SessionKeysArgs,
    SessionKeysClient,
};

/// The window every test below works against, and a ledger well inside it.
const WINDOW_FROM: u32 = 100;
const WINDOW_UNTIL: u32 = 200;
const IN_WINDOW: u32 = 150;

/// A delegate that approves everything, so the tests can drive delegation
/// without producing real signatures.
#[contract]
pub struct AlwaysApproves;

#[contractimpl]
impl CustomAccountInterface for AlwaysApproves {
    type Signature = ();
    type Error = SessionKeyError;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), SessionKeyError> {
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

fn session_key(key: &Address, from: u32, until: u32) -> SessionKey {
    SessionKey {
        key: key.clone(),
        valid_from_ledger: from,
        valid_until_ledger: until,
    }
}

fn register_account(env: &Env, keys: Vec<SessionKey>) -> Address {
    env.register(SessionKeys, SessionKeysArgs::__constructor(&keys))
}

// ---------------------------------------------------------------------------
// The window decision itself.
// ---------------------------------------------------------------------------

#[test]
fn window_accepts_a_key_inside_its_window() {
    assert_eq!(require_window(IN_WINDOW, WINDOW_FROM, WINDOW_UNTIL), Ok(()));
}

#[test]
fn window_accepts_both_inclusive_boundaries() {
    // Both bounds are inclusive. A key that is valid "from ledger 100 to
    // ledger 200" is valid in ledgers 100 and 200, not 99 and not 201.
    assert_eq!(require_window(WINDOW_FROM, WINDOW_FROM, WINDOW_UNTIL), Ok(()));
    assert_eq!(require_window(WINDOW_UNTIL, WINDOW_FROM, WINDOW_UNTIL), Ok(()));
}

#[test]
fn window_refuses_a_key_before_its_window_as_not_yet_valid() {
    assert_eq!(
        require_window(WINDOW_FROM - 1, WINDOW_FROM, WINDOW_UNTIL),
        Err(SessionKeyError::SessionNotYetValid)
    );
}

#[test]
fn window_refuses_a_key_after_its_window_as_expired() {
    assert_eq!(
        require_window(WINDOW_UNTIL + 1, WINDOW_FROM, WINDOW_UNTIL),
        Err(SessionKeyError::SessionExpired)
    );
}

#[test]
fn an_inverted_window_accepts_nothing() {
    // valid_from_ledger > valid_until_ledger is a contradiction, not a
    // permissive window. A key configured that way must never authenticate.
    let from = WINDOW_UNTIL;
    let until = WINDOW_FROM;
    for now in [0, from - 1, from, until, until + 1, u32::MAX] {
        assert!(
            require_window(now, from, until).is_err(),
            "an inverted window accepted ledger {now}"
        );
    }
}

// ---------------------------------------------------------------------------
// The contract, through the path a transaction takes.
// ---------------------------------------------------------------------------

#[test]
fn constructor_stores_the_key_set() {
    let env = Env::default();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    let account = register_account(
        &env,
        vec![
            &env,
            session_key(&first, WINDOW_FROM, WINDOW_UNTIL),
            session_key(&second, WINDOW_FROM + 10, WINDOW_UNTIL + 10),
        ],
    );
    let client = SessionKeysClient::new(&env, &account);

    let stored = client.session_keys();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored.get(0).unwrap().valid_from_ledger, WINDOW_FROM);
    assert_eq!(stored.get(1).unwrap().valid_until_ledger, WINDOW_UNTIL + 10);
}

#[test]
fn check_auth_accepts_an_in_window_session_key() {
    let env = Env::default();
    env.ledger().set_sequence_number(IN_WINDOW);

    let key = env.register(AlwaysApproves, ());
    let account = register_account(
        &env,
        vec![&env, session_key(&key, WINDOW_FROM, WINDOW_UNTIL)],
    );
    let protected = env.register(Protected, ());

    let entry = session_keys_entry(&env, &account, &protected, &[key.clone()]);
    env.set_auths(&[entry]);

    // The control for every refusal below: the same entry builder and the
    // same account, at a ledger inside the window, is accepted.
    ProtectedClient::new(&env, &protected).protected(&account);
}

#[test]
fn check_auth_refuses_an_expired_session_key() {
    let env = Env::default();
    env.ledger().set_sequence_number(WINDOW_UNTIL + 1);

    let key = env.register(AlwaysApproves, ());
    let account = register_account(
        &env,
        vec![&env, session_key(&key, WINDOW_FROM, WINDOW_UNTIL)],
    );
    let protected = env.register(Protected, ());

    let entry = session_keys_entry(&env, &account, &protected, &[key.clone()]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "an expired session key");
}

#[test]
fn check_auth_refuses_a_session_key_that_is_not_yet_valid() {
    let env = Env::default();
    env.ledger().set_sequence_number(WINDOW_FROM - 1);

    let key = env.register(AlwaysApproves, ());
    let account = register_account(
        &env,
        vec![&env, session_key(&key, WINDOW_FROM, WINDOW_UNTIL)],
    );
    let protected = env.register(Protected, ());

    let entry = session_keys_entry(&env, &account, &protected, &[key.clone()]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "a session key that is not valid yet");
}

#[test]
fn check_auth_refuses_an_unregistered_session_key() {
    let env = Env::default();
    env.ledger().set_sequence_number(IN_WINDOW);

    let registered = env.register(AlwaysApproves, ());
    let stranger = env.register(AlwaysApproves, ());
    let account = register_account(
        &env,
        vec![&env, session_key(&registered, WINDOW_FROM, WINDOW_UNTIL)],
    );
    let protected = env.register(Protected, ());

    let entry = session_keys_entry(&env, &account, &protected, &[stranger.clone()]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "an unregistered session key");
}

#[test]
fn check_auth_refuses_when_no_session_key_is_attached() {
    let env = Env::default();
    env.ledger().set_sequence_number(IN_WINDOW);

    let registered = env.register(AlwaysApproves, ());
    let account = register_account(
        &env,
        vec![&env, session_key(&registered, WINDOW_FROM, WINDOW_UNTIL)],
    );
    let protected = env.register(Protected, ());

    // A well-formed entry that names nobody. Nothing authenticates the
    // account, so authorizing would be authorizing on the strength of no one.
    let entry = session_keys_entry(&env, &account, &protected, &[]);
    env.set_auths(&[entry]);

    let result = ProtectedClient::new(&env, &protected).try_protected(&account);
    assert_auth_refused(result, "an entry with no session key");
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Asserts the host refused the invocation because __check_auth rejected it.
///
/// A failing __check_auth surfaces to the caller as (Context, InvalidAction);
/// the contract's own error code is not visible from here, so these tests
/// assert the exact outer error rather than merely "something went wrong".
/// Which `SessionKeyError` arm was returned is proven twice over: directly, by
/// the `require_window` tests above, and against the live host by scenario G
/// in e2e_test.go, which reports the raw error.
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
/// `protected.protected(account)`, naming zero or more session keys.
///
/// `signature_expiration_ledger` is set well past the window under test so
/// that the host's clock is not what these tests trip over; the contract's own
/// window is the clock under test.
fn session_keys_entry(
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
    // order; sorting by the XDR encoding is what soroauth does too.
    nodes.sort_by_key(|node| node.address.to_xdr(soroban_sdk::xdr::Limits::none()).unwrap());

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account_sc,
                    nonce: 1,
                    signature_expiration_ledger: env.ledger().sequence() + 1000,
                    // The account authenticates purely through its session
                    // keys, which CAP-71-01 permits.
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
