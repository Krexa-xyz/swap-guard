//! Tests run the real OpenZeppelin smart-account `__check_auth` with the
//! authorization contexts a Soroswap swap produces:
//!
//!   1. `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`
//!   2. `path[0].transfer(account, pair(path[0], path[1]), amount_in)`
//!
//! The "gap" tests use only today's audited building blocks (a router rule
//! plus OZ `spending_limit` on the token rule) and show what a leaked
//! "swap-only" session key can still do. The "guard" tests add Swap Guard.
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    map, symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, Bytes, BytesN, Env, IntoVal, Map, String, Symbol, TryFromVal, Val, Vec,
};
use stellar_accounts::{
    policies::{spending_limit, Policy},
    smart_account::{
        self, AuthDigestPreimage, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountError,
    },
};

use crate::{SwapGuard, SwapGuardClient, SwapGuardError, SwapGuardParams};

// ---------- test doubles ----------

/// Minimal OZ smart account (same as OZ's multisig example, minus upgrades).
#[contract]
struct Account;

#[contractimpl]
impl Account {
    pub fn __constructor(e: &Env, signers: Vec<Signer>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "owner"),
            None,
            &signers,
            &Map::new(e),
        );
    }
}

#[contractimpl]
impl CustomAccountInterface for Account {
    type Error = SmartAccountError;
    type Signature = AuthPayload;
    fn __check_auth(
        e: Env,
        payload: Hash<32>,
        signatures: AuthPayload,
        contexts: Vec<Context>,
    ) -> Result<(), SmartAccountError> {
        smart_account::do_check_auth(&e, &payload, &signatures, &contexts)
    }
}

#[contractimpl(contracttrait)]
impl SmartAccount for Account {}

/// OZ spending_limit, wrapped as a contract (same as OZ's example).
#[contract]
struct SpendingLimit;

#[contractimpl]
impl Policy for SpendingLimit {
    type AccountParams = spending_limit::SpendingLimitAccountParams;
    fn enforce(e: &Env, c: Context, s: Vec<Signer>, r: ContextRule, a: Address) {
        spending_limit::enforce(e, &c, &s, &r, &a)
    }
    fn install(e: &Env, p: Self::AccountParams, r: ContextRule, a: Address) {
        spending_limit::install(e, &p, &r, &a)
    }
    fn uninstall(e: &Env, r: ContextRule, a: Address) {
        spending_limit::uninstall(e, &r, &a)
    }
}

/// Signature verifier that accepts every signature. Signature checking is
/// OZ's job and is not what these tests are about.
#[contract]
struct OkVerifier;

#[contractimpl]
impl OkVerifier {
    pub fn verify(_e: &Env, _hash: Bytes, _key: Val, _sig: Val) -> bool {
        true
    }
    pub fn canonicalize_key(e: &Env, key: Val) -> Bytes {
        Bytes::try_from_val(e, &key).unwrap()
    }
    pub fn batch_canonicalize_key(e: &Env, keys: Vec<Val>) -> Vec<Bytes> {
        Vec::from_iter(e, keys.iter().map(|k| Bytes::try_from_val(e, &k).unwrap()))
    }
}

/// Router double with Soroswap's read interface: a fixed 1:2 price and one
/// pair address per token pair.
#[contract]
struct MockRouter;

#[contractimpl]
impl MockRouter {
    pub fn set_pair(e: Env, a: Address, b: Address, pair: Address) {
        e.storage().instance().set(&(a.clone(), b.clone()), &pair);
        e.storage().instance().set(&(b, a), &pair);
    }
    pub fn router_pair_for(e: Env, token_a: Address, token_b: Address) -> Address {
        e.storage().instance().get(&(token_a, token_b)).unwrap()
    }
    pub fn router_get_amounts_out(e: Env, amount_in: i128, path: Vec<Address>) -> Vec<i128> {
        let mut out = vec![&e, amount_in];
        let mut x = amount_in;
        for _ in 1..path.len() {
            x *= 2;
            out.push_back(x);
        }
        out
    }
}

// ---------- setup ----------

struct T {
    e: Env,
    account: Address,
    router: Address,
    usdc: Address,
    xlm: Address,
    junk: Address,
    usdc_xlm_pair: Address,
    usdc_junk_pair: Address,
    attacker: Address,
    session: Signer,
    router_rule: u32,
    usdc_rule: u32,
}

const DAILY_CAP: i128 = 1_000;
const PER_SWAP_CAP: i128 = 500;

fn setup(with_guard: bool) -> T {
    let e = Env::default();
    e.mock_all_auths();

    let verifier = e.register(OkVerifier, ());
    let owner = Signer::External(verifier.clone(), Bytes::from_array(&e, &[1u8; 32]));
    let session = Signer::External(verifier.clone(), Bytes::from_array(&e, &[2u8; 32]));
    let account = e.register(Account, (vec![&e, owner],));

    let router = e.register(MockRouter, ());
    let usdc = Address::generate(&e);
    let xlm = Address::generate(&e);
    let junk = Address::generate(&e); // worthless token, attacker-made pool
    let usdc_xlm_pair = Address::generate(&e);
    let usdc_junk_pair = Address::generate(&e);
    let rc = MockRouterClient::new(&e, &router);
    rc.set_pair(&usdc, &xlm, &usdc_xlm_pair);
    rc.set_pair(&usdc, &junk, &usdc_junk_pair);

    let spending = e.register(SpendingLimit, ());
    let guard = e.register(SwapGuard, ());
    let gp = SwapGuardParams {
        router: router.clone(),
        allowed_tokens: vec![&e, usdc.clone(), xlm.clone()],
        max_amount_in: PER_SWAP_CAP,
        max_slippage_bps: 100,
    };
    let sl = spending_limit::SpendingLimitAccountParams {
        spending_limit: DAILY_CAP,
        period_ledgers: 17_280,
    };

    let mut router_policies: Map<Address, Val> = Map::new(&e);
    let mut usdc_policies: Map<Address, Val> = map![&e, (spending.clone(), sl.into_val(&e))];
    if with_guard {
        router_policies.set(guard.clone(), gp.clone().into_val(&e));
        usdc_policies.set(guard.clone(), gp.into_val(&e));
    }

    let ac = AccountClient::new(&e, &account);
    let valid_until = Some(e.ledger().sequence() + 1_000);
    let router_rule = ac
        .add_context_rule(
            &ContextRuleType::CallContract(router.clone()),
            &String::from_str(&e, "session-router"),
            &valid_until,
            &vec![&e, session.clone()],
            &router_policies,
        )
        .id;
    let usdc_rule = ac
        .add_context_rule(
            &ContextRuleType::CallContract(usdc.clone()),
            &String::from_str(&e, "session-usdc"),
            &valid_until,
            &vec![&e, session.clone()],
            &usdc_policies,
        )
        .id;

    // From here on, no auth is mocked: every check goes through __check_auth.
    e.set_auths(&[]);

    let attacker = Address::generate(&e);
    T { e, account, router, usdc, xlm, junk, usdc_xlm_pair, usdc_junk_pair, attacker, session, router_rule, usdc_rule }
}

fn swap_ctx(t: &T, amount_in: i128, min_out: i128, path: Vec<Address>, to: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: t.router.clone(),
        fn_name: Symbol::new(&t.e, "swap_exact_tokens_for_tokens"),
        args: vec![
            &t.e,
            amount_in.into_val(&t.e),
            min_out.into_val(&t.e),
            path.into_val(&t.e),
            to.into_val(&t.e),
            (t.e.ledger().timestamp() + 60).into_val(&t.e),
        ],
    })
}

fn transfer_ctx(t: &T, token: &Address, to: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![&t.e, t.account.into_val(&t.e), to.into_val(&t.e), amount.into_val(&t.e)],
    })
}

/// Runs the account's real __check_auth, signed by the session key.
fn check(t: &T, contexts: Vec<Context>, rule_ids: Vec<u32>) -> bool {
    code(t, contexts, rule_ids).is_none()
}

/// Same as `check`, but returns the contract error code on refusal.
fn code(t: &T, contexts: Vec<Context>, rule_ids: Vec<u32>) -> Option<u32> {
    let sig = AuthPayload {
        signers: map![&t.e, (t.session.clone(), Bytes::new(&t.e))],
        context_rule_ids: rule_ids,
    };
    t.e.try_invoke_contract_check_auth::<SmartAccountError>(
        &t.account,
        &BytesN::from_array(&t.e, &[7u8; 32]),
        sig.into_val(&t.e),
        &contexts,
    )
    .err()
    .map(|err| match err {
        Ok(e) => e as u32,
        Err(soroban_sdk::InvokeError::Contract(c)) => c,
        Err(other) => panic!("unexpected host error: {other:?}"),
    })
}

/// A normal swap: 400 USDC -> XLM, quote 800, min out 792 (1% slippage).
fn good_swap(t: &T, amount: i128) -> bool {
    check(
        t,
        vec![
            &t.e,
            swap_ctx(t, amount, amount * 2 * 99 / 100, vec![&t.e, t.usdc.clone(), t.xlm.clone()], &t.account),
            transfer_ctx(t, &t.usdc, &t.usdc_xlm_pair, amount),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    )
}

// ---------- the gap: today's building blocks ----------

#[test]
fn gap_session_key_can_send_usdc_to_any_address() {
    let t = setup(false);
    // No swap at all: a plain transfer to the attacker. spending_limit only
    // checks the amount, so this is accepted.
    assert!(check(
        &t,
        vec![&t.e, transfer_ctx(&t, &t.usdc, &t.attacker, 900)],
        vec![&t.e, t.usdc_rule],
    ));
}

#[test]
fn gap_session_key_can_swap_into_attacker_pool_with_zero_min_out() {
    let t = setup(false);
    // Swap USDC into a worthless token through a pool the attacker owns,
    // accepting any output.
    assert!(check(
        &t,
        vec![
            &t.e,
            swap_ctx(&t, 900, 0, vec![&t.e, t.usdc.clone(), t.junk.clone()], &t.account),
            transfer_ctx(&t, &t.usdc, &t.usdc_junk_pair, 900),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    ));
}

#[test]
fn gap_spending_limit_still_caps_the_daily_amount() {
    let t = setup(false);
    assert!(!check(
        &t,
        vec![&t.e, transfer_ctx(&t, &t.usdc, &t.attacker, DAILY_CAP + 1)],
        vec![&t.e, t.usdc_rule],
    ));
}

// ---------- with Swap Guard ----------

#[test]
fn guard_allows_a_normal_swap() {
    let t = setup(true);
    assert!(good_swap(&t, 400));
}

#[test]
fn guard_blocks_transfer_to_any_address() {
    let t = setup(true);
    assert!(!check(
        &t,
        vec![&t.e, transfer_ctx(&t, &t.usdc, &t.attacker, 100)],
        vec![&t.e, t.usdc_rule],
    ));
}

#[test]
fn guard_blocks_unlisted_token_in_path() {
    let t = setup(true);
    assert!(!check(
        &t,
        vec![
            &t.e,
            swap_ctx(&t, 400, 800, vec![&t.e, t.usdc.clone(), t.junk.clone()], &t.account),
            transfer_ctx(&t, &t.usdc, &t.usdc_junk_pair, 400),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    ));
}

#[test]
fn guard_blocks_zero_min_out() {
    let t = setup(true);
    assert!(!check(
        &t,
        vec![
            &t.e,
            swap_ctx(&t, 400, 0, vec![&t.e, t.usdc.clone(), t.xlm.clone()], &t.account),
            transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    ));
}

#[test]
fn guard_blocks_amount_over_per_swap_cap() {
    let t = setup(true);
    assert!(!good_swap(&t, PER_SWAP_CAP + 1));
}

#[test]
fn guard_blocks_other_recipient() {
    let t = setup(true);
    assert!(!check(
        &t,
        vec![
            &t.e,
            swap_ctx(&t, 400, 792, vec![&t.e, t.usdc.clone(), t.xlm.clone()], &t.attacker),
            transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    ));
}

#[test]
fn guard_blocks_transfer_that_does_not_match_the_swap() {
    let t = setup(true);
    // Swap says 100, transfer moves 400 to the pair.
    assert!(!check(
        &t,
        vec![
            &t.e,
            swap_ctx(&t, 100, 198, vec![&t.e, t.usdc.clone(), t.xlm.clone()], &t.account),
            transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400),
        ],
        vec![&t.e, t.router_rule, t.usdc_rule],
    ));
}

#[test]
fn guard_blocks_other_router_functions() {
    let t = setup(true);
    let ctx = Context::Contract(ContractContext {
        contract: t.router.clone(),
        fn_name: Symbol::new(&t.e, "remove_liquidity"),
        args: vec![&t.e],
    });
    assert!(!check(&t, vec![&t.e, ctx], vec![&t.e, t.router_rule]));
}

#[test]
fn guard_plus_spending_limit_enforce_the_daily_cap() {
    let t = setup(true);
    assert!(good_swap(&t, 500));
    assert!(good_swap(&t, 500));
    // 1,000 spent in this window: the next swap is refused by spending_limit.
    assert!(!good_swap(&t, 1));
}

#[test]
fn session_key_expires_with_its_context_rule() {
    let t = setup(true);
    t.e.ledger().with_mut(|l| l.sequence_number += 1_001);
    assert!(!good_swap(&t, 400));
}

#[test]
fn install_rejects_bad_params() {
    let e = Env::default();
    e.mock_all_auths();
    let guard = e.register(SwapGuard, ());
    let router = Address::generate(&e);
    let rule = ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(router.clone()),
        name: String::from_str(&e, "r"),
        signers: Vec::new(&e),
        signer_ids: Vec::new(&e),
        policies: Vec::new(&e),
        policy_ids: Vec::new(&e),
        valid_until: None,
    };
    let bad = SwapGuardParams {
        router,
        allowed_tokens: vec![&e, Address::generate(&e)],
        max_amount_in: 0,
        max_slippage_bps: 100,
    };
    let r = SwapGuardClient::new(&e, &guard).try_install(&bad, &rule, &Address::generate(&e));
    assert_eq!(r.err().unwrap().ok().unwrap(), SwapGuardError::InvalidParams.into());
}

#[test]
fn refusals_come_from_the_expected_check() {
    let t = setup(true);
    let usdc_xlm = vec![&t.e, t.usdc.clone(), t.xlm.clone()];
    let rr = vec![&t.e, t.router_rule, t.usdc_rule];
    let c = |ctxs| code(&t, ctxs, rr.clone());
    assert_eq!(
        code(&t, vec![&t.e, transfer_ctx(&t, &t.usdc, &t.attacker, 100)], vec![&t.e, t.usdc_rule]),
        Some(SwapGuardError::TransferWithoutSwap as u32)
    );
    assert_eq!(
        c(vec![&t.e, swap_ctx(&t, 400, 800, vec![&t.e, t.usdc.clone(), t.junk.clone()], &t.account), transfer_ctx(&t, &t.usdc, &t.usdc_junk_pair, 400)]),
        Some(SwapGuardError::TokenNotAllowed as u32)
    );
    assert_eq!(
        c(vec![&t.e, swap_ctx(&t, 400, 0, usdc_xlm.clone(), &t.account), transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400)]),
        Some(SwapGuardError::SlippageTooHigh as u32)
    );
    assert_eq!(
        c(vec![&t.e, swap_ctx(&t, 501, 1000, usdc_xlm.clone(), &t.account), transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 501)]),
        Some(SwapGuardError::AmountTooLarge as u32)
    );
    assert_eq!(
        c(vec![&t.e, swap_ctx(&t, 400, 792, usdc_xlm.clone(), &t.attacker), transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400)]),
        Some(SwapGuardError::RecipientNotAccount as u32)
    );
    assert_eq!(
        c(vec![&t.e, swap_ctx(&t, 100, 198, usdc_xlm.clone(), &t.account), transfer_ctx(&t, &t.usdc, &t.usdc_xlm_pair, 400)]),
        Some(SwapGuardError::TransferMismatch as u32)
    );
}
