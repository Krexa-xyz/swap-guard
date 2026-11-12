//! End-to-end tests against Soroswap's real contracts (the wasm Soroswap
//! published for its March 2024 mainnet deployment), real Stellar Asset
//! Contract tokens, and real authorization: every call by the session key
//! goes through signed auth entries and the smart account's `__check_auth`.
//! Nothing is mocked except the signature verifier (signature checking is
//! OZ's job, not Swap Guard's).
extern crate std;

use soroban_sdk::{
    map,
    testutils::{Address as _, Ledger},
    token::{StellarAssetClient, TokenClient},
    vec,
    xdr::{
        InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
        SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        SorobanCredentials, VecM,
    },
    Address, Bytes, Env, IntoVal, Map, String, TryFromVal, Val, Vec,
};
use stellar_accounts::{
    policies::spending_limit::SpendingLimitAccountParams,
    smart_account::{AuthPayload, ContextRuleType, Signer},
};

use crate::{
    test::{Account, AccountClient, OkVerifier, SpendingLimit},
    RateFloor, SwapGuard, SwapGuardError, SwapGuardParams, UNIT,
};
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short, BytesN, Symbol,
};
use stellar_accounts::smart_account::SmartAccountError;

mod factory {
    soroban_sdk::contractimport!(file = "testdata/soroswap_factory.wasm");
}
mod router {
    soroban_sdk::contractimport!(file = "testdata/soroswap_router.wasm");
}
const PAIR_WASM: &[u8] = include_bytes!("../testdata/soroswap_pair.wasm");

struct W {
    e: Env,
    account: Address,
    router_id: Address,
    usdc: Address,
    xlm: Address,
    junk: Address,
    attacker: Address,
    session: Signer,
    router_rule: u32,
    usdc_rule: u32,
    nonce: core::cell::Cell<i64>,
}

const DEADLINE: u64 = 1_000_000;

fn setup(with_guard: bool) -> W {
    let e = Env::default();
    e.mock_all_auths_allowing_non_root_auth();
    e.cost_estimate().budget().reset_unlimited();

    // Soroswap: factory + router from published wasm.
    let admin = Address::generate(&e);
    let pair_hash = e.deployer().upload_contract_wasm(PAIR_WASM);
    let factory_id = e.register(factory::WASM, ());
    factory::Client::new(&e, &factory_id).initialize(&admin, &pair_hash);
    let router_id = e.register(router::WASM, ());
    let router = router::Client::new(&e, &router_id);
    router.initialize(&factory_id);

    // Tokens (Stellar Asset Contracts).
    let usdc = e.register_stellar_asset_contract_v2(admin.clone()).address();
    let xlm = e.register_stellar_asset_contract_v2(admin.clone()).address();
    let junk = e.register_stellar_asset_contract_v2(admin.clone()).address();
    let mint = |t: &Address, to: &Address, n: i128| StellarAssetClient::new(&e, t).mint(to, &n);

    // Honest pool: 1,000,000 USDC : 2,000,000 XLM.
    let lp = Address::generate(&e);
    mint(&usdc, &lp, 1_000_000);
    mint(&xlm, &lp, 2_000_000);
    router.add_liquidity(&usdc, &xlm, &1_000_000, &2_000_000, &0, &0, &lp, &DEADLINE);

    // Attacker pool: 10 USDC : 1,000,000 JUNK.
    let attacker = Address::generate(&e);
    mint(&usdc, &attacker, 10);
    mint(&junk, &attacker, 1_000_000);
    router.add_liquidity(&usdc, &junk, &10, &1_000_000, &0, &0, &attacker, &DEADLINE);

    // Smart account with an owner key and a session key.
    let verifier = e.register(OkVerifier, ());
    let owner = Signer::External(verifier.clone(), Bytes::from_array(&e, &[1u8; 32]));
    let session = Signer::External(verifier.clone(), Bytes::from_array(&e, &[2u8; 32]));
    let account = e.register(Account, (vec![&e, owner],));
    mint(&usdc, &account, 10_000);

    let spending = e.register(SpendingLimit, ());
    let guard = e.register(SwapGuard, ());
    let gp = SwapGuardParams {
        router: router_id.clone(),
        factory: factory_id.clone(),
        allowed_tokens: vec![&e, usdc.clone(), xlm.clone()],
        max_amount_in: 500,
        floors: vec![&e, RateFloor { token_in: usdc.clone(), token_out: xlm.clone(), min_out_per_unit: 19 * UNIT / 10 }],
    };
    let sl = SpendingLimitAccountParams { spending_limit: 1_000, period_ledgers: 17_280 };

    let mut router_policies: Map<Address, Val> = Map::new(&e);
    let mut usdc_policies: Map<Address, Val> = map![&e, (spending, sl.into_val(&e))];
    if with_guard {
        router_policies.set(guard.clone(), gp.clone().into_val(&e));
        usdc_policies.set(guard, gp.into_val(&e));
    }
    let ac = AccountClient::new(&e, &account);
    let until = Some(e.ledger().sequence() + 1_000);
    let router_rule = ac
        .add_context_rule(&ContextRuleType::CallContract(router_id.clone()), &String::from_str(&e, "session-router"), &until, &vec![&e, session.clone()], &router_policies)
        .id;
    let usdc_rule = ac
        .add_context_rule(&ContextRuleType::CallContract(usdc.clone()), &String::from_str(&e, "session-usdc"), &until, &vec![&e, session.clone()], &usdc_policies)
        .id;

    // From here on the session key's calls need real signed auth entries.
    e.set_auths(&[]);
    W { e, account, router_id, usdc, xlm, junk, attacker, session, router_rule, usdc_rule, nonce: core::cell::Cell::new(1) }
}

impl W {
    fn router(&self) -> router::Client<'_> {
        router::Client::new(&self.e, &self.router_id)
    }
}

fn sc(e: &Env, v: Val) -> ScVal {
    ScVal::try_from_val(e, &v).unwrap()
}

fn call(e: &Env, contract: &Address, f: &str, args: std::vec::Vec<Val>, subs: std::vec::Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::try_from(contract).unwrap(),
            function_name: ScSymbol(f.try_into().unwrap()),
            args: VecM::try_from(args.into_iter().map(|v| sc(e, v)).collect::<std::vec::Vec<_>>()).unwrap(),
        }),
        sub_invocations: VecM::try_from(subs).unwrap(),
    }
}

/// Signs `root` for the smart account with the session key (one context rule
/// id per context, in tree order).
fn sign(w: &W, root: SorobanAuthorizedInvocation, rule_ids: Vec<u32>) {
    let e = &w.e;
    let n = w.nonce.get();
    w.nonce.set(n + 1);
    let payload = AuthPayload { signers: map![e, (w.session.clone(), Bytes::new(e))], context_rule_ids: rule_ids };
    e.set_auths(&[SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::try_from(&w.account).unwrap(),
            nonce: n,
            signature_expiration_ledger: e.ledger().sequence() + 100,
            signature: sc(e, payload.into_val(e)),
        }),
        root_invocation: root,
    }]);
}

fn bal(w: &W, t: &Address, who: &Address) -> i128 {
    TokenClient::new(&w.e, t).balance(who)
}

/// The session key signs a swap; returns true if it went through.
fn session_swap(w: &W, amount_in: i128, min_out: i128, out_token: &Address) -> bool {
    let e = &w.e;
    let path = vec![e, w.usdc.clone(), out_token.clone()];
    let pair = w.router().router_pair_for(&w.usdc, out_token);
    let transfer = call(e, &w.usdc, "transfer", std::vec![w.account.into_val(e), pair.into_val(e), amount_in.into_val(e)], std::vec![]);
    let swap = call(
        e,
        &w.router_id,
        "swap_exact_tokens_for_tokens",
        std::vec![amount_in.into_val(e), min_out.into_val(e), path.clone().into_val(e), w.account.into_val(e), DEADLINE.into_val(e)],
        std::vec![transfer],
    );
    sign(w, swap, vec![e, w.router_rule, w.usdc_rule]);
    let r = w.router().try_swap_exact_tokens_for_tokens(&amount_in, &min_out, &path, &w.account, &DEADLINE);
    if let Err(err) = &r { std::println!("swap refused: {err:?}"); }
    r.is_ok()
}

/// The session key signs a plain USDC transfer to the attacker.
fn session_transfer_out(w: &W, amount: i128) -> bool {
    let e = &w.e;
    let root = call(e, &w.usdc, "transfer", std::vec![w.account.into_val(e), w.attacker.into_val(e), amount.into_val(e)], std::vec![]);
    sign(w, root, vec![e, w.usdc_rule]);
    TokenClient::new(e, &w.usdc).try_transfer(&w.account, &w.attacker, &amount).is_ok()
}

fn fair_min_out(w: &W, amount_in: i128) -> i128 {
    let q = w.router().router_get_amounts_out(&amount_in, &vec![&w.e, w.usdc.clone(), w.xlm.clone()]);
    q.last().unwrap() * 995 / 1000
}

// ---------- the gap, with real funds ----------

#[test]
fn e2e_gap_session_key_steals_usdc_by_plain_transfer() {
    let w = setup(false);
    assert!(session_transfer_out(&w, 900));
    assert_eq!(bal(&w, &w.usdc, &w.attacker), 900);
    assert_eq!(bal(&w, &w.usdc, &w.account), 9_100);
}

#[test]
fn e2e_gap_session_key_dumps_usdc_into_attacker_pool() {
    let w = setup(false);
    assert!(session_swap(&w, 900, 0, &w.junk));
    // The account now holds junk; the attacker pulls the USDC out of their pool.
    w.e.mock_all_auths();
    let pair = w.router().router_pair_for(&w.usdc, &w.junk);
    let lp = TokenClient::new(&w.e, &pair).balance(&w.attacker);
    w.router().remove_liquidity(&w.usdc, &w.junk, &lp, &0, &0, &w.attacker, &DEADLINE);
    // Attacker put in 10 USDC and gets back far more of the account's USDC.
    // (Soroswap locks a small amount of LP forever, so not all of it.)
    let got = bal(&w, &w.usdc, &w.attacker);
    assert!(got > 500, "attacker usdc = {got}");
    assert_eq!(bal(&w, &w.usdc, &w.account), 9_100);
}

// ---------- with Swap Guard, same attacks ----------

#[test]
fn e2e_guard_allows_a_fair_swap() {
    let w = setup(true);
    let min_out = fair_min_out(&w, 400);
    assert!(session_swap(&w, 400, min_out, &w.xlm));
    assert_eq!(bal(&w, &w.usdc, &w.account), 9_600);
    assert!(bal(&w, &w.xlm, &w.account) >= min_out);
}

#[test]
fn e2e_guard_blocks_plain_transfer() {
    let w = setup(true);
    assert!(!session_transfer_out(&w, 900));
    assert_eq!(bal(&w, &w.usdc, &w.attacker), 0);
    assert_eq!(bal(&w, &w.usdc, &w.account), 10_000);
}

#[test]
fn e2e_guard_blocks_attacker_pool() {
    let w = setup(true);
    assert!(!session_swap(&w, 400, 0, &w.junk));
    assert_eq!(bal(&w, &w.usdc, &w.account), 10_000);
}

#[test]
fn e2e_guard_blocks_below_floor_and_over_cap() {
    let w = setup(true);
    assert!(!session_swap(&w, 400, 700, &w.xlm)); // below 1.9 floor (760)
    let min_out = fair_min_out(&w, 501);
    assert!(!session_swap(&w, 501, min_out, &w.xlm)); // over per-swap cap
    assert_eq!(bal(&w, &w.usdc, &w.account), 10_000);
}

#[test]
fn e2e_guard_and_spending_limit_cap_the_day() {
    let w = setup(true);
    for _ in 0..2 {
        let m = fair_min_out(&w, 500);
        assert!(session_swap(&w, 500, m, &w.xlm));
    }
    let m = fair_min_out(&w, 10);
    assert!(!session_swap(&w, 10, m, &w.xlm));
    assert_eq!(bal(&w, &w.usdc, &w.account), 9_000);
}

#[test]
fn e2e_session_key_stops_working_after_expiry() {
    let w = setup(true);
    w.e.ledger().with_mut(|l| l.sequence_number += 1_001);
    let m = fair_min_out(&w, 400);
    assert!(!session_swap(&w, 400, m, &w.xlm));
}

// ---------- why each guarded call is refused ----------

/// Runs the account's __check_auth on the contexts of a session-key swap and
/// returns the contract error code (None = accepted).
fn swap_refusal(w: &W, amount_in: i128, min_out: i128, out_token: &Address) -> Option<u32> {
    let e = &w.e;
    let pair = w.router().router_pair_for(&w.usdc, out_token);
    let swap = Context::Contract(ContractContext {
        contract: w.router_id.clone(),
        fn_name: Symbol::new(e, "swap_exact_tokens_for_tokens"),
        args: vec![e, amount_in.into_val(e), min_out.into_val(e), vec![e, w.usdc.clone(), out_token.clone()].into_val(e), w.account.into_val(e), DEADLINE.into_val(e)],
    });
    let transfer = Context::Contract(ContractContext {
        contract: w.usdc.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![e, w.account.into_val(e), pair.into_val(e), amount_in.into_val(e)],
    });
    check_code(w, vec![e, swap, transfer], vec![e, w.router_rule, w.usdc_rule])
}

fn check_code(w: &W, contexts: Vec<Context>, ids: Vec<u32>) -> Option<u32> {
    let e = &w.e;
    let payload = AuthPayload { signers: map![e, (w.session.clone(), Bytes::new(e))], context_rule_ids: ids };
    e.try_invoke_contract_check_auth::<SmartAccountError>(&w.account, &BytesN::from_array(e, &[9u8; 32]), payload.into_val(e), &contexts)
        .err()
        .map(|err| match err {
            Ok(x) => x as u32,
            Err(soroban_sdk::InvokeError::Contract(c)) => c,
            Err(o) => panic!("unexpected: {o:?}"),
        })
}

#[test]
fn e2e_each_refusal_comes_from_swap_guard() {
    let w = setup(true);
    let e = &w.e;
    assert_eq!(swap_refusal(&w, 400, fair_min_out(&w, 400), &w.xlm), None);
    assert_eq!(swap_refusal(&w, 400, 0, &w.junk), Some(SwapGuardError::TokenNotAllowed as u32));
    assert_eq!(swap_refusal(&w, 400, 700, &w.xlm), Some(SwapGuardError::BelowOwnerFloor as u32));
    assert_eq!(swap_refusal(&w, 501, fair_min_out(&w, 501), &w.xlm), Some(SwapGuardError::AmountTooLarge as u32));
    let out = Context::Contract(ContractContext {
        contract: w.usdc.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![e, w.account.into_val(e), w.attacker.into_val(e), 900i128.into_val(e)],
    });
    assert_eq!(check_code(&w, vec![e, out], vec![e, w.usdc_rule]), Some(SwapGuardError::TransferWithoutSwap as u32));
}
