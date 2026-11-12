//! # Swap Guard
//!
//! An OpenZeppelin smart-account policy that turns a delegated signer into a
//! trade-only session key for the Soroswap router.
//!
//! Install the same policy contract on two kinds of context rule of a smart
//! account:
//!
//! * the rule for the **router** (`CallContract(router)`): the session key may
//!   only call `swap_exact_tokens_for_tokens`, with `to` equal to the smart
//!   account, every token in `path` on the allowlist, `amount_in` at or below
//!   the per-swap cap, and `amount_out_min` within `max_slippage_bps` of the
//!   router's own on-chain quote;
//! * the rule for each **input token** (`CallContract(token)`): the session key
//!   may only `transfer` that token when the same authorization also contains
//!   a guarded router swap, and only to that swap's first pair, for exactly
//!   that swap's `amount_in`.
//!
//! The second rule closes a gap in the current building blocks: a swap needs
//! the account to authorize `token.transfer(account, pair, amount_in)`, and
//! the audited `spending_limit` policy limits the amount of a transfer but not
//! its recipient. Without Swap Guard on the token rule, a "swap-only" key can
//! send the token to any address.
//!
//! Daily volume is left to OZ `spending_limit` (install it on the token rule
//! next to Swap Guard). Key expiry is left to the context rule's own
//! `valid_until`.
#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractclient, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, Address, Env, Symbol, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, ContextRuleType, Signer},
};

/// Subset of the Soroswap router interface that the policy reads.
#[contractclient(name = "SoroswapRouterClient")]
pub trait SoroswapRouter {
    fn router_get_amounts_out(e: Env, amount_in: i128, path: Vec<Address>) -> Vec<i128>;
    fn router_pair_for(e: Env, token_a: Address, token_b: Address) -> Address;
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SwapGuardError {
    NotInstalled = 4100,
    AlreadyInstalled = 4101,
    InvalidParams = 4102,
    RuleNotForRouterOrToken = 4103,
    NoSigners = 4104,
    FunctionNotAllowed = 4105,
    BadArguments = 4106,
    RecipientNotAccount = 4107,
    TokenNotAllowed = 4108,
    AmountTooLarge = 4109,
    SlippageTooHigh = 4110,
    TransferWithoutSwap = 4111,
    TransferMismatch = 4112,
}

/// Installation parameters. The same values are used on the router rule and on
/// each token rule.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SwapGuardParams {
    /// Soroswap router the session key may call.
    pub router: Address,
    /// Tokens that may appear anywhere in a swap path.
    pub allowed_tokens: Vec<Address>,
    /// Largest `amount_in` for one swap.
    pub max_amount_in: i128,
    /// Largest accepted gap between the router quote and `amount_out_min`,
    /// in basis points (100 = 1%).
    pub max_slippage_bps: u32,
}

/// A swap approved on the router rule, waiting for its matching token
/// transfer inside the same `__check_auth` call.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingTransfer {
    pub token: Address,
    pub pair: Address,
    pub amount: i128,
    /// Ledger where the swap was approved. A transfer is only matched in the
    /// same ledger, so a leftover approval cannot be used later.
    pub ledger: u32,
}

#[contracttype]
enum Key {
    Params(Address, u32),
    Pending(Address),
}

const BPS: i128 = 10_000;

fn swap_fn(e: &Env) -> Symbol {
    Symbol::new(e, "swap_exact_tokens_for_tokens")
}

fn arg<T: TryFromVal<Env, soroban_sdk::Val>>(e: &Env, args: &Vec<soroban_sdk::Val>, i: u32) -> T {
    let v = args.get(i).unwrap_or_else(|| panic_with_error!(e, SwapGuardError::BadArguments));
    T::try_from_val(e, &v).unwrap_or_else(|_| panic_with_error!(e, SwapGuardError::BadArguments))
}

fn params(e: &Env, account: &Address, rule_id: u32) -> SwapGuardParams {
    e.storage()
        .persistent()
        .get(&Key::Params(account.clone(), rule_id))
        .unwrap_or_else(|| panic_with_error!(e, SwapGuardError::NotInstalled))
}

fn enforce_swap(e: &Env, p: &SwapGuardParams, fn_name: &Symbol, args: &Vec<soroban_sdk::Val>, account: &Address) {
    if *fn_name != swap_fn(e) {
        panic_with_error!(e, SwapGuardError::FunctionNotAllowed)
    }
    let amount_in: i128 = arg(e, args, 0);
    let amount_out_min: i128 = arg(e, args, 1);
    let path: Vec<Address> = arg(e, args, 2);
    let to: Address = arg(e, args, 3);

    if to != *account {
        panic_with_error!(e, SwapGuardError::RecipientNotAccount)
    }
    if path.len() < 2 || amount_in <= 0 || amount_out_min < 0 {
        panic_with_error!(e, SwapGuardError::BadArguments)
    }
    for t in path.iter() {
        if !p.allowed_tokens.contains(&t) {
            panic_with_error!(e, SwapGuardError::TokenNotAllowed)
        }
    }
    if amount_in > p.max_amount_in {
        panic_with_error!(e, SwapGuardError::AmountTooLarge)
    }

    let router = SoroswapRouterClient::new(e, &p.router);
    let quote = router.router_get_amounts_out(&amount_in, &path);
    let quoted_out = quote.last().unwrap_or_else(|| panic_with_error!(e, SwapGuardError::BadArguments));
    // amount_out_min >= quoted_out * (1 - bps)
    if amount_out_min * BPS < quoted_out * (BPS - p.max_slippage_bps as i128) {
        panic_with_error!(e, SwapGuardError::SlippageTooHigh)
    }

    let pending = PendingTransfer {
        token: path.get_unchecked(0),
        pair: router.router_pair_for(&path.get_unchecked(0), &path.get_unchecked(1)),
        amount: amount_in,
        ledger: e.ledger().sequence(),
    };
    e.storage().temporary().set(&Key::Pending(account.clone()), &pending);
}

fn enforce_transfer(e: &Env, token: &Address, fn_name: &Symbol, args: &Vec<soroban_sdk::Val>, account: &Address) {
    if *fn_name != symbol_short!("transfer") {
        panic_with_error!(e, SwapGuardError::FunctionNotAllowed)
    }
    let from: Address = arg(e, args, 0);
    let to: Address = arg(e, args, 1);
    let amount: i128 = arg(e, args, 2);

    let key = Key::Pending(account.clone());
    let pending: PendingTransfer = e
        .storage()
        .temporary()
        .get(&key)
        .unwrap_or_else(|| panic_with_error!(e, SwapGuardError::TransferWithoutSwap));
    // One swap authorizes exactly one transfer.
    e.storage().temporary().remove(&key);

    if from != *account || pending.token != *token || pending.pair != to || pending.amount != amount
        || pending.ledger != e.ledger().sequence()
    {
        panic_with_error!(e, SwapGuardError::TransferMismatch)
    }
}

#[contract]
pub struct SwapGuard;

#[contractimpl]
impl Policy for SwapGuard {
    type AccountParams = SwapGuardParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if authenticated_signers.is_empty() {
            panic_with_error!(e, SwapGuardError::NoSigners)
        }
        let p = params(e, &smart_account, context_rule.id);

        match context {
            Context::Contract(ContractContext { contract, fn_name, args }) => {
                if contract == p.router {
                    enforce_swap(e, &p, &fn_name, &args, &smart_account)
                } else if p.allowed_tokens.contains(&contract) {
                    enforce_transfer(e, &contract, &fn_name, &args, &smart_account)
                } else {
                    panic_with_error!(e, SwapGuardError::RuleNotForRouterOrToken)
                }
            }
            _ => panic_with_error!(e, SwapGuardError::FunctionNotAllowed),
        }
    }

    fn install(e: &Env, p: SwapGuardParams, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        if p.max_amount_in <= 0 || p.max_slippage_bps > 10_000 || p.allowed_tokens.len() < 2 {
            panic_with_error!(e, SwapGuardError::InvalidParams)
        }
        match &context_rule.context_type {
            ContextRuleType::CallContract(c) if *c == p.router || p.allowed_tokens.contains(c) => {}
            _ => panic_with_error!(e, SwapGuardError::RuleNotForRouterOrToken),
        }
        let key = Key::Params(smart_account, context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, SwapGuardError::AlreadyInstalled)
        }
        e.storage().persistent().set(&key, &p);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        e.storage().persistent().remove(&Key::Params(smart_account, context_rule.id));
    }
}

#[contractimpl]
impl SwapGuard {
    pub fn get_params(e: Env, smart_account: Address, context_rule_id: u32) -> SwapGuardParams {
        params(&e, &smart_account, context_rule_id)
    }
}

#[cfg(test)]
mod test;
