# Swap Guard

Trade-only session keys for Stellar smart accounts.

Swap Guard is a policy contract for [OpenZeppelin Stellar smart accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts)
(the accounts used by the Smart Account Kit). It lets an owner give a second key that can **only swap on Soroswap**, inside limits the contract enforces. The key can never move funds out of the account.

> Status: work in progress, **testnet only, not audited**. Do not use with real funds.

## The gap

To let a key swap on Soroswap, a smart account must authorize two calls:

1. `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, to, deadline)`
2. `path[0].transfer(account, pair, amount_in)` (made by the router)

With today's building blocks, the owner adds a context rule for the router and a context rule for the input token with the audited OZ `spending_limit` policy. `spending_limit` checks the **amount** of a `transfer`, not its **recipient**, and nothing checks the router call's arguments. So a leaked or buggy "swap-only" key can still:

- send the input token straight to any address, up to the daily cap;
- swap through a pool the attacker made with a worthless token, with `amount_out_min = 0`.

Both are shown by passing tests in [`contracts/swap-guard/src/test.rs`](contracts/swap-guard/src/test.rs) (`gap_*`). The tests run the real OZ `__check_auth` with the contexts a Soroswap swap produces.

## What Swap Guard checks

Install the same policy on the router rule and on each input-token rule.

| Context | Rule |
|---|---|
| Router | only `swap_exact_tokens_for_tokens`; `to` is the account; every token in `path` is on the allowlist; `amount_in` ≤ per-swap cap; `amount_out_min` within `max_slippage_bps` of the router's own `router_get_amounts_out` quote |
| Input token | only `transfer`, only inside an approved swap in the same ledger, only to that swap's first pair, for exactly its `amount_in` |

It reuses what already exists instead of rebuilding it:

- **daily volume** → OZ `spending_limit` on the token rule;
- **key expiry** → the context rule's own `valid_until`;
- **signatures** → OZ smart account signers and verifiers.

## Build and test

```sh
cargo test                 # 15 tests
stellar contract build     # wasm (stellar-cli 25.2+)
```

## Testnet

| | |
|---|---|
| Swap Guard policy | [`CBF6KNLMTKPUSRJIWZNJTMW24JTZQKWGX6TUAKPITQTGS7BXXDBWP2JT`](https://stellar.expert/explorer/testnet/contract/CBF6KNLMTKPUSRJIWZNJTMW24JTZQKWGX6TUAKPITQTGS7BXXDBWP2JT) |

## Roadmap (30-day sprint)

- [x] Gap tests against OZ `spending_limit`
- [x] Policy contract + unit tests, deployed to testnet
- [ ] Property tests; end-to-end testnet swaps through the Soroswap testnet router (allowed and refused tx hashes)
- [ ] TypeScript helper on the Smart Account Kit (session key made on the user's device)
- [ ] Testnet reference app, integration guide, threat model

## Trust model

- Owner: passkey signer on the user's device. Only the owner changes limits or revokes.
- Session key: made and kept on the user's device. No server holds or signs for user accounts.
- No oracle, relayer, keeper or admin key. Slippage is checked against the router's own on-chain quote, so it limits loss against the current pool price; it does not stop a price that was moved before the swap. The token allowlist keeps the key off attacker-made pools.
- Worst case if a session key leaks: swaps between allowlisted tokens, within the per-swap and daily caps, at no worse than the set slippage from the pool price at that moment, with output returned to the account, until the owner revokes or the rule expires.

## License

MIT
