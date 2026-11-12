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

Both are shown with real funds in [`contracts/swap-guard/src/e2e.rs`](contracts/swap-guard/src/e2e.rs) (`e2e_gap_*`): Soroswap's own published router, factory and pair contracts, Stellar Asset Contract tokens, and signed auth entries checked by the smart account's real `__check_auth`. In the first test the attacker receives 900 USDC; in the second the account's USDC ends up in the attacker's pool and the attacker withdraws it.

## What Swap Guard checks

Install the same policy on the router rule and on each input-token rule.

| Context | Rule |
|---|---|
| Router | only `swap_exact_tokens_for_tokens`; `to` is the account; every token in `path` is on the allowlist; `amount_in` ≤ per-swap cap; `amount_out_min` at or above the **owner-set minimum rate** for that direction (no rate set → refused) |
| Input token | only `transfer`, only inside an approved swap in the same ledger, only to that swap's first pair, for exactly its `amount_in` |

It reuses what already exists instead of rebuilding it:

- **daily volume** → OZ `spending_limit` on the token rule;
- **key expiry** → the context rule's own `valid_until`;
- **signatures** → OZ smart account signers and verifiers.

## Build and test

```sh
cargo test                 # 26 tests: 17 unit, 9 end-to-end on Soroswap's contracts
stellar contract build     # wasm (stellar-cli 25.2+)
```

## Testnet

| | |
|---|---|
| Swap Guard policy | [`CCCRDWE6WH7DACT5TMW5AYN6EPAFLABNBAS2SK5E7MQVYQNOX2UZGS6M`](https://stellar.expert/explorer/testnet/contract/CCCRDWE6WH7DACT5TMW5AYN6EPAFLABNBAS2SK5E7MQVYQNOX2UZGS6M) |

## Roadmap (30-day sprint)

- [x] Gap tests against OZ `spending_limit`
- [x] Policy contract + unit tests, deployed to testnet
- [x] End-to-end tests on Soroswap's published contracts with real tokens and signed auth
- [ ] Property tests; multi-hop; live testnet swaps through the Soroswap testnet router (allowed and refused tx hashes)
- [ ] TypeScript helper on the Smart Account Kit (session key made on the user's device)
- [ ] Testnet reference app, integration guide, threat model

## Trust model

- Owner: passkey signer on the user's device. Only the owner changes limits or revokes.
- Session key: made and kept on the user's device. No server holds or signs for user accounts.
- No oracle, relayer, keeper or admin key. The price limit is an **owner-set minimum rate per direction**. A live pool quote is not used: it can be moved inside the same transaction, and the policy cannot call the router anyway (the router is still running when it asks for authorization, and Soroban forbids re-entry). The token allowlist keeps the key off attacker-made pools.
- Worst case if a session key leaks: swaps between allowlisted tokens, within the per-swap and daily caps, at no worse than the owner's rate floor, with output returned to the account, until the owner revokes or the rule expires.

## License

MIT
