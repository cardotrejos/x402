# x402 Elixir SDK — Roadmap

> Internal roadmap. Living document — update as priorities shift.
> Priorities and effort estimates come from the ecosystem gap analysis in
> [docs/ecosystem-comparison.md](docs/ecosystem-comparison.md) (§8); item tags
> (P0.1, P1.4, …) reference its numbering.

## Current State (v0.5.x)

✅ x402 v2 protocol primitives (PaymentRequired / PaymentSignature / PaymentResponse, 8KB header caps)
✅ Plug middleware (PaymentGate): verify-before-handler, settle-after-response, replay claim, extension echo
✅ Facilitator client (verify/settle) with CDP JWT auth and Ecto-style runtime config
✅ Extensions: payment_identifier (ETS cache), SIWX (local EIP-191 recovery), bazaar builder
✅ Lifecycle hooks, telemetry spans, wallet validation (EVM + Solana)
✅ >90% coverage, dialyzer-clean, live CDP smoke tests, published on Hex.pm

## Gap-closure sprint — all P0/P1/P2 items shipped

The full ecosystem gap list from [docs/ecosystem-comparison.md](docs/ecosystem-comparison.md) §8 is
now merged to `main` across 24 PRs. The SDK is role-complete (payer client, resource-server
middleware, facilitator client, **and** a facilitator engine), speaks HTTP and MCP transports, and
covers EVM (`exact`/`upto`) and Solana (`exact`) schemes.

### P0 — correctness and table stakes

- [x] **P0.1** Remove the fake v1 validation path — explicit `{:unsupported_x402_version, v}` rejection (#50)
- [x] **P0.2** GET `/supported` + `/discovery/resources` in the facilitator client; feePayer / facilitatorAddress discovery (#61)
- [x] **P0.3** De-serialized facilitator client — GenServer holds config, HTTP + retries run in the caller (#60)
- [x] **P0.4** Payer client — `X402.Signer`, `X402.EIP3009` signing, `X402.Client` + Finch 402→sign→retry (#58)

### P1 — ecosystem parity

- [x] **P1.1** `X402.Scheme` behaviour + registry (CAIP-2 wildcards); `ExactEVM` / `UptoEVM` / `ExactSVM` (#70)
- [x] **P1.2a** Local pre-verification checks before the facilitator call (#52)
- [x] **P1.2b** Full local EVM verification — `X402.Verify.EVM`, `X402.RPC`, `X402.ERC6492` (EOA / ERC-1271 / ERC-6492, simulation) (#67)
- [x] **P1.3** `put_new/3` Cache behaviour; gate routed through pluggable adapters (#53)
- [x] **P1.3b** Redis replay-cache adapter over optional `redix` (#69)
- [x] **P1.4** Route matching on decoded `script_name ++ path_info` + GHSA-3j63-5h8p-gf7c regression tests (#51)
- [x] **P1.5** Upstream e2e harness component (`integration/e2e_server/`); the foundation PR is staged on a fork (#59)
- [x] **P1.6** MCP transport — `X402.MCP` client + server payment wrapper on `_meta` `x402/payment` keys (#64)

### P2 — differentiation

- [x] **P2.1** Facilitator engine + HTTP scaffold — `X402.Facilitator.Engine`, `X402.Plug.Facilitator`, runnable example (#73)
- [x] **P2.2** `upto` via Permit2 witness signing — `X402.Permit2` (#71)
- [x] **P2.3** SVM `exact` — `X402.Base58`, `X402.Solana`, `X402.Signer.SolanaKey`, `X402.Scheme.ExactSVM` (#74)
- [x] **P2.4** Gas-sponsoring extensions (EIP-2612, ERC-20 approval) (#65) + offer-receipt (EIP-712 & JWS) (#68); bazaar discovery client (#62)
- [x] **P2.5** Browser paywall — content negotiation + `X402.Paywall` / `X402.Paywall.Default` (#66)

### Security recommendations (report §6.6)

- [x] `claim_order: :before_verify` replay-storm shedding (#54)
- [x] `SECURITY.md` + CDP token-reuse doc correction (#56)

## Next up — production polish (v1.0)

- [ ] LiveDashboard integration, rate limiting per wallet, multi-facilitator failover
- [ ] Guides: "Build a paid API in 5 minutes", "x402 for AI agents", "Deploying on Fly.io"
- [ ] Example Phoenix app, `mix x402.gen.paywall` generator
- [ ] Security audit of crypto verification paths
- [ ] Hex v1.0 publish

## Follow-ups noted during the sprint — closed 2026-08-28

- [x] `X402.Verify.EVM` wired into the gate as the inline `local_verification` option
  (`:structural` / `:signature` / `:full`, exact-EVM only, fail-closed on infrastructure errors).
- [x] Facilitator engine: counterfactual ERC-6492 settlement behind the `eip6492_allowed_factories`
  allowlist (+ `max_deploy_gas_limit` ceiling), ERC-20 Transfer-event receipt verification, and
  pending-settlement reconciliation (`X402.Facilitator.PendingSettlementStore` + ETS adapter,
  delete-before-reconcile fast path); the gate retries a `settlement_pending` settle exactly once.
- [x] SVM on-chain verify/settle: `X402.Solana.RPC`, `X402.Verify.SVM` (local Ed25519 + static path +
  simulation, TS `invalid_exact_svm_*` reasons), `X402.Facilitator.SVMEngine` (fee-payer co-sign,
  `duplicate_settlement` dedup, confirmation polling), and a multi-engine `X402.Plug.Facilitator`.
- [x] Hardened replay keys: the gate's dedup claim now keys on signature-covered payment identity
  (EIP-3009 from+nonce / Permit2 owner+nonce / SVM message-bytes hash) instead of raw header bytes,
  and the `payment_identifier` extension's `paymentId` is decoded, validated, and surfaced.
- [ ] Open the staged upstream e2e PR from the fork to `x402-foundation/x402`
  (`cardotrejos/x402-1@feat/elixir-e2e-server` — merges cleanly at upstream HEAD; publishing it is a
  maintainer action under the repo owner's name).

---

*Last updated: 2026-08-28 — sprint follow-ups closed (inline verification, 6492 settlement,
reconciliation, SVM facilitator, canonical replay keys).*
