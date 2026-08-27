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

## In flight (stack #55: PRs #50–#54, #56)

- [x] **P0.1** Remove the fake v1 validation path — explicit `{:unsupported_x402_version, v}` rejection (#50)
- [x] **P1.4** Route matching on decoded `path_info` segments + GHSA-3j63-5h8p-gf7c regression tests (#51)
- [x] **P1.2a** Local pre-verification checks (payTo / exact amount / validity window) before the facilitator call (#52)
- [x] **P1.3** `put_new/3` in the `Cache` behaviour; gate routed through pluggable adapters (#53)
- [x] **§6.6.2** `claim_order: :before_verify` replay-storm shedding (#54)
- [x] **§6.6** `SECURITY.md` + CDP token-reuse doc correction (#56)

## P0 — correctness and table stakes

- [ ] **P0.2** GET `/supported` (+ `/discovery/resources`) in the facilitator client; startup route
      validation; `feePayer` / `facilitatorAddress` discovery
- [ ] **P0.3** De-serialize the facilitator client: GenServer becomes a config holder, HTTP + retries
      run in the caller's process via the stateless `X402.Facilitator.HTTP`
- [ ] **P0.4** Payer client (EVM `exact`): promote the EIP-3009/EIP-712 signing out of `test/support`
      into `lib/x402/client/` behind an `X402.Signer` behaviour; Req/Finch 402 → sign → retry flow

## P1 — ecosystem parity

- [ ] **P1.1** `X402.Scheme` behaviour — per-(scheme, network) verify/sign registration keyed off
      `/supported`; refactor `PaymentSignature.validate` and PaymentGate's hardcoded flow onto it
- [ ] **P1.2b** Optional full local EIP-712 verification (EOA / ERC-1271 / ERC-6492) behind the
      optional crypto deps
- [ ] **P1.3b** Redis adapter for the replay cache (behaviour landed in #53)
- [ ] **P1.5** Upstream e2e harness entry (`x402-foundation/x402`) + third-party SDK docs listing
- [ ] **P1.6** MCP transport: client + server payment wrapper on `_meta` `x402/payment` keys

## P2 — differentiation

- [ ] **P2.1** Facilitator engine (EVM exact verify/settle) + the ecosystem's first facilitator HTTP
      scaffold — promoted from the old moonshot list; only community Rust ships one today
- [ ] **P2.2** `upto` with Permit2 + `facilitatorAddress` discovery
- [ ] **P2.3** SVM `exact` (client first)
- [ ] **P2.4** Remaining extensions: EIP-2612 + ERC-20-approval gas sponsoring, offer-receipt,
      bazaar *discovery client*
- [ ] **P2.5** Lean Phoenix-friendly paywall for browser-facing routes

## v1.0 — production polish

- [ ] LiveDashboard integration, rate limiting per wallet, multi-facilitator failover
- [ ] Guides: "Build a paid API in 5 minutes", "x402 for AI agents", "Deploying on Fly.io"
- [ ] Example Phoenix app, `mix x402.gen.paywall` generator
- [ ] Security audit of crypto verification paths
- [ ] Hex v1.0 publish

## Sequencing

**P0.2 → P1.1 → (P0.4, P1.2b)** is the critical path: the `/supported` endpoint feeds the scheme
registry, which the payer client and any new mechanism plug into. P1.5's server entry can land before
the client exists (the harness tests roles separately). MCP (P1.6) depends on P0.4 for its client half.

---

*Last updated: 2026-08-26*
