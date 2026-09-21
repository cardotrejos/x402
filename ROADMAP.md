# x402 Elixir SDK — Roadmap

> Living document. Last refreshed 2026-09-16 from a comparison of this SDK
> against upstream [x402-foundation/x402](https://github.com/x402-foundation/x402)
> (v2 specification, HTTP/MCP transports, extension specs, and the SDK
> feature matrix at that date).

## Where we are

`0.6.1` ships the complete v2 protocol surface for every role:

- Protocol primitives: `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` /
  `PAYMENT-RESPONSE` codecs with 8 KB header caps, CAIP-2 networks.
- Payer client: `X402.Client` (+ Finch and MCP drivers), signers for EVM and
  Solana keys, `exact` (EIP-3009, SVM) and `upto` (Permit2) signing.
- Resource server: `X402.Plug.PaymentGate` (verify-before-handler,
  settle-after-response, canonical replay keys, ETS/Redis claim caches,
  local EVM verification, browser paywall) and `X402.MCP.Server`.
- Facilitator: `X402.Facilitator` client (CDP auth, hooks, `/supported`,
  discovery) and on-chain engines (`Engine` for EVM, `SVMEngine` for
  Solana) behind `X402.Plug.Facilitator`.
- Extensions: payment-identifier, sign-in-with-x, bazaar, gas sponsoring
  (EIP-2612 / ERC-20 approval), offer-receipt.
- Quality: 95 % coverage floor, dialyzer/credo clean, optional-dependency
  build, downstream consumer check, live CDP smoke tests.

## Gap analysis against upstream (2026-09-16)

| Area | Upstream x402 | This SDK | Plan |
|------|---------------|----------|------|
| Core v2 protocol, HTTP transport | stable | complete | — |
| `EXTENSION-RESPONSES` facilitator sidechannel | HTTP transport §7.2.1 | missing | **0.7.0** |
| `payment-identifier` extension | `payment-identifier` key, `info.id`/`info.required`, 409 on fingerprint mismatch | legacy `paymentIdentifier` only | **0.7.0** (dual format), legacy removed in 1.0.0 |
| `sign-in-with-x` extension | CAIP-122 header, challenge advertisement, `invalid_siwx_*` codes, EVM + Solana | legacy `{message, signature}` header, EVM only, no gate integration | **0.7.0** (dual format), legacy removed in 1.0.0 |
| Bazaar discovery metadata | sanitised service name / tags / icon URL, `routeTemplate` | unvalidated | **0.7.0** |
| Client `paymentFlow` rule | only `authorization` (or absent) is payable | any value accepted | **0.7.0** |
| Supply chain | pinned actions, least-privilege tokens | floating action tags | **0.7.0** |
| `exact` on EVM via Permit2 (`permit2Authorization` payload variant) | shipped | EIP-3009 only | 0.8.0 |
| Client default spend controls (per-request / session ceilings) | shipped | none by default | 0.8.0 |
| Dynamic price / `payTo`, `routeTemplate` + `pathParams` | shipped | static route maps | 0.8.0 |
| `builder-code` extension | shipped | missing | 0.8.0 |
| Resource-server hooks `on_verified_payment_canceled`, `on_protected_request`; extension hook adapters | shipped | partial (facilitator hooks only) | 0.8.0 |
| MCP client hooks | shipped | missing | 0.8.0 |
| Bazaar `/discovery/search` | shipped | `/discovery/resources` only | 0.8.0 |
| Automatic SIWX in Finch / MCP clients | shipped | manual | 0.8.0 |
| `batch-settlement`, `auth-capture`, `extension-auth-hints`, `http-message-signatures` extensions | shipped | missing | 0.9.0 |
| `upto` on Solana | shipped | missing | 0.9.0 |
| LiveDashboard page, per-wallet rate limiting, multi-facilitator failover | n/a (Elixir-specific polish) | missing | 0.9.0 |

## Release train

### 0.7.0 — spec conformance (in progress)

- [x] CI hardening: pinned actions, `contents: read` token
- [x] Client rejects requirements whose `extra.paymentFlow` is not `authorization`
- [x] Bazaar metadata sanitisers (`X402.Extensions.Bazaar.Metadata`, `:route_template`)
- [x] `EXTENSION-RESPONSES` sidechannel (`X402.ExtensionResponses`, facilitator client,
  gate assign + telemetry, facilitator plug emission)
- [x] `payment-identifier` spec format: `extension/1`, `generate_id/0`, `extract_id/1`,
  `fingerprint/2`, client `enricher/1`; gate + MCP enforce `required` (400) and
  fingerprint conflicts (409); legacy format deprecated
- [x] `sign-in-with-x` spec format: challenge advertisement, CAIP-122 messages for
  EVM and Solana, `sign/3`, `verify/2`, `Signer.sign_message/2`, Ed25519 verifier,
  `X402.Extensions.SIWX.Server`, gate `siwx:` option; legacy header deprecated
- [ ] Docs: CHANGELOG, guides, README

### 0.8.0 — ecosystem parity

- [ ] `exact` via Permit2 on EVM (client signing, local verification, engine settlement)
- [ ] Client spend controls: default per-request ceiling and session budget
- [ ] Dynamic route pricing: `price`/`pay_to` functions, `routeTemplate` + `pathParams`
- [ ] `builder-code` extension (advertise, echo, validate)
- [ ] Gate hooks `on_verified_payment_canceled` / `on_protected_request`; extension hook adapters
- [ ] MCP client hooks mirroring the Finch client
- [ ] Bazaar `/discovery/search` client
- [ ] Automatic SIWX in `X402.Client.Finch` / `X402.MCP.Client`

### 0.9.0 — advanced extensions and operations

- [ ] `batch-settlement`, `auth-capture`, `extension-auth-hints`, `http-message-signatures`
- [ ] `upto` on Solana
- [ ] LiveDashboard page over the existing telemetry
- [ ] Per-wallet rate limiting in the gate
- [ ] Multi-facilitator failover for `X402.Facilitator`

### 1.0.0 — stable API

- [ ] Remove the legacy `paymentIdentifier` and SIWX `{message, signature}` formats and the
  deprecated functions listed under "Compatibility policy"
- [ ] Independent security audit of the crypto verification and settlement paths
- [ ] Upstream e2e harness PR (`integration/e2e_server/`) merged and a passing
  cross-language run; SDK listed in the upstream feature matrix
- [ ] Live EVM exact/upto and SVM exact settlement matrix, including Redis replay
  protection and pending-settlement reconciliation
- [ ] Public API, error-contract and migration-policy review; `guides/upgrading.md`
- [ ] Guides ("Build a paid API in 5 minutes", "x402 for AI agents", deployment),
  example Phoenix app, `mix x402.gen.paywall`
- [ ] Hex 1.0.0 publish

## Compatibility policy

`0.7.x` accepts both the spec wire formats and the pre-0.7.0 formats. Legacy
input emits `[:x402, :payment_identifier, :legacy]` / `[:x402, :siwx, :legacy]`
telemetry plus a one-time warning. `1.0.0` removes:

| Deprecated | Replacement |
|------------|-------------|
| `extensions["paymentIdentifier"]` (Base64 `{"paymentId"}` or map) | `extensions["payment-identifier"]["info"]["id"]` |
| `X402.Extensions.PaymentIdentifier.encode/1`, `decode/1`, `fetch_payment_id/1` | `extension/1`, `extract_id/1`, `enricher/1` |
| `SIGN-IN-WITH-X` = Base64 `{"message","signature"}` | Base64 CAIP-122 fields (`X402.Extensions.SIWX.encode_signed/1`) |
| `X402.Extensions.SIWX.encode_header/1`, `decode_header/1` | `encode_signed/1`, `decode_signed/1`, `sign/3`, `verify/2` |
