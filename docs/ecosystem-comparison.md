# x402 Ecosystem Comparison — SDKs, Gaps, and Roadmap

**Date:** 2026-08-26
**Audience:** maintainers of the Elixir x402 SDK (Hex package `x402`, v0.5.0 in-repo; v0.4.1 is the latest published Hex release)
**Baseline for code-level claims:** the official monorepo cloned at commit `dd927a2` (2026-04-21, the `coinbase/x402` fork), referenced below as `x402-upstream/`. The canonical repo is now `x402-foundation/x402`; §2.6 documents the delta between that snapshot and foundation HEAD `8468e3a` (2026-08-26). Elixir paths are relative to this repo's root.

**Method:** produced by a multi-agent deep read of the upstream TypeScript/Python/Go/Java SDKs, the full spec tree, the examples/e2e harness, and this SDK, plus web research on community SDKs and facilitators. Sixteen load-bearing claims (tagged `matrix/C1–C8`, `security/C1–C8` below) were independently re-verified against source with file-and-line evidence; two came back *partial* and their corrections are incorporated. Adoption numbers were checked directly against the GitHub/npm/PyPI/crates.io/hex.pm APIs on 2026-08-26.

---

## 1. Executive Summary

**State of the ecosystem.** x402 has consolidated around protocol **v2** (three `PAYMENT-*` headers carrying Base64 JSON; `x402Version: 2`), governed by the x402 Foundation under the Linux Foundation (launched April 2026; Coinbase contributed the protocol, and the repo moved to `x402-foundation/x402` — 6,543 stars, 1,968 forks, ~310 contributors; `coinbase/x402` is now a development fork). The official monorepo ships four SDKs — TypeScript (the reference implementation), Python, Go, and a minimal Java client — plus a spec tree covering schemes `exact` and `upto` in production (`auth-capture` and `batch-settlement` incoming), three transports (HTTP, MCP, A2A), 8 per-chain `exact` bindings at our snapshot growing to 16 at HEAD, and seven-plus extensions. TS, Python, and Go are role-complete: payer client, resource-server middleware for the ecosystem's major web frameworks, a facilitator HTTP client, **and a full local facilitator verify/settle engine** with real cryptography (EIP-712 incl. ERC-1271/6492, on-chain simulation, SVM instruction whitelisting). A convention-based cross-language e2e interop harness (`x402-upstream/e2e/`) exercises clients × servers × facilitators across all three.

**Where the Elixir SDK stands.** We are a well-engineered but **role-narrow** SDK: v2 headers, a Plug resource-server middleware, and a facilitator HTTP client — nothing else. Within that narrow scope we are genuinely ahead of the official SDKs on operational hardening (see §9): the only SDK with a pre-decode header size cap, the only resource-server middleware with built-in replay/dedup, the only SDK that enforces `https://` on facilitator URLs, and the only one shipping facilitator (CDP) auth in-tree. But we cannot *pay* (no client role — verified matrix/C1), we cannot *verify* (no local crypto on payment signatures — verified matrix/C6, security/C2), our facilitator client speaks only 2 of the 4 facilitator endpoints (verified matrix/C2), our "v1" support validates a wire format that exists nowhere (verified matrix/C3), and all facilitator traffic serializes through one GenServer doing blocking HTTP with retry sleeps inside `handle_call` (verified matrix/C7).

**The five most important gaps (detail in §8):**

1. **No payer client** — the entire "agentic payments" demand side is closed to Elixir. The only EIP-3009 signing code we have lives in `test/support/x402_test_payments.ex` and is excluded from the Hex package (matrix/C1).
2. **Fake v1 path, zero v1 interop** — our "v1" validator requires `~w(transactionHash network scheme payerWallet)`, a shape matching no published x402 wire format, and we never read the `X-PAYMENT` header v1 mandates (matrix/C3). This is worse than not supporting v1: it looks like support.
3. **Facilitator client missing GET `/supported` and `/discovery/resources`** — so startup route validation, SVM `feePayer` discovery, and `upto` `facilitatorAddress` discovery are all impossible (matrix/C2).
4. **Facilitator GenServer is a throughput bottleneck** — blocking Finch calls plus `:timer.sleep` retry backoff inside `handle_call`, worst case ~15s per call against a 5s default caller timeout (matrix/C7).
5. **No MCP transport** — all three official SDKs ship MCP client+server payment layers keyed on `_meta` `x402/payment` keys; our `bazaar.ex` can only *describe* an MCP tool as discovery metadata (matrix/C5).

Secondary but strategic: our replay guard is per-node ETS with no pluggable distributed backend, so clustered BEAM deployments — the deployments Elixir is *for* — can execute the resource handler twice for one payment (matrix/C4); and we are absent from the upstream e2e harness, so we have no official interop proof (matrix/C8).

---

## 2. The x402 Protocol Landscape

### 2.1 v1 vs v2

| | v1 | v2 |
|---|---|---|
| Spec | `x402-upstream/specs/x402-specification-v1.md` | `specs/x402-specification-v2.md` |
| Headers (HTTP) | `X-PAYMENT` (client→server), `X-PAYMENT-RESPONSE` (server→client) — `specs/transports-v1/http.md:46-97` | `PAYMENT-REQUIRED` (402 body companion), `PAYMENT-SIGNATURE` (client→server), `PAYMENT-RESPONSE` (server→client) — `specs/transports-v2/http.md:11-166` |
| Payment payload | `{x402Version: 1, scheme, network, payload: {signature, authorization: {from, to, value, validAfter, validBefore, nonce}}}` | `{x402Version: 2, resource: {url, description, mimeType}, accepted: <one PaymentRequirements entry echoed back>, payload: {signature, authorization}}` |
| Network naming | Chain slugs (`"base-sepolia"`) | CAIP-2 (`"eip155:84532"`, `"solana:..."`) |
| Status | Legacy; still served by `legacy/` packages in TS and Go | Current; all non-legacy upstream code |

The v2 spec's own architecture framing (`specs/x402-specification-v2.md`, "Architecture") splits the protocol into **Types** (transport- and scheme-independent data structures), **Logic** (scheme × network payment formation/verification), and **Representation** (transport encoding: HTTP, MCP, A2A). This three-layer split is exactly how the TS/Python/Go SDKs are physically organized (see §5) and is the most useful mental model for planning Elixir work.

### 2.2 Schemes

From `x402-upstream/specs/schemes/`:

- **`exact`** (`schemes/exact/scheme_exact.md`) — pay a fixed amount. Per-chain bindings at the snapshot: **EVM** (EIP-3009 `transferWithAuthorization`, plus permit2/erc7710 transfer methods), **SVM/Solana**, **Algorand**, **Aptos**, **Hedera**, **Keeta**, **Stellar**, **Sui**. At foundation HEAD the list has doubled — see §2.6.
- **`upto`** (`schemes/upto/scheme_upto.md`, `scheme_upto_evm.md`) — authorize a ceiling, settle actual usage; EVM implementation is Permit2-based and requires a `facilitatorAddress` in `extra` (discovered via GET `/supported` — see matrix/C2). HEAD adds an SVM binding.
- **`batch-settlement`** (`schemes/batch-settlement/`) — spec-stage, including a Cloudflare-authored variant; HEAD adds concrete EVM and SVM bindings.
- **`auth-capture`** — new at HEAD (`schemes/auth-capture/`, EVM binding): authorize now, capture later.

### 2.3 Transports

Specs exist for v1 and v2 of each: **HTTP** (`transports-v2/http.md`), **MCP** (`transports-v2/mcp.md` — payment payload rides in tool-call `_meta` under `x402/payment`, response under `x402/payment-response`), **A2A** (`transports-v2/a2a.md` — agent-to-agent protocol). All three official SDKs implement HTTP + MCP (verified matrix/C5); A2A is spec + examples territory.

### 2.4 Extensions

From `specs/extensions/`: **bazaar** (service discovery; the one extension Elixir partially implements), **payment_identifier** (client-supplied idempotency ID), **sign-in-with-x** (SIWX auth; Elixir implements verification), **eip2612_gas_sponsoring**, **erc20_gas_sponsoring**, **offer-and-receipt** (the largest extension spec), **http-message-signatures**; HEAD adds **builder_code** and **extension-auth-hints**. TS implements six as packages (`typescript/packages/extensions/src/{bazaar,eip2612-gas-sponsoring,erc20-approval-gas-sponsoring,offer-receipt,payment-identifier,sign-in-with-x}`); Python and Go each implement four.

### 2.5 Facilitators, adoption, and momentum

The facilitator API is four endpoints: `POST /verify`, `POST /settle`, `GET /supported` (advertise scheme/network kinds + per-kind `extra` like SVM `feePayer`), and `GET /discovery/resources` (bazaar). The default public facilitator is `https://x402.org/facilitator` (our default too — `lib/x402/facilitator.ex:19`).

**Facilitator market:** the Coinbase CDP hosted facilitator (`api.cdp.coinbase.com/platform/v2/x402/*`) is the main authenticated production option — Base, Polygon, Arbitrum, World Chain, and Solana; 1,000 free settlements/month then ~$0.001 per settlement, with KYT/OFAC screening (per CDP docs). Our `X402.Facilitator.Auth.CDP` targets it. Beyond CDP, the ecosystem page tracks ~19 zero-fee facilitators including Polygon's, PayAI, x402.rs (Rust), thirdweb, Dexter, and Fireblocks. Cloudflare co-authored the batch-settlement scheme and joined the Foundation (members include Google, Microsoft, Visa, Mastercard, Stripe, and AWS, per the Foundation launch announcement).

**Adoption numbers (verified against registry APIs, 2026-08-26):**

| Signal | Value |
|---|---|
| `x402-foundation/x402` GitHub | 6,543 stars · 1,968 forks · pushed same day |
| npm `x402` (legacy v1 line) | 385,762 downloads/week |
| npm `@x402/core` (v2) | 267,725 downloads/week |
| PyPI `x402` | 44,138/week (188k/month) |
| crates.io `x402-rs` | 21,277 all-time, v0.12.5 |
| hex.pm `x402` (us) | 495 all-time · 21/week |
| hex.pm `mpp` (adjacent protocol, see §3.5) | 2,001 all-time · 513/week |

Public dashboards reported on the order of ~157M cumulative x402 transactions and ~$41M volume by July 2026, with 30-day volume cooling from its peak (treat as order-of-magnitude; dashboard-sourced). The strategic read: the protocol has real traction, TypeScript dominates, Python/Go are far behind TS but far ahead of everyone else — and Elixir's numbers are a rounding error, which is precisely the opportunity: the official docs give first-class treatment to TS/Go/Python only, and the third-party SDK listing has ~3 entries. Getting listed there is cheap visibility (see §8, P1.5).

### 2.6 Delta: April snapshot → foundation HEAD (2026-08-26)

The canonical repo moved fast in the four months after our analysis snapshot. Verified by direct diff of the two clones:

- **Versions:** `@x402/core` 2.10.0 → **2.23.0**; Python `x402` 2.8.0 → **2.20.0**; Go module is now major-versioned `github.com/x402-foundation/x402/go/v2`.
- **TS mechanisms:** 5 → **11** packages — adds `concordium`, `hedera`, `keeta`, `near`, `tvm` (TRON), `xrpl` alongside `evm`, `svm`, `aptos`, `stellar`, `avm`. Python adds `tvm`. Go still ships `evm` + `svm` only.
- **Spec growth:** `exact` chain bindings 8 → **16** (adds Canton, Cardano, Casper, Concordium, NEAR, Starknet, TON, XRPL); new **auth-capture** scheme; batch-settlement now has concrete EVM/SVM bindings; `upto` gains SVM; new extensions `builder_code` and `extension-auth-hints`.
- **e2e harness:** reorganized into per-language directories (`e2e/{servers,clients,facilitators}/{typescript,go,python}`) — still exactly three languages; Java remains excluded; some file-level mechanics cited in §7 (e.g. `proxy-base.ts`) have moved.
- **Java:** still a ~21-file proof of concept.

Implications: (1) verify current upstream state immediately before any interop or upstream-PR work — four-month-old file references will have drifted; (2) chains are proliferating at a pace that makes a pluggable scheme/mechanism seam (§8, P1.1) non-optional; (3) future analysis and PRs should target `x402-foundation/x402`, not the Coinbase fork.

---

## 3. SDK-by-SDK Profiles

### 3.1 TypeScript (reference implementation)

**Layout:** `typescript/packages/{core, http, mechanisms, extensions, mcp, legacy}` — a package-per-concern monorepo published as `@x402/*`, lockstep-versioned via a changesets "fixed" group.

- **Core** (`packages/core/src/`): protocol types + three role engines — `x402Facilitator.ts` (local verify/settle dispatching to registered scheme facilitators, with hooks; `verify()` at :283, `settle()` at :404), `server/x402ResourceServer.ts` (calls `getSupported()` in `initialize()` at :376 to build supported-kind maps and validate routes at startup), and client logic. `http/httpFacilitatorClient.ts` implements all four facilitator endpoints (`/supported` fetch at :322) with zod validation on every response (`isValid: z.boolean()` etc., :65-105) throwing `FacilitatorResponseError` on mismatch.
- **Mechanisms** (`packages/mechanisms/{evm,svm,stellar,aptos,avm,...}`): per-chain client + facilitator scheme implementations. The EVM `exact` facilitator (`evm/src/exact/facilitator/eip3009.ts`) does full local verification: EIP-712 `verifyTypedData` covering EOA + ERC-1271 + ERC-6492 counterfactual wallets (:113-171), `payTo` equality (:174), `validBefore >= now+6s` (:182-190), `validAfter <= now` (:192-199), exact BigInt amount (:201-208), and on-chain `eth_call` simulation (:210-227). Settle re-runs verify (":255-258 — 'Re-verify before settling'") with `simulateInSettle` defaulting to `false`. The SVM facilitator whitelists transaction instructions strictly (3–6 instructions: ComputeLimit/ComputePrice/TransferChecked + Lighthouse/Memo only — `svm/src/exact/facilitator/scheme.ts:151-299`) and dedupes settlements via an in-memory `Map` with a 120s TTL (`settlement-cache.ts`).
- **HTTP integrations** (`packages/http/`): axios, fetch, express, fastify, hono, next, paywall (embedded HTML paywall).
- **MCP** (`packages/mcp/`): client (`x402MCPClient.ts` — retries tool calls carrying the payment in `_meta["x402/payment"]`, :565-589) and server wrapper (`paymentWrapper.ts:162-273`).
- **Extensions:** all six listed in §2.4.
- **Legacy** (`packages/legacy/`): v1 packages (`x402`, `x402-express/next/hono`) — where the 2025 route-matching CVE lived and was fixed (`legacy/x402/src/shared/middleware.ts:67-104`). Still 385k downloads/week — v1 traffic is far from dead.

**Weak spots (verified):** inbound `PAYMENT-SIGNATURE` decode is a charset regex + `JSON.parse` **cast** with no size limit and no zod on the decode path (`core/src/http/index.ts:27-32`; security/C1); the resource-server role trusts facilitator booleans with no on-chain check (security/C8).

### 3.2 Python

**Layout:** single PyPI package `x402` (`python/x402/`) mirroring TS conceptually: `client.py`/`server.py`/`facilitator.py` (each with a `*_base.py` sans-IO core), `mechanisms/{evm,svm}` (+`tvm` at HEAD), `http/` (httpx + requests clients; FastAPI + Flask middleware; paywall), `mcp/` (sync and async client + server), `extensions/{bazaar, eip2612_gas_sponsoring, erc20_approval_gas_sponsoring, payment_identifier}`, pydantic `schemas/`. True async and sync variants are unified by a generator-core pattern that yields hook/facilitator-call commands to thin async/sync drivers — the cleanest sans-IO layering in the ecosystem.

Same facilitator-engine depth as TS: EVM exact facilitator verifies "EOA, EIP-1271, or ERC-6492" (`mechanisms/evm/exact/facilitator.py:126`), simulates transfers (:251), can deploy ERC-6492 wallets (:390); SVM instruction whitelist at `mechanisms/svm/exact/facilitator.py:178-249`; SVM settlement cache `dict + threading.Lock`, 120s TTL. Facilitator responses are pydantic-validated and mapped to 502 on parse failure (`http/middleware/fastapi.py:197`). It is also v1+v2 dual-stack with typed V1 models and V1→V2 network maps. ~957 tests.

**Weak spots:** inbound header decode is unbounded `base64.b64decode` + `json.loads` (pydantic only afterward — security/C1); pydantic non-strict mode coerces some mistyped facilitator values (e.g. `isValid: "true"`) rather than rejecting (security/C8 nuance); float money math in places; no facilitator HTTP harness.

### 3.3 Go

**Layout:** one root module (now `github.com/x402-foundation/x402/go/v2`) with flat top-level role files (`client.go`, `server.go`, `facilitator.go`, each with a `*_hooks.go` companion and `*_test.go`), plus `mechanisms/{evm,svm}`, `http/` (gin, echo, nethttp middleware; `facilitator_client.go`; embedded paywall templates), `mcp/` (official go-sdk), `extensions/{bazaar, eip2612gassponsor, erc20approvalgassponsor, paymentidentifier}`, `legacy/` (deprecated v1, where the only Go CDP auth lives). Excellent long-form role docs in-repo: `CLIENT.md`, `SERVER.md`, `FACILITATOR.md` (~20K each).

The Go ERC-6492 verifier is the ecosystem's clearest fail-closed design: undeployed smart-wallet signatures are classified as counterfactual but **not** treated as valid until on-chain simulation proves them (`mechanisms/evm/verify_universal.go:22-23, 86-93`; verified security/C4). Facilitator response envelopes use pointer fields (`IsValid *bool`) so absent/mistyped values fail hard (security/C8). 206 tests including env-gated live on-chain integration and duplicate-tx attack suites.

**Weak spots:** bare `base64.StdEncoding.DecodeString` on inbound headers with no size cap (`http/server.go:829-831`; security/C1); no non-deprecated CDP auth (security/C7); no facilitator HTTP server scaffold (users hand-write `r.POST("/verify", ...)` per `FACILITATOR.md:59`); MCP auto-pay bypasses client policies; duplicated V1/V2 hook code.

### 3.4 Java

**Layout:** ~21 source files (`java/src/main/java/org/x402/`): Jackson model classes, `client/HttpFacilitatorClient.java` (verify/settle/supported; **no auth mechanism at all** — constructor takes only a baseUrl, :32-36), `client/X402HttpClient.java`, `server/PaymentFilter.java` (a stateless servlet filter with a static price table), `crypto/CryptoSigner.java` (bring-your-own signer). No mechanisms, no MCP, no extensions, no facilitator engine, no header size cap. v1-only with `x402Version=1` hardcoded, network `base-sepolia` and asset `USDC` hardcoded — and it has drifted from even the v1 wire format (POSTs `paymentHeader` where the spec sends decoded `paymentPayload`; expects `txHash`/`networkId` instead of `transaction`/`network`), so it cannot interoperate with current facilitators. Not on Maven Central; excluded from the e2e harness.

**Verified defects (security/C8):** settlement runs after `chain.doFilter` (:146-155); on settle failure with a committed response it just returns (:158-162, 190-193) — **the client keeps the resource unpaid**; the 402 path writes without `resetBuffer()`; :122 interpolates unescaped `ex.getMessage()` into a JSON error body. Java is best read as a proof-of-concept and a cautionary tale for what a minimal port looks like. It is also our closest peer in scope — and we beat it on every axis.

### 3.5 Community SDKs — and the Elixir competitive picture

No Rust/Ruby/.NET SDK exists in the official monorepo; the community fills the gap:

- **Rust — `x402-rs`** (flagship community SDK; ~287 GitHub stars, crates.io 21,277 downloads, v0.12.5): v1+v2, `exact` scheme only, axum server middleware + reqwest client middleware, **a facilitator binary** and a hosted facilitator at `facilitator.x402.rs`, OpenTelemetry instrumentation. Notable: the community shipped a runnable facilitator before any official SDK did — evidence for the §8 P2.1 thesis.
- **Ruby** — QuickNode's `x402-rails` / `x402-payments` gems (v2; officially listed on the third-party SDK page).
- **.NET** — `michielpost/x402-dotnet` (NuGet `x402` 2.2.x family, ~5k downloads).
- **Java (community)** — the Mogami stack (Spring Boot annotation-driven middleware + facilitator), considerably ahead of the official Java PoC.
- **PHP** — fragmented Laravel packages, none dominant. **Swift/Kotlin** — nothing exists.

**Elixir/BEAM:** hex.pm has **no competing spec-conformant x402 SDK** — we are first and alone. The adjacent packages are ZenHive's `mpp` (a different "Machine Payments Protocol", currently out-downloading us 513/wk vs 21/wk), `raxol_payments` (agent auto-pay tooling), and the dead `facilixir`. Two consequences: the BEAM niche is ours to lose, and the official docs' third-party SDK page (3 entries today) is an easy, high-visibility listing target once we can demonstrate interop (§8, P1.5).

### 3.6 Elixir (this SDK)

**Layout:** 28 files under `lib/`, flat modules per house style: header codecs (`lib/x402/{payment_required,payment_signature,payment_response,header}.ex`), `lib/x402/plug/payment_gate.ex` (the Plug middleware, ~1300 lines — the SDK's center of gravity), `lib/x402/facilitator{.ex,/http.ex,/auth.ex,/auth/cdp.ex,/error.ex}`, `lib/x402/hooks{.ex,/context.ex,/default.ex}`, extensions (`bazaar.ex`, `payment_identifier/{cache,ets_cache}.ex`, `siwx/*`), `wallet.ex`, `telemetry.ex`. ~6,600 lib LOC, ~7,900 test LOC. v0.5.0 (2026-08-26) added CDP facilitator auth, Ecto-style `otp_app:` runtime config, and the bazaar extension builder (CHANGELOG.md).

**Roles covered:** resource server (v2 only, in practice — see matrix/C3) and facilitator HTTP client (`/verify` + `/settle` only). **Roles absent:** payer client (matrix/C1), facilitator engine (matrix/C6), MCP anything (matrix/C5).

**Distinctive strengths (all verified, §9):** 8KB pre-decode cap on all three headers (`lib/x402/header.ex:7`); atomic ETS replay guard (`payment_gate.ex:495-502`); `https://` enforcement on facilitator URLs (`facilitator/http.ex:330-366`); in-tree CDP JWT auth with 120s exp, fresh nonce, and a `uris` claim binding method+host+path (`auth/cdp.ex`); strict fail-closed facilitator-response validation that even on `success: false` requires well-typed `transaction`/`network` fields (`payment_gate.ex:1040-1075`); hooks behaviour with six callbacks; telemetry spans; NimbleOptions on all user-facing options. 31 test files against 28 lib files, Bypass + Mox per house rules, >90% coverage gate.

**Distinctive weaknesses:** everything in §1's top-five list, plus: `PaymentSignature.validate/2` is structural only (regex + requirements map-equality + `upto` ceiling comparison — zero cryptography; security/C2); the replay cache is hardcoded to `ETSCache` with no `put_new` in the `Cache` behaviour, so a distributed backend cannot even be plugged in (matrix/C4); route matching does no percent-decoding and has zero encoded-path regression tests for the bug class of GHSA-3j63-5h8p-gf7c (`payment_gate.ex:1279-1280`, :927; security/C6).

---

## 4. Feature Comparison Matrices

Legend: ✅ full, 🟡 partial, ❌ absent. Paths in headers abbreviate `x402-upstream/`.

### 4.1 Roles

| Role | TS | Python | Go | Java | Rust (comm.) | Elixir |
|---|---|---|---|---|---|---|
| Payer client (sign + retry-with-payment) | ✅ | ✅ | ✅ | 🟡 EVM exact only | ✅ reqwest | ❌ signing code exists only in `test/support/`, excluded from Hex (C1) |
| Resource-server middleware | ✅ express/fastify/hono/next | ✅ FastAPI/Flask | ✅ gin/echo/nethttp | 🟡 servlet filter (unsafe, §3.4) | ✅ axum | ✅ Plug |
| Facilitator HTTP client | ✅ 4 endpoints + zod | ✅ 4 endpoints + pydantic | ✅ 4 endpoints, pointer envelopes | 🟡 no auth | ✅ | 🟡 **verify + settle only** (C2) |
| Facilitator engine (local verify/settle) | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ (C6) |
| Facilitator HTTP server scaffold | ❌ (examples only) | ❌ (examples only) | ❌ (examples only) | ❌ | ✅ binary + hosted | ❌ |

Among official SDKs, none ships a facilitator HTTP *server* scaffold — runnable facilitators live only in `examples/{typescript,python,go}/facilitator` (verified C6). Only community Rust does. That is a genuine open niche (§8, P2.1).

### 4.2 Protocol coverage

| | TS | Python | Go | Java | Elixir |
|---|---|---|---|---|---|
| v2 headers (PAYMENT-*) | ✅ | ✅ | ✅ | ✅ | ✅ |
| v1 (X-PAYMENT) interop | ✅ `legacy/` | 🟡 dual-stack | ✅ `legacy/` + `types/v1` | ❌ (drifted) | ❌ — the "v1" path validates `transactionHash/network/scheme/payerWallet`, a shape matching **no published wire format**, and never reads `X-PAYMENT` (C3) |
| `exact` EVM (EIP-3009) | ✅ verify+settle+sign | ✅ | ✅ | 🟡 types only | 🟡 structural validation only; facilitator does the rest |
| `exact` SVM | ✅ | ✅ | ✅ | ❌ | ❌ |
| Other chains | ✅ 9 more mechanism pkgs at HEAD | 🟡 +TRON at HEAD | ❌ | ❌ | ❌ |
| `upto` | ✅ EVM Permit2 | 🟡 | 🟡 | ❌ | 🟡 amount-ceiling check in `payment_signature.ex:396-494`; no Permit2, no `facilitatorAddress` discovery (C2) |
| CAIP-2 networks | ✅ | ✅ | ✅ | ✅ | ✅ |

### 4.3 Transports & integrations

| | TS | Python | Go | Java | Elixir |
|---|---|---|---|---|---|
| HTTP client wrappers | axios, fetch | httpx, requests | net/http | HttpClient | ❌ (no client role) |
| HTTP server frameworks | 4 + paywall | 2 + paywall | 3 + paywall | servlet | Plug (covers Phoenix) |
| MCP client + server | ✅ `packages/mcp` | ✅ sync+async | ✅ `go/mcp` | ❌ | ❌ — `bazaar.ex` only *describes* MCP tools (C5) |
| A2A | 🟡 examples | ❌ | ❌ | ❌ | ❌ |
| Paywall HTML | ✅ | ✅ | ✅ | ❌ | ❌ |
| e2e interop harness presence | ✅ | ✅ | ✅ | ❌ | ❌ (C8) |

### 4.4 Extensions

| Extension | TS | Python | Go | Elixir |
|---|---|---|---|---|
| bazaar | ✅ incl. facilitator discovery client | ✅ | ✅ | 🟡 builder only (`bazaar.ex` builds 402-response payloads; never queries `/discovery/resources` — C2/C5) |
| payment_identifier | ✅ (validation-only; explicitly defers idempotency — `extensions/src/payment-identifier/resourceServer.ts:68-73`) | ✅ | ✅ | 🟡 ships an ETS idempotency cache, but the gate keys on raw-header sha256 and **never consumes the extension's `paymentId`** (security/C3) |
| sign-in-with-x | ✅ | ❌ | ❌ | ✅ incl. local EIP-191 recovery (`siwx/verifier/default.ex`) — deeper than TS's storage-dependent nonce check |
| eip2612 / erc20 gas sponsoring | ✅/✅ | ✅/✅ | ✅/✅ | ❌/❌ |
| offer-receipt | ✅ | ❌ | ❌ | ❌ |

### 4.5 Operational hardening (Elixir's home turf)

| | TS | Python | Go | Java | Elixir |
|---|---|---|---|---|---|
| Inbound header size cap | ❌ | ❌ | ❌ | ❌ | ✅ 8KB pre-decode (`header.ex:7`; security/C1) |
| Built-in replay/dedup in server middleware | ❌ | ❌ | ❌ | ❌ | ✅ (with caveats — security/C3, matrix/C4) |
| https enforcement on facilitator URL | ❌ | ❌ | ❌ | ❌ | ✅ loopback-only http exemption (security/C7) |
| In-tree CDP facilitator auth | ❌ (separate `@coinbase/x402`) | ❌ | 🟡 deprecated `legacy/` only | ❌ | ✅ Ed25519/ES256 JWT (security/C7) |
| Fail-closed malformed facilitator responses | ✅ zod | 🟡 pydantic non-strict coercion | ✅ pointer fields | 🟡 | ✅ incl. field checks on `success:false` (security/C8) |
| Telemetry/observability | 🟡 hooks | 🟡 hooks | 🟡 hooks | ❌ | ✅ `:telemetry` spans + hooks |

---

## 5. Architecture & Code-Structure Comparison

### 5.1 How the official SDKs are shaped

All three mature SDKs physically encode the spec's Types / Logic / Representation split:

- **TS:** *package* per layer — `core` (types + role engines), `mechanisms/<chain>` (logic), `http` + `mcp` (representation), `extensions`. Schemes register into role engines at runtime (`registerScheme`-style wiring; `mechanisms/svm/src/register.ts`), so `core` has zero chain deps.
- **Python:** *module* per layer inside one package, with a further split of every role into `<role>_base.py` (sans-IO logic) + `<role>.py` (IO shell) — e.g. `facilitator_base.py` under `facilitator.py`. This sans-IO layering is the most directly portable idea for Elixir.
- **Go:** flat root package for types + role engines with `*_hooks.go` companions, subpackages for mechanisms/transports. Closest in feel to our flat-module convention.

The common architectural spine: **a scheme is a pluggable unit implementing a client interface (sign) and a facilitator interface (verify/settle), registered per (scheme, network) kind, discovered at runtime via GET `/supported`.** Everything else — middleware, MCP wrappers, extensions — composes around that spine. Given §2.6's chain proliferation (5 → 11 TS mechanism packages in four months), this seam is the load-bearing design decision.

### 5.2 What our flat-module + behaviour approach gets right

- Flat modules + behaviours are the *correct* Elixir translation of the TS registration pattern. `X402.Hooks` (six callbacks) is a cleaner analog of Go's `*_hooks.go` files than TS's option-bag hooks. NimbleOptions beats all three at option validation ergonomics.
- Our sans-IO instinct is half-realized already: header codecs are pure modules with doctests, exactly like Python's `*_base.py` layer.
- One process-shaped decision the others can't express: supervised, TTL-swept state (ETSCache, SIWX ETSStorage) as first-class library citizens.

### 5.3 What it gets wrong

1. **No scheme/mechanism seam at all.** `PaymentSignature.validate/2` hardcodes its checks; `PaymentGate` hardcodes one flow (`@supported_payment_flow`, `payment_gate.ex:61`). There is no `X402.Scheme` behaviour, so adding `upto`-Permit2 or SVM means editing core modules, not adding one. The TS `mechanisms/` split should become a behaviour: `@callback verify(payload, requirements, opts)` / `@callback sign(requirements, signer, opts)` with per-scheme modules.
2. **GenServer where a pool (or no process) belongs** (matrix/C7). `X402.Facilitator` funnels every verify/settle through one process doing blocking `Finch.request` + `:timer.sleep` backoff inside `handle_call` (`facilitator.ex:292-310`; `facilitator/http.ex:135, :185`). Worst case ~3 attempts × 5s receive_timeout + jitter inside a callback whose callers default to a 5s `GenServer.call` timeout. Ironically the house rule ("No GenServer unless necessary… use GenServer only for stateful clients") was over-applied: the only real state is config, which belongs in a persistent term or is threaded per-call; the HTTP work belongs in the caller's process (Finch already pools). `X402.Facilitator.HTTP.request/5` is already the correct stateless core — the GenServer should become a thin config holder, with `verify/settle` executing in the caller.
3. **Behaviours that exist can't be used.** `PaymentIdentifier.Cache` defines `get/put/delete` but the gate calls `ETSCache.put_new/3` directly (`payment_gate.ex:772-782`), so the one callback that matters for replay (`put_new`) isn't in the behaviour and no Redis/Mnesia adapter can be supplied (matrix/C4). Behaviour-over-config only pays off if the call sites go through the behaviour.
4. **Test-only crypto that the package needs.** EIP-3009/EIP-712 signing lives in `test/support/x402_test_payments.ex` (`sign_transfer_with_authorization/3` at :194, `eip712_digest/2` at :204) — compiled only under `:test`, excluded from Hex (`mix.exs:57-58, :105`). We already carry `ex_secp256k1` + `ex_keccak` as optional deps for SIWX; the marginal cost of promoting this into `lib/` as a client signer is small (matrix/C1).

---

## 6. Security Comparison

All claims here were independently verified (security/C1–C8); corrections from verification are applied.

### 6.1 Inbound hardening — Elixir leads

Elixir is the **only** x402 SDK (all four official SDKs checked) with an application-level pre-decode size cap on payment headers: 8KB via `@max_header_bytes` (`lib/x402/header.ex:7`), enforced with `byte_size` guards before any Base64/JSON work in all three codecs (`payment_signature.ex:85`, `payment_required.ex:96`, `payment_response.ex:88`). TS decodes with a charset regex + unvalidated `JSON.parse` cast (zod schemas exist but are unused on this path — `core/src/http/index.ts:27-32`); Go does bare `base64.StdEncoding.DecodeString` (`http/server.go:829-831`); Python decodes unbounded then pydantic-validates; Java has nothing. (security/C1)

### 6.2 Verification depth — Elixir trails badly

Elixir performs **zero local payment-signature cryptography and zero validAfter/validBefore timing checks** — everything is delegated to the remote facilitator (security/C2). `PaymentSignature.validate/2` never inspects `authorization.to`, never compares `authorization.value` for `exact`, never checks timing, never touches signature bytes. The TS/Go/Python facilitator engines locally enforce: `payTo` equality, exact BigInt amount, `validBefore >= now+6s`, `validAfter <= now`, EOA/EIP-1271/ERC-6492 signature verification, and on-chain simulation (file refs in §3.1). Go's ERC-6492 handling is the model to copy: counterfactual signatures are never valid until simulation proves them (`verify_universal.go:22-23, 86-93`), and all three engines re-run full verify inside settle (`simulateInSettle` defaulting false) (security/C4).

Consequence: an Elixir resource server's security posture equals its facilitator's, fully. That is the protocol's intended trust model for the server role — **no** SDK's server role verifies settlement on-chain, so a lying facilitator (`isValid: true`, fake tx hash) means unpaid delivery in every language (security/C8) — but the others can at least *become* their own facilitator; we cannot.

### 6.3 Replay protection — Elixir unique but bounded

Elixir ships the only built-in replay/dedup in any SDK's resource-server middleware: sha256 of the raw `PAYMENT-SIGNATURE` header claimed atomically via `:ets.insert_new` before settlement, released on handler ≥400 or settle failure, duplicate → 402 (`payment_gate.ex:495-502, :541-554`; `ets_cache.ex:229-254`). Upstream's own payment-identifier extension explicitly defers idempotency ("Future hooks… if needed" — `resourceServer.ts:68-73`). (security/C3)

Bounds, all verified: the claim happens **after** facilitator verify (wasted verify calls under replay storms); it is **per-node only** with no pluggable distributed backend (matrix/C4 — in a cluster, each node claims independently; the handler and its side effects run on every node even when the facilitator later rejects the duplicate settle); nil cache degrades to `:ok` with a warning; keying on raw header bytes means a re-encoded JSON of the same authorization bypasses it; and the extension's `paymentId` is never consumed.

For comparison: the only upstream dedup anywhere is the SVM settlement cache, and it is facilitator-side, in-memory, per-process, 120s TTL in all three SDKs — useless across replicas (security/C5; nuance: Solana's ledger itself blocks the same signed tx landing twice, so the cross-replica gap is duplicate settle-success reporting, not literal double-spend). EVM replay protection everywhere is purely chain-level nonces, detected via simulation at verify time only — settle-time simulation is off by default in all three.

### 6.4 Transport & facilitator-trust hardening — Elixir leads

Only Elixir enforces `https://` on facilitator base URLs (`:insecure_scheme` error; loopback exempt — `facilitator/http.ex:330-366`) and ships facilitator auth in-tree: `X402.Facilitator.Auth.CDP` mints a per-call Ed25519/ES256 JWT with fresh 16-byte nonce, 120s exp, and a `uris` claim binding `METHOD host path` (`auth/cdp.ex:121-145`; one doc overstatement to fix: the token *is* reused across in-call HTTP retries). TS/Go/Python only default to an https URL string with no scheme validation; TS's CDP impl lives in the separate `@coinbase/x402` package, Go's only in deprecated `legacy/`. (security/C7)

All four SDKs fail closed on *malformed* facilitator responses; Elixir is strictest (requires well-typed `transaction`/`network` even on `success:false`, maps malformed → 500 never success), TS/zod and Go/pointer-fields equivalent, Python coerces some mistypes (non-strict pydantic). Java gives committed responses away free on settle failure. (security/C8)

### 6.5 Published advisories (corrected record)

1. **GHSA-3j63-5h8p-gf7c** (2025-08-20, HIGH): legacy `x402` npm + `x402-next/express/hono` < 0.5.2 — route-matching bypass via URL-encoded path segments; fixed in `findMatchingRoute` (`legacy/x402/src/shared/middleware.ts:67-104` now percent-decodes with fail-safe fallback, converts backslashes, collapses slashes). Upstream added `malformedPathBypass.test.ts` suites (hono, fastify).
2. **GHSA-qr2g-p6q7-w82m** (2026-03-07, HIGH): `@x402/svm` npm < 2.6.0, `x402` PyPI < 2.3.0, **Go < 2.5.0**. **Mechanism correction:** the official record (all three changelogs) attributes the fix to the in-memory SVM `SettlementCache` preventing **duplicate transaction settlement during the on-chain confirmation window** — a settlement-replay bug, *not* "improper Ed25519 verification" (that framing traces only to an unofficial aggregator). (security/C6)

**Elixir exposure to bug class #1 is untested:** `normalize_path/1` only trims trailing slashes (`payment_gate.ex:1279-1280`); `match_route/3` matches raw `conn.request_path` by exact/glob equality with no percent-decoding; the test tree has zero encoded-path or malformed-percent-sequence route tests. Note the raw-match design's failure shape: an encoded alias of a protected path will not equal the configured literal, so **no route matches and the request passes through unguarded** — exactly the CVE's bypass shape if the router still serves the encoded alias. This needs tests, not reasoning. (security/C6)

Also relevant: two academic audits of the x402 ecosystem circulated in 2026 (arXiv 2605.11781, 2607.19545), and this repo already remediated EEF cowboy/plug dependency CVEs (commit 0745490).

### 6.6 Elixir security recommendations

1. **Encoded-path regression tests now** (S): port the malformedPathBypass cases; decide and document normalization semantics (recommend: match on Plug's decoded `conn.path_info` segments rather than raw `request_path`).
2. **Verify-then-claim ordering option** (S): offer claim-before-verify to shed replay storms without paying facilitator round-trips.
3. **Add `put_new` to the Cache behaviour + route gate calls through it** (S): unlocks Redis/Mnesia adapters; document the clustered double-execution hazard loudly until then (matrix/C4).
4. **Local pre-checks even while delegating** (M): before calling the facilitator, cheaply check `authorization.to == payTo`, `value == amount` (exact), and validAfter/validBefore windows from the decoded payload. Zero crypto needed, kills whole classes of junk traffic, mirrors checks at `eip3009.ts:174-208`.
5. **Fix the CDP doc overstatement** (S): "never reused across retries" → reused within one call's retries.
6. **Kill or fix the fake v1 path** (see P0 in §8) — a validator that accepts an invented shape under the name "v1" is a security-adjacent liability: it can create false confidence of interop and accepts payloads no facilitator will ever settle.
7. **Add a `SECURITY.md`** (S): upstream has one; we handle payments and have none.

---

## 7. Testing & Quality Comparison

| | TS | Python | Go | Java | Elixir |
|---|---|---|---|---|---|
| Unit test culture | Strong; per-package (~45k lines vitest) | Strong (~957 tests) | Strong; `*_test.go` beside every role file | Minimal | Strong: 31 test files / 28 lib files, doctests, Bypass for HTTP, Mox for behaviours, >90% coverage gate |
| Security regression tests | ✅ `malformedPathBypass.test.ts` (hono, fastify) | 🟡 | 🟡 duplicate-tx attack suites | ❌ | ❌ for the encoded-path class (§6.5); ✅ for header-size/malformed-Base64 classes |
| Cross-language e2e interop | ✅ `e2e/` clients×servers×facilitators on live testnets | ✅ | ✅ | ❌ | ❌ (matrix/C8) |
| Live smoke tests | examples | examples | examples | ❌ | ✅ documented (`guides/live-smoke-tests.md`), tiered CDP suite |
| Lint/static | eslint, changesets | ruff etc. | golangci, changie | checkstyle+SpotBugs+JaCoCo | credo/dialyzer |

**The e2e harness is the strategic one** (matrix/C8, verdict *partial* — honored here): components are discovered purely by convention (a component dir with `test.config.json` declaring `x402Versions`, `protocolFamilies`, `transport`, `extensions`, plus `install.sh`/`build.sh`/`run.sh`); the harness computes compatible client×server×facilitator scenarios and asserts real settlement tx hashes on live testnets. **But** it is *not* "one directory and done": at the snapshot, `e2e/src/proxy-base.ts:31-65` extracted run commands against a whitelist (`pnpm`/`npm`/`node`/`python`/`uv run`/`go run`) — `mix run` would throw — and CI installs no Erlang/OTP. Admitting Elixir = component directory **+** a run-command whitelist patch (or a launcher shim) **+** a CI toolchain step. At foundation HEAD the harness has been reorganized into per-language directories (`e2e/servers/{typescript,go,python}` …), so re-check the current admission mechanics when submitting — but the shape of the work is the same: small, mechanical, and worth an upstream PR. It would make Elixir the first non-monorepo language with official interop proof.

---

## 8. Gap Analysis: Prioritized Roadmap

Effort: S ≤ ~2 days, M ≈ 1–2 weeks, L ≈ 3+ weeks.

### P0 — correctness and table stakes

| # | What | Why | Copy from | Effort |
|---|---|---|---|---|
| P0.1 | **Remove or rewrite the fake v1 path.** Short term: delete the `~w(transactionHash network scheme payerWallet)` validator (`payment_signature.ex:18, :196-205`) and reject `x402Version` ∈ {nil, 1} explicitly with a clear error. Optionally later: real v1 = read `X-PAYMENT`, validate `{scheme, network, payload:{signature, authorization}}` per `specs/transports-v1/http.md`, emit `X-PAYMENT-RESPONSE`. | Current code advertises v1 interop that is exactly zero (matrix/C3); spec-conformant v1 payloads are rejected with `{:missing_fields, ["payerWallet","transactionHash"]}`. Silent wrongness is worse than absence. And v1 still moves 385k npm downloads/week. | `specs/x402-specification-v1.md` §5.2; TS `packages/legacy/x402/src/` | S (delete) / M (real v1) |
| P0.2 | **GET `/supported` in the facilitator client**, plus wiring: startup route validation in PaymentGate, `feePayer`/`facilitatorAddress` injection into `extra`. | Without it, SVM and `upto`-EVM are unimplementable-by-discovery and route configs are unvalidated (matrix/C2). Also the prerequisite for P1.1's scheme registry. | `core/src/http/httpFacilitatorClient.ts:310-347`; `x402ResourceServer.ts:376, :441`; `mechanisms/svm/.../scheme.ts:96-102`; `mechanisms/evm/src/upto/server/scheme.ts:107-108` | S–M (HTTP.request needs a GET path — currently hardcoded `:post` at `facilitator/http.ex:130`) |
| P0.3 | **De-serialize the Facilitator client.** Keep the GenServer as config holder only; execute HTTP in the caller's process via the already-stateless `X402.Facilitator.HTTP.request/5`; replace `:timer.sleep` backoff with caller-side retry. | One process, blocking HTTP + sleeps in `handle_call`, worst case ~15s vs 5s call timeout (matrix/C7). This is the kind of defect Elixir users will judge us hardest on. | Our own `facilitator/http.ex` (it is already correct); pattern: Finch's own pool model | M |
| P0.4 | **Payer client (EVM `exact`).** Promote `test/support/x402_test_payments.ex` signing (`sign_transfer_with_authorization/3`, `eip712_digest/2`) into `lib/x402/client/` behind an `X402.Signer` behaviour; add a Req/Finch wrapper that does the 402 → sign → retry-with-`PAYMENT-SIGNATURE` loop. | Half the protocol — and the entire agentic/AI demand side driving x402 adoption — needs a payer. We already ship the crypto deps (`ex_secp256k1`, `ex_keccak`) as optionals (matrix/C1). | TS `core` client + `packages/http/fetch`; Python `client_base.py` (sans-IO shape); Go `CLIENT.md` | M–L |

### P1 — ecosystem parity

| # | What | Why | Copy from | Effort |
|---|---|---|---|---|
| P1.1 | **`X402.Scheme` behaviour** (verify-side + sign-side callbacks, per (scheme, network) registration keyed off `/supported`). Refactor `PaymentSignature.validate` + PaymentGate's `@supported_payment_flow` onto it. | The architectural seam every other SDK has and we lack (§5.3.1); prerequisite for upto/SVM/anything — and chains are proliferating fast (§2.6). | TS `mechanisms/*` registration; Go `interfaces.go` | M |
| P1.2 | **Local pre-verification checks** (payTo/value/validAfter/validBefore, no crypto) + optional full local EIP-712 verification module behind the optional deps. | §6.6.4; narrows the delegation gap of security/C2 without requiring a full engine. | `eip3009.ts:174-227`; Go `verify_eoa.go`, `verify_1271.go`, `verify_universal.go` | S (pre-checks) / L (full EIP-712 + 1271/6492) |
| P1.3 | **Distributed replay cache:** add `put_new/3` to `X402.Extensions.PaymentIdentifier.Cache`, route PaymentGate through the behaviour, ship the ETS impl as default, document a Redis adapter sketch. | Clustered BEAM double-execution (matrix/C4) is *our* audience's default deployment shape. | Our `ets_cache.ex:229-254` as the reference impl | S–M |
| P1.4 | **Encoded-path route-matching tests + normalization** | §6.6.1; the one published-CVE bug class we have no tests for (security/C6). | `typescript/packages/http/hono/src/malformedPathBypass.test.ts` | S |
| P1.5 | **Upstream e2e harness entry + third-party SDK listing:** an Elixir server component (+ client once P0.4 lands), the run-command/CI patches upstream, then a PR to the docs' third-party SDKs page (3 entries today). | Official interop proof; discoverability; forces our wire compat honest (matrix/C8, corrected scope; §3.5). | e2e templates + text protocols (re-check layout at HEAD — §2.6) | M (incl. upstream PR round-trips) |
| P1.6 | **MCP transport** (client + server payment wrapper on `_meta` `x402/payment` keys), building on an Elixir MCP library (e.g. Hermes MCP) the way upstream builds on the platform MCP SDKs. | All three official SDKs ship it; MCP is where agentic payments actually happen (matrix/C5). Depends on P0.4 for the client half. | `packages/mcp/src/{types/mcp.ts, client/x402MCPClient.ts, server/paymentWrapper.ts}`; `python/x402/mcp/` | L |

### P2 — differentiation

| # | What | Why | Copy from | Effort |
|---|---|---|---|---|
| P2.1 | **Facilitator engine + a facilitator HTTP scaffold.** No official SDK ships a runnable facilitator server (verified C6) — only community Rust does, and its hosted facilitator became ecosystem infrastructure (§3.5). BEAM supervision + our existing fail-closed discipline make "run your own facilitator in Elixir" a credible story. Engine first (EVM exact verify/settle), Plug router scaffold second. Aligns with the existing `x402_facilitator` plan in ROADMAP.md. | Open niche; converts our biggest weakness (delegation) into a product. | `core/src/facilitator/x402Facilitator.ts`; `examples/typescript/facilitator/`; Go `FACILITATOR.md`; x402-rs facilitator | L |
| P2.2 | `upto` with Permit2 + `facilitatorAddress` discovery (needs P0.2, P1.1). | Usage-based pricing is the scheme APIs actually want. | `mechanisms/evm/src/upto/` | L |
| P2.3 | SVM `exact` (client first; facilitator-side instruction whitelist if P2.1 lands). | Second-largest network in the ecosystem. | `mechanisms/svm/`; `python/x402/mechanisms/svm/` | L |
| P2.4 | Remaining extensions: gas-sponsoring pair, offer-receipt; bazaar *discovery client* (query `/discovery/resources`). | Parity tail; the bazaar client is cheap once P0.2's GET path exists — and it was already planned as ROADMAP v0.4. | `typescript/packages/extensions/src/*`; `extensions/src/bazaar/facilitatorClient.ts:135` | S–M each |
| P2.5 | Paywall (HTML 402 page) for browser-facing routes. | TS/Python/Go all ship one; ours can be a lean Phoenix-friendly component rather than a 2.2MB embedded template. | `go/http/paywall.go` (structure), not its templates | M |

**Sequencing note:** P0.2 → P1.1 → (P0.4, P1.2) is the critical path; P1.5 becomes far more valuable once a client exists (the harness tests clients and servers separately, so the server entry can go first).

**Reconciliation with ROADMAP.md:** the existing roadmap already names the buyer client (its v0.5 goal) and bazaar client (v0.4), and promoted the facilitator to an active project — those survive as P0.4, P2.4, and P2.1. What this analysis adds that the roadmap misses entirely: the fake-v1 correctness bug (P0.1), the missing `/supported` endpoint (P0.2), the GenServer bottleneck (P0.3), the scheme-behaviour seam (P1.1), the encoded-path test gap (P1.4), the e2e/listing play (P1.5), and MCP (P1.6) — MCP's absence is the roadmap's biggest blind spot given where agentic payments are happening. ROADMAP.md should be updated to this ordering.

---

## 9. What We Do Better (honest list)

All verified; this is real, not spin — but note every item lives inside the resource-server + facilitator-client scope.

1. **Only SDK with a pre-decode header size cap** (8KB, all three headers) — every other SDK will Base64/JSON-decode unbounded attacker input (security/C1).
2. **Only resource-server middleware with built-in replay/dedup** — atomic, race-safe via `:ets.insert_new`, with correct release-on-failure semantics; upstream's own extension punts on this (security/C3; caveats in §6.3).
3. **Only SDK enforcing https on facilitator URLs**, with `verify_peer` + system cacerts on the default pool (security/C7).
4. **Only SDK with current, in-tree CDP facilitator auth** — per-call JWT, fresh nonce, 120s exp, method+host+path-bound `uris` claim. TS's is a separate package; Go's is deprecated; Python and Java have none (security/C7).
5. **Strictest fail-closed facilitator-response handling** — even `success:false` must carry well-typed `transaction`/`network` or we 500; Python coerces, Java leaks (security/C8).
6. **Deepest SIWX implementation** — actual local EIP-191 recovery vs TS's optional-storage nonce bookkeeping (§4.4).
7. **Observability**: `:telemetry` spans plus a six-callback hooks behaviour — richer than any counterpart's hook surface relative to SDK size.
8. **Test discipline relative to scope**: 31 test files / 28 lib files, doctests, mocked HTTP, >90% coverage gate, documented live smoke tests; Ecto-style `otp_app:` runtime config is more production-operable than any counterpart's config story.
9. **First and only spec-conformant x402 SDK on the BEAM** — no hex.pm competitor exists (§3.5).

---

## 10. Appendix: Sources

**Repositories (primary evidence):**
- Canonical monorepo: https://github.com/x402-foundation/x402 (HEAD `8468e3a`, 2026-08-26). Analysis snapshot: the `coinbase/x402` fork at commit `dd927a2` (2026-04-21).
- This SDK: analyzed at v0.5.0, branch `rt/x402-sdks-comparison-8326a2`.
- Hex package: https://hex.pm/packages/x402 · Docs: https://hexdocs.pm/x402 · Protocol docs: https://docs.x402.org · Default facilitator: https://x402.org/facilitator

**Registry APIs queried 2026-08-26 (adoption table, §2.5):** api.github.com/repos/{x402-foundation,coinbase}/x402 · api.npmjs.org/downloads/point/last-week/{x402,@x402/core} · pypistats.org/api/packages/x402/recent · crates.io/api/v1/crates/x402-rs · hex.pm/api/packages/{x402,mpp}

**Community SDKs (§3.5):** x402-rs (github.com/x402-rs/x402-rs, facilitator.x402.rs) · QuickNode x402-rails/x402-payments · michielpost/x402-dotnet (NuGet) · Mogami (Java/Spring)

**Spec files (paths under `x402-upstream/specs/`):** `x402-specification-v1.md`, `x402-specification-v2.md`, `transports-v{1,2}/{http,mcp,a2a}.md`, `schemes/exact/*`, `schemes/upto/*`, `schemes/batch-settlement/*`, `schemes/auth-capture/*` (HEAD), `extensions/*`, `scheme_template.md`, `transport_template.md`.

**Security advisories:**
- GHSA-3j63-5h8p-gf7c — https://github.com/advisories/GHSA-3j63-5h8p-gf7c (published 2025-08-20; npm `x402`, `x402-next`, `x402-express`, `x402-hono` < 0.5.2).
- GHSA-qr2g-p6q7-w82m — https://github.com/advisories/GHSA-qr2g-p6q7-w82m (published 2026-03-07; npm `@x402/svm` < 2.6.0, PyPI `x402` < 2.3.0, Go SDK < 2.5.0; mechanism per upstream changelogs: SVM duplicate-settlement during confirmation window).
- Academic audits: arXiv 2605.11781, 2607.19545.

**Verification record:** sixteen load-bearing claims (matrix/C1–C8, security/C1–C8) were independently verified against source before drafting; two returned *partial* verdicts whose corrections are incorporated: matrix/C8 (e2e admission needs run-command/CI patches, not just a directory) and security/C6 (Go affected range < 2.5.0; advisory mechanism is settlement replay, not Ed25519 verification).
