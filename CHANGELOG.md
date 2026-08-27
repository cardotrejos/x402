# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `X402.Extensions.PaymentIdentifier.RedisCache` — a Redis-backed
  `X402.Extensions.PaymentIdentifier.Cache` adapter for clustered
  deployments (ROADMAP P1.3b), over the **new optional `redix` dependency**.
  The replay-protection claim is a single atomic `SET key value NX PX ttl`,
  so a replayed payment proof is claimed exactly once across all nodes;
  expiry is server-side (an expired claim never blocks a retry), live claims
  are never evicted by the adapter, and connection/Redis errors surface as
  `{:error, reason}` so `X402.Plug.PaymentGate` fails closed. The adapter
  does not own the connection — users supervise `Redix` themselves and pass
  the pid/name to `RedisCache.new/1` (`:ttl_ms`, `:namespace`, and an
  injectable `:command` module implementing
  `X402.Extensions.PaymentIdentifier.RedisCache.Command` for testing without
  a live server). A live conformance suite tagged `:redis` (excluded by
  default) runs against `REDIS_URL`
- **Local pre-verification checks in `X402.Plug.PaymentGate`** (option
  `local_prechecks:`, default `true`): before the facilitator round-trip, the
  gate now validates the EIP-3009-style `payload.authorization` object against
  the matched requirements — `to` must equal `payTo` (case-insensitive for hex
  addresses), `value` must equal the advertised amount on `"exact"` routes,
  `validAfter` must not be in the future, and `validBefore` must cover now
  plus a 6-second settlement buffer (mirroring the reference facilitators).
  Failures answer 402 with reason `{:precheck_failed, detail}` and never reach
  the facilitator; payloads without an authorization object (other schemes,
  Permit2) and absent fields are skipped, so the facilitator remains the
  authority. (Ecosystem report §6.6.4/§8 P1.2.)
- `X402.Plug.PaymentGate` `claim_order:` option (`:after_verify` |
  `:before_verify`, default `:after_verify` — unchanged behavior). With
  `:before_verify` the gate claims the payment proof before calling the
  facilitator, rejecting replayed duplicates with 402 without any facilitator
  round-trip, and releases the claim when verification fails for any reason;
  release-on-handler-error and release-on-settle-failure semantics are
  unchanged. Trade-off documented in the moduledoc: `:before_verify` sheds
  replay-storm load from the facilitator, but a node crash during
  verification strands the claim until the cache TTL expires, while
  `:after_verify` never strands a claim on verification but pays one verify
  call per replayed request. Verify-time exits (facilitator call timeout or
  `:noproc`) also release the claim before propagating, so a slow or down
  facilitator cannot strand a payer's replay lock
- `put_new/3` callback on `X402.Extensions.PaymentIdentifier.Cache` — the
  atomic first-writer-wins claim used for replay protection is now part of the
  behaviour contract (TTL semantics and return values documented), so
  alternative adapters (Redis, Mnesia, database-backed) can be plugged into
  `X402.Plug.PaymentGate`; the cache moduledoc includes a Redis `SET NX PX`
  adapter sketch. The contract forbids evicting live entries to admit a new
  claim: at capacity, `ETSCache.put_new/3` now purges expired entries and
  otherwise refuses with `{:error, :cache_full}` (the gate fails closed) —
  previously it evicted the soonest-expiring live claim, which let cheap junk
  claims drop legitimate replay locks
- `X402.Plug.PaymentGate` `payment_identifier_cache:` accepts `{:global, name}`
  and `{:via, registry, term}` GenServer names, normalized to the bundled
  `ETSCache` adapter like a bare pid/name
- `X402.Plug.PaymentGate` `payment_identifier_cache:` now also accepts a
  `{module, cache}` adapter tuple implementing
  `X402.Extensions.PaymentIdentifier.Cache`; a bare pid/name keeps working and
  is normalized to the bundled `ETSCache` adapter
- `X402.Facilitator.supported/0..1` — `GET /supported` returning the
  facilitator's payment kinds, extensions, and signers as
  `{:ok, %{kinds: [...], extensions: [...], signers: %{...}}}`, validated
  fail-closed (`{:error, %Error{type: :malformed_facilitator_response}}` on a
  malformed body). Unlocks startup route validation, SVM `feePayer` discovery,
  and `upto` `facilitatorAddress` discovery
- `X402.Facilitator.list_resources/0..2` — `GET /discovery/resources` with
  NimbleOptions-validated filter and pagination parameters (`type`, `pay_to`,
  `scheme`, `network`, `extensions`, `limit`, `offset`), returning fail-closed
  parsed `{:ok, %{items: [...], pagination: ..., x402_version: ...}}`
- `X402.Facilitator.HTTP.get/3..4` — GET transport with optional `:query`
  parameters, sharing the retry/backoff/TLS pipeline with `request/5`
- Telemetry spans `[:x402, :facilitator, :supported]` and
  `[:x402, :facilitator, :list_resources]`, consistent with the existing
  verify/settle spans
- Facilitator auth implementations now receive the real request method
  (`:get` for the new endpoints) in `request_info`, so CDP JWTs bind
  `GET host path` in their `uris` claim
- `X402.Extensions.Bazaar` discovery client — `list_resources/0..2` queries a
  facilitator's `GET /discovery/resources` and parses every discovered entry
  into a well-typed map (resource URL, `accepts` PaymentRequirements list,
  `lastUpdated`, metadata, extensions), fail-closed on structurally invalid
  entries; `parse_resource/1` for per-entry parsing; and pure filter helpers
  `filter_by_network/2`, `filter_by_scheme/2`, and `filter_by_max_price/2`

### Changed

- `X402.Facilitator.verify/2..4` and `settle/2..4` now execute the HTTP
  request — including retries with backoff, lifecycle hooks, telemetry spans,
  and per-request auth header minting — in the calling process. The
  facilitator GenServer is now a supervised configuration holder consulted
  only for its settings, so concurrent payment operations no longer serialize
  behind a single process (previously blocking HTTP plus retry sleeps ran
  inside `handle_call`, with a worst case well beyond the default
  `GenServer.call/3` timeout). The public API, option surface, return shapes,
  telemetry event names, and hook semantics are unchanged; note that
  `X402.Hooks` callbacks now run in the caller's process
- `X402.Plug.PaymentGate` routes all replay claim/release calls through the
  `X402.Extensions.PaymentIdentifier.Cache` behaviour instead of calling
  `ETSCache` directly; adapter claim errors other than
  `{:error, :already_exists}` fail closed with HTTP 500
- Implementations of `X402.Extensions.PaymentIdentifier.Cache` must now export
  `put_new/3`; `validate_adapter/1` rejects adapters without it

### Documentation

- Documented the clustered-BEAM double-execution hazard of the per-node ETS
  replay cache in the `PaymentGate`, `Cache`, and `ETSCache` moduledocs
- Added `SECURITY.md` — private vulnerability reporting, supported versions,
  and the SDK's trust model (facilitator-delegated verification, transport
  hardening, per-node replay cache caveat)
- Corrected the `X402.Facilitator.Auth.CDP.headers/2` doc: the JWT is signed
  fresh per facilitator operation, and transport retries within one operation
  reuse it inside its 120-second validity window

### Security

- **`X402.Plug.PaymentGate` route matching now runs on decoded
  `conn.script_name ++ conn.path_info` segments instead of the raw
  `conn.request_path`.**
  Adapters drop empty path segments when building `path_info`, so
  `//api/resource` reached the router as the protected resource while the
  gate's raw string comparison passed it through unpaid — the same bug class
  as GHSA-3j63-5h8p-gf7c in the legacy TypeScript middleware. Segments are
  additionally percent-decoded (malformed sequences match verbatim), so the
  gate also covers routers that decode; a decoded match a router would 404
  merely answers 402 first, which is the fail-safe direction for a paywall.
  Regression tests cover double-slash, percent-encoded, encoded-slash, glob,
  and malformed-percent aliases. Telemetry `path` metadata now reports the
  decoded path. (Ecosystem report §6.5/§8 P1.4.)

### Removed

- **The legacy "v1" validation path in `X402.PaymentSignature`.** It required
  `transactionHash`/`network`/`scheme`/`payerWallet` — a shape that matches no
  published x402 wire format (real v1 payments carry
  `{scheme, network, payload: {signature, authorization}}` in the `X-PAYMENT`
  header, which this SDK never reads) — so it advertised v1 interop that was
  exactly zero while accepting payloads no facilitator would settle. Payloads
  declaring `x402Version: 1` or omitting the version now return
  `{:error, {:unsupported_x402_version, 1 | nil}}` (mapped to HTTP 400 by
  `X402.Plug.PaymentGate`). The `{:invalid_format, _}` error reason no
  longer occurs; `{:missing_fields, _}` remains for v2 `accepted` objects
  missing required PaymentRequirements fields.
  (Ecosystem report §8 P0.1.)
- Payer client (report §8 P0.4): `X402.Client` — transport-agnostic core with
  `select_requirements/2` (filterable payment-option selection with a
  `max_amount` budget guard), `build_payment/3` (v2 `PaymentPayload` assembly
  with full requirements and extension echo), and `encode_payment/1`
- `X402.Signer` behaviour — the client-side signing seam (`address/1` +
  `sign_eip712/3` over the precomputed EIP-712 digest and full typed data),
  with `X402.Signer.LocalKey` as the built-in raw-private-key implementation
  (optional `ex_secp256k1`/`ex_keccak`; the key is redacted from `inspect/1`)
- `X402.EIP3009` — EIP-3009 `TransferWithAuthorization` building, EIP-712
  domain derivation from payment requirements, digest computation, signing,
  and signer recovery, promoted from `test/support/x402_test_payments.ex`
  (which now delegates to it)
- `X402.Client.Finch` — HTTP convenience client: on `402` with a
  `PAYMENT-REQUIRED` header it decodes, signs, and retries once with
  `PAYMENT-SIGNATURE` (never pays twice), returning the decoded
  `PAYMENT-RESPONSE` settlement receipt; includes an `on_payment_required`
  budget/consent hook and enforces `https://` for non-loopback resources
- `[:x402, :client, :select | :sign | :build | :request]` telemetry events
- `guides/client.md` — "Paying for x402 Resources from Elixir"
- `X402.EIP712` — shared EIP-712 hashing primitives (requirements-derived
  domain, domain separator, `hash_struct/2`, `digest/2`, and the ABI word
  encoders), extracted from `X402.EIP3009` which now delegates to it
- `X402.Extensions.EIP2612GasSponsoring` — the `eip2612GasSponsoring`
  gas-sponsoring extension (report §8 P2.4): server-side declaration
  (`build_extension/0`) and echo validation (`extract_info/1` /
  `validate_info/1`), plus client-side EIP-2612 `Permit` signing
  (`sign_permit/3`, `put_info/2`, and `enricher/2` for
  `X402.Client.build_payment/3`)
- `X402.Extensions.ERC20ApprovalGasSponsoring` — the
  `erc20ApprovalGasSponsoring` gas-sponsoring extension (report §8 P2.4)
  for tokens without EIP-2612: server-side declaration and echo
  validation, plus client-side assembly of the extension data around a
  pre-signed `approve(Permit2, amount)` transaction (`build_info/1`,
  `put_info/2`, and `enricher/1` for `X402.Client.build_payment/3`)
- `X402.Client.build_payment/3` and `X402.Client.Finch.request/3`
  `:extensions` option — client extension enrichers applied to the
  assembled payload (how gas-sponsoring data is attached opt-in)
- `integration/e2e_server/` — resource-server component for the official x402 cross-language e2e interop harness (`X402.Plug.PaymentGate` + `X402.Facilitator` behind Bandit), including a ready-to-copy `e2e/servers/elixir/http/bandit/` tree for the foundation repo, the upstream patch list, and a local smoke suite (`verify.sh`)
- MCP transport (report §8 P1.6): `X402.MCP` — library-agnostic pure
  functions implementing the x402 MCP transport over plain tool-call
  request/result maps (`_meta["x402/payment"]` payloads,
  `_meta["x402/payment-response"]` receipts, payment-required results with
  `structuredContent` + `content[0].text`, and `402`/`-32042` JSON-RPC
  payment errors)
- `X402.MCP.Server` — wraps any MCP tool handler with the
  verify → execute → settle flow against `X402.Facilitator`, validating
  payloads as strictly as `X402.Plug.PaymentGate` (v2 version check,
  `accepted` matching, extension echo) with optional replay protection via
  the same `payment_identifier_cache` option
- `X402.MCP.Client` — drives any tool-call function through the
  detect → sign → retry-once loop (never pays twice) with the same
  `on_payment_required` veto hook and `max_amount` budget guard as
  `X402.Client.Finch`, plus `build_payment_meta/3` for manual retries
- `[:x402, :mcp, :payment_required | :payment_verified | :payment_rejected | :call]`
  telemetry events
- `guides/mcp.md` — "Paid MCP Tools in Elixir"

## [0.5.0] - 2026-08-26

### Added

- `X402.Facilitator.Auth` behaviour and `X402.Facilitator.Auth.CDP` — per-request JWT authentication for the Coinbase Developer Platform x402 facilitator, configured via the new `auth:` option on `X402.Facilitator.start_link/1`
- `X402.Facilitator` `otp_app:` option — Ecto-style runtime configuration where `config :app, <name>` supplies options (including auth credentials) and `config/runtime.exs` is the single source of truth; explicit options take precedence
- `X402.Extensions.Bazaar.build_extension/1` — factory for the `bazaar` discovery extension payload (`info` + `schema`), supporting HTTP and MCP inputs

### Fixed

- CDP JWT `uris` claim now binds to the full request path (facilitator base URL path + endpoint) — the previous `host + /verify` binding caused the hosted CDP facilitator to reject all requests with 401 (`request_info.path` is now the fully-qualified path)
- The auth request host is now derived from the URI host and port (port included only when non-default, matching JavaScript `URL.host` semantics) instead of the deprecated `URI.authority` field, which is no longer populated on recent Elixir and failed dialyzer
- Bazaar text-body declarations now accept string examples and emit a matching string schema
- Bazaar output schemas now match scalar and array examples instead of always declaring an object

### Testing

- Live smoke tests against the CDP hosted facilitator (`cdp_live_test.exs`, tagged `:smoke`, excluded from the default run) covering negative-control, authentication, end-to-end verify, and settlement tiers
- `X402.TestPayments` reworked around a `Config` struct with default values; payment configuration now comes from `from_env/1` (facilitator-agnostic `X402_*` vars only) — no hardcoded sample wallets, and end-to-end receivers default to a fresh burner wallet (never the payer, and never the zero address, which USDC rejects)
- Removed `test_helper.exs` compile-time redefinition of `X402.Hooks` — the real module compiles cleanly and the test suite passes without the override

## [0.4.1] - 2026-08-15

### Fixed

- Declare `:telemetry` as a required runtime dependency so telemetry events and
  facilitator calls work in downstream installs without optional dependencies
- Start the OTP `:public_key` application used by
  `X402.Facilitator.HTTP.secure_pool_opts/0`
- Exercise the library from a minimal downstream Mix project in CI to catch
  missing runtime dependencies before publishing

## [0.4.0] - 2026-08-15

### Added

- x402 v2 `PaymentPayload` validation and complete `PaymentRequirements` matching
- Extension-echo validation for server-advertised extension data
- `X402.Plug.PaymentGate.put_settlement_amount/2` for metered `"upto"` routes
- Multi-option `accepts` and v2 `ResourceInfo` support in `X402.Plug.PaymentGate`

### Changed

- `X402.Plug.PaymentGate` now verifies before the protected handler and settles only
  after a successful handler response
- Facilitator requests now use the v2 `{x402Version, paymentPayload,
  paymentRequirements}` wire format
- `"upto"` verification uses `PaymentRequirements.amount` as the authorized maximum;
  settlement uses it as the actual atomic amount charged
- Plug route prices and all documentation examples use atomic token units

### Fixed

- Fail closed when facilitator responses omit or mistype `isValid`, `success`,
  `transaction`, or `network`
- Preserve the full request URL, including its query string, in `ResourceInfo.url`
- Reject partial or mutated accepted requirements instead of matching only five fields
- Return HTTP 500 for facilitator transport failures and malformed facilitator responses
  while retaining HTTP 400 for invalid input and HTTP 402 for payment failure
- Reject unsupported `upfront` and `escrow` flows instead of applying unsafe
  authorization-flow timing
- Avoid creating atoms from untrusted string route keys
- Compile cleanly without optional SIWX crypto dependencies and return
  `:missing_dependency` when the default verifier cannot load them

### Migration

- Replace the removed Plug option `facilitator_url:` with a supervised
  `X402.Facilitator` process and pass it via `facilitator:`.
- Replace decimal display amounts such as `"0.01"` with atomic-unit strings such as
  `"10000"` for six-decimal USDC.
- Hook callbacks use `context.payload` / `context.requirements` and return
  `{:cont, context}`, `{:halt, reason}`, or `{:recover, result}` as documented by
  `X402.Hooks`.

## [0.3.3] - 2026-03-29

### Fixed

- Payment signature format validation and SIWX ETS size cap (#39)
- Tightened Solana address validation and warn on missing idempotency cache (#36)
- Enforce `https://` scheme on facilitator `base_url` — prevents plaintext credential leakage (#35)
- Added 8KB payload size cap to `PaymentRequired` and `PaymentResponse` to prevent oversized payloads (#34)
- TLS peer verification enabled by default and `PAYMENT-SIGNATURE` header size cap (#32)

### Changed

- Bumped minimum Elixir to `~> 1.19` (#33)
- Optimized decimal parsing and centralized utility functions (#37)

### Added

- Unit test for `HTTP.secure_pool_opts/0` (#38)

## [0.3.2] - 2026-03-01

### Fixed

- Safe cache eviction with bounded cleanup to prevent full-table scans under load (#30)
- Atomic payment claim in PaymentGate plug to prevent double-settlement on concurrent requests (#30)
- SIWX ETSStorage read consistency — route `get` through GenServer to prevent revoked session reads (#31)
- Full-jitter exponential backoff in Facilitator.HTTP to prevent thundering herd on retries (#31)
- Base.decode64 padding safety in PaymentSignature and PaymentRequired (#31)


## [0.3.1] - 2026-02-25

### Fixed

- Fixed unbounded ETS cache growth vulnerability (DoS) — added `max_size` config with LRU eviction (#17)
- Fixed expired entries not being deleted during direct ETS reads (#25)
- Fixed `mix format` compliance across all files

### Added

- Comprehensive tests for `X402.Behaviour.implements?/2` with doctests (#28)
- Test coverage for facilitator hook exception and throw handling (#24)
- Optimized ETS cache with direct concurrent reads bypassing GenServer serialization (#25)

## [0.3.0] - 2026-02-17

### Added

- **SIWX (Sign-In-With-X)** — Repeat access without repayment (#14)
  - `X402.Extensions.SIWX` — CAIP-122 message construction and EIP-4361 (SIWE) format
  - `X402.Extensions.SIWX.Verifier` — behaviour for signature verification
  - `X402.Extensions.SIWX.Verifier.Default` — EVM signature verification via `ex_secp256k1`
  - `X402.Extensions.SIWX.Storage` — behaviour for access record persistence
  - `X402.Extensions.SIWX.ETSStorage` — default ETS adapter with TTL and periodic cleanup
  - `SIGN-IN-WITH-X` header encode/decode
- **"upto" Scheme** — Max-price bidding for flexible payments (#13)
  - `PaymentRequired` encode/decode for `"upto"` scheme with `maxPrice`
  - `PaymentSignature` validation: payment value ≤ maxPrice
  - Facilitator client support for upto verification with hooks
  - `PaymentGate` Plug route config supports upto scheme
- **Payment Identifier** — Idempotency extension (#12)
  - `X402.Extensions.PaymentIdentifier` — encode/decode payment IDs in payloads
  - `X402.Extensions.PaymentIdentifier.Cache` — behaviour for deduplication cache
  - `X402.Extensions.PaymentIdentifier.ETSCache` — default ETS adapter with TTL
- **Lifecycle Hooks** — Behaviour-based hooks for verify/settle (#10)
  - `before_verify/2`, `after_verify/2`, `before_settle/2`, `after_settle/2`
  - `on_verify_failure/2`, `on_settle_failure/2`
  - Context struct with request metadata, result, and error tracking

### Changed

- `ex_secp256k1` and `ex_keccak` are now optional dependencies (only needed for SIWX)
- ETS storage uses `:protected` access with direct reads bypassing GenServer for better concurrency

### Fixed

- Credo strict compliance: implicit `try`, redundant `with` clauses
- Dialyzer: unreachable pattern matches in PaymentIdentifier and SIWX Verifier

## [0.1.0] - 2026-02-14

### Added

- `X402.PaymentRequired` — encode/decode `PAYMENT-REQUIRED` headers (Base64 JSON)
- `X402.PaymentSignature` — decode/validate `PAYMENT-SIGNATURE` headers
- `X402.PaymentResponse` — encode `PAYMENT-RESPONSE` settlement headers
- `X402.Facilitator` — GenServer client for facilitator `/verify` and `/settle` endpoints
- `X402.Facilitator.HTTP` — HTTP transport with retry logic and telemetry
- `X402.Plug.PaymentGate` — drop-in Plug middleware for payment gating
- `X402.Wallet` — EVM and Solana wallet address validation
- Comprehensive test suite with >90% coverage
- Full ExDoc documentation with guides
