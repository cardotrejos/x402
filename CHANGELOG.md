# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Changed

- `X402.Plug.PaymentGate` routes all replay claim/release calls through the
  `X402.Extensions.PaymentIdentifier.Cache` behaviour instead of calling
  `ETSCache` directly; adapter claim errors other than
  `{:error, :already_exists}` fail closed with HTTP 500
- Implementations of `X402.Extensions.PaymentIdentifier.Cache` must now export
  `put_new/3`; `validate_adapter/1` rejects adapters without it

### Documentation

- Documented the clustered-BEAM double-execution hazard of the per-node ETS
  replay cache in the `PaymentGate`, `Cache`, and `ETSCache` moduledocs

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
