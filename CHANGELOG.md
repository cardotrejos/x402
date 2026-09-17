# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Authentication extensions**: `X402.Extensions.AuthHints` builds and
  reads `auth-hints` declarations for OAuth2 and SIWX, scoped to accepted
  payment indexes. `X402.Extensions.HTTPMessageSignatures` advertises
  signature registration, algorithms, and tags. Both include gate adapters.
  These are advertisements, not automatic credential acquisition or
  authentication enforcement.
- **HTTP message signatures**: `X402.HTTPSignature` implements a bounded
  RFC 9421 request/response profile with Ed25519, ECDSA P-256, and
  RSA-PSS-SHA512, structured fields, required-coverage and time checks,
  response-to-request binding, and caller-controlled key lookup.
  `X402.HTTPSignature.Key` imports/exports public JWKs and generates keys;
  `X402.Plug.HTTPSignatureDirectory` serves a signed public directory with
  runtime rotation. Negotiation, automatic key discovery, content-digest
  validation, and nonce replay storage remain application responsibilities.
- **Operations controls**: optional verified-payer/IP/custom-key rate
  limits in the payment gate, a per-node ETS limiter, ordered facilitator
  failover, optional `Telemetry.Metrics` definitions, and local telemetry
  statistics. Denied payments return 429 without settlement. With fallbacks,
  settlement makes one HTTP attempt per endpoint and only fails over on
  proven non-delivery; TLS alerts, timeouts, and HTTP 5xx remain ambiguous.
  Single-endpoint retries are unchanged.
- **Permit2 transfer method for the `exact` EVM scheme**: requirements
  declaring `extra.assetTransferMethod: "permit2"` now run end to end
  alongside the default EIP-3009 flow. `X402.Scheme.ExactEVM` dispatches
  on `transfer_method/1` (absent or `"eip3009"`, `"permit2"`; anything
  else — `"erc7710"` included — is `{:unsupported_transfer_method, value}`
  and never selected by the client). `X402.Client.build_payment/3` signs a
  Permit2 `PermitWitnessTransferFrom` through `X402.Permit2.sign_exact/2`
  — spender `x402ExactPermit2Proxy` (`exact_proxy_address/0`), witness
  `payTo`, permitted amount the exact `amount` — producing a
  `%{"signature", "permit2Authorization"}` scheme payload;
  `build_exact_authorization/2`, `domain/1`, and `digest/2` (the witness
  shape selects the EIP-712 type) generalise the upto helpers, which remain
  as aliases. `X402.Scheme.EVM.permit2_precheck/3` runs the local
  pre-checks (recipient, amount, token, spender, validity window) before
  the facilitator round-trip, and `X402.Facilitator.verify/2` and
  `settle/2` reject an exact-Permit2 payload whose `permitted.amount`
  differs from the requirements (`{:invalid_exact_payment,
  :amount_mismatch}`) without calling out. `X402.Verify.EVM` detects the
  payment `kind` (`:eip3009`, `:permit2_exact`, `:permit2_upto`) and runs
  the reference facilitator's Permit2 checklist in order at every level —
  scheme, network, spender, recipient, deadline, `validAfter`, amount,
  token, signature — with `:full` additionally requiring the proxy to be
  deployed, simulating the proxy's `settle` (`upto` as the witness
  facilitator), classifying Permit2 / proxy custom errors by selector or
  revert text, and diagnosing unexplained reverts via `PERMIT2()`,
  `balanceOf`, and `allowance(payer, Permit2)`; the `permit2_*` and
  `upto_*` reasons are new. `X402.Facilitator.Engine` settles exact-Permit2
  and `upto` through the x402 proxies with calldata from
  `X402.Permit2.exact_settle_calldata/2` / `upto_settle_calldata/3` (the
  same encoders verification simulates with), `supported/1` advertises
  `exact` and `upto` per network, and `upto` is routed only when
  `extra.facilitatorAddress` is the engine's signer. `X402.Plug.PaymentGate`
  derives exact-Permit2 replay keys from the signed permit's `from` +
  `nonce`; exact and upto share the `evm-permit2:` prefix because Permit2
  nonces are per owner, not per spender
- **Resource-server lifecycle hooks — `X402.Hooks`
  `on_protected_request/2` and `on_verified_payment_canceled/2`**: two
  optional callbacks invoked by `X402.Plug.PaymentGate` and
  `X402.MCP.Server` with an `X402.Hooks.RequestContext` (transport, conn
  or MCP request, matched route, `method` / `path` / `path_params` or
  `tool`, and the requirements and extensions about to be advertised),
  mirroring the reference resource server's `onProtectedRequest` and
  `onVerifiedPaymentCanceled`. `on_protected_request/2` runs before any
  payment processing on every request matching a gated route or paid tool
  and may continue with `{:cont, context}` — optionally replacing
  `context.requirements` or `context.extensions` for that request, for a
  per-caller discount — answer directly with `{:halt, {status, body}}`
  (telemetry `reason: {:hook_halted, status}`), or let the handler run
  unpaid with `{:halt, :skip_payment}` (`[:x402, :plug, :pass_through]` /
  `[:x402, :mcp, :pass_through]` with `reason: :hook_skipped`); an
  exception or invalid return fails closed with an internal error.
  `on_verified_payment_canceled/2` runs when a payment the facilitator
  verified is not settled — the handler answered a status of 400 or above
  or returned an `isError` result (`reason: :handler_failed`), the MCP
  handler raised (`:handler_raised`), or settlement failed before a
  transaction was broadcast (`:settlement_failed`) — with its return value
  ignored and exceptions logged. `X402.Hooks.Default` implements neither,
  so existing hook modules keep working unchanged
- **Extension adapters — `X402.Extension`**: a behaviour packaging one
  protocol extension's server-side lifecycle (`key/0`, optional `init/1`,
  `advertise/2`, `validate/3`, `after_verify/4`, `after_settle/4`) so the
  gate runs it from a single option. `X402.Plug.PaymentGate` gains
  `:extensions` — `[module | {module, opts}]` — whose adapters advertise
  on every 402 (merged over each route's static `extensions` map),
  validate the client's echo after the generic echo check (a failure
  answers **400** `invalid_payload` with reason
  `{:extension_invalid, key, reason}`), and are notified with the
  facilitator's verify and settle results. Bundled adapters:
  `X402.Extensions.PaymentIdentifier.Adapter` (`required:`) and
  `X402.Extensions.BuilderCode.Adapter` (`app_code:`, `service_codes:`)
- **Builder-code spec format — `X402.Extensions.BuilderCode`**: the
  [builder-code extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md)
  (ERC-8021 on-chain attribution). Servers advertise the app code and up
  to 5 service codes with `extension/2`; clients echo it and attach up to
  5 service codes of their own through `enricher/1` for
  `X402.Client.build_payment/3`'s `:extensions` option (`always: true`
  attaches `s` even when not advertised, never `a`). Codes match
  `^[a-z0-9_]{1,32}$` (`valid_code?/1`); servers read an echo with
  `extract/1` and enforce the spec's echo rules with `validate_echo/2`.
  `X402.Plug.PaymentGate` and `X402.MCP.Server` run those rules on every
  payload echoing `extensions["builder-code"]`, advertised or not:
  malformed codes and more than ten service codes are rejected with
  **400** `invalid_payload` (reason `{:invalid_builder_code, detail}`),
  and an app code differing from the advertised one is an
  `:extension_echo_mismatch`. The codes travel to the facilitator inside
  the payload, which encodes them into the settlement calldata
- **Dynamic route pricing in `X402.Plug.PaymentGate`**: the route fields
  `:price`, `:pay_to`, `:description`, and `:accepts` — and `:price` /
  `:pay_to` inside each `:accepts` entry — may be 1-arity functions of
  the `Plug.Conn`, evaluated once per gated request before the 402
  advertisement and before the client's `accepted` is matched. A
  function returns the plain value or `{:ok, value}`; `{:error, reason}`
  or an invalid value answers **500** and emits
  `[:x402, :plug, :payment_rejected]` with
  `reason: {:dynamic_route_error, reason}`, never reaching the client
- **`:param` route patterns and the `:bazaar` route option in
  `X402.Plug.PaymentGate`**: a route `:path` may be a template with
  `:param` segments (`/api/users/:id`), each matching one non-empty
  segment; the captured values are assigned as `:x402_path_params`
  (`%{"id" => "42"}`) on every gated request, paid or not, and are
  available to dynamic pricing functions and hooks. The `:bazaar` route
  option (a keyword list of `X402.Extensions.Bazaar.build_extension/1`
  options) advertises the discovery extension under
  `extensions["bazaar"]` on every 402; for `:param` routes it carries
  the template as the top-level `routeTemplate` catalog key and the
  captured values as `info.input.pathParams`. Globs cannot be advertised
- **Bazaar discovery search — `X402.Facilitator.search_resources/2` and
  `X402.Extensions.Bazaar.search/2`**: the natural-language
  `GET /discovery/search` endpoint. Parameters (`:query` required;
  `:type`, `:pay_to`, `:scheme`, `:network`, `:extensions`, `:limit`,
  `:cursor`) are validated with `NimbleOptions` and sent as query string
  parameters; the response (`:resources`, `:partial_results`,
  `:pagination` with an opaque `cursor`) is validated fail-closed.
  `X402.Extensions.Bazaar.search/2` parses each entry into the same typed
  maps as `list_resources/2`. Both accept a bare keyword list to target
  the default facilitator name
- **Client lifecycle hooks — `X402.Client.Hooks`**: `before_payment/2`
  (after selection, before signing — may replace `context.requirements`
  or `{:halt, reason}`), `after_payment/2` (may replace
  `context.payload`), and `on_payment_failure/2` (may replace the error
  or `{:recover, payload}`), mirroring the reference client's
  `onBeforePaymentCreation` / `onAfterPaymentCreation` /
  `onPaymentCreationFailure`, with `X402.Client.Hooks.Context` and the
  no-op `X402.Client.Hooks.Default`. Passed as `hooks:` to
  `X402.Client.build_payment/3`, `X402.Client.Finch.request/3`, and
  `X402.MCP.Client.call/3`. Hook errors surface as
  `{:hook_halted, callback, reason}`,
  `{:hook_callback_failed, callback, reason}`, or
  `{:hook_invalid_return, callback, value}`
- **Client spend controls — `X402.Client.Policy` and
  `X402.Client.Budget`**: the `policies:` option of
  `X402.Client.select_requirements/2` (and every function and driver
  built on it) takes 2-arity functions of the candidate requirements and
  the `PaymentRequired` map returning `true`, `false`, or
  `{:error, reason}`; every policy must accept an entry for it to be
  selected. Ready-made ones: `max_amount/1`, `networks/1` (trailing `*`
  wildcard), `assets/1` (case-insensitive), and `schemes/1`.
  `X402.Client.Budget` is a session budget process (`start_link/1` with
  `:limit` and optional `:per_asset`, `reserve/3`, `release/3`,
  `spent/1`); the `budget:` driver option reserves the selected amount
  before the paid retry is sent, fails with
  `{:error, {:budget_exceeded, details}}` when a limit would be
  exceeded, and releases the reservation when the payment is not
  accepted. When none of `max_amount:`, `policies:`, or `budget:` is
  configured, `X402.Client.Finch` and `X402.MCP.Client` log a one-time
  warning that the client will sign any amount a server asks for
- **Automatic Sign-In-With-X on the client — `X402.Client.SIWX`**: the
  `siwx:` option of `X402.Client.Finch.request/3` and
  `X402.MCP.Client.call/3` (`chain_id:` — a CAIP-2 chain or `:auto` to
  pick the first advertised `supportedChains` entry the signer can sign
  — plus optional `address:`, `signature_scheme:`, and `domain:`, the
  latter required for MCP and defaulting to the resource URL's host on
  HTTP). When the 402 advertises a `sign-in-with-x` challenge the client
  signs it (`X402.Client.SIWX.authenticate/4`, refusing challenges not
  bound to the expected origin) and retries with the proof and no
  payment; a response that is not payment-required is returned with
  `siwx_authenticated: true`, otherwise the payment flow continues with
  the proof attached to the paid request too. MCP proofs travel in
  request `_meta["x402/sign-in-with-x"]` (`X402.MCP.siwx_meta_key/0`,
  `put_siwx/2`, `fetch_siwx/1`). Each attempt emits
  `[:x402, :client, :siwx]` with `:transport`, `:chain_id`, and
  `:outcome` (`:authenticated` or `:payment_required`) or `:reason`;
  failures surface as `{:error, {:siwx, reason}}`
- **Sign-In-With-X spec format — `X402.Extensions.SIWX`**: the
  [sign-in-with-x extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/sign-in-with-x.md)
  as the spec defines it, for EVM and Solana wallets. Servers advertise a
  CAIP-122 challenge under `PaymentRequired.extensions["sign-in-with-x"]`
  (`challenge/1` / `X402.Extensions.SIWX.Challenge`: fresh nonce and
  timestamps per 402, `supportedChains` with `eip191` / `ed25519` types,
  and the proof JSON schema); clients sign it with any `X402.Signer`
  (`sign/3` — EIP-4361 text signed with EIP-191 `personal_sign` on
  `eip155:*`, Sign-In-With-Solana text signed with Ed25519 on `solana:*`,
  message construction in `X402.Extensions.SIWX.Message`) and send the
  proof fields Base64-encoded in `SIGN-IN-WITH-X` (`encode_signed/1`);
  servers decode (`decode_signed/1`) and verify (`verify/2`) them in the
  spec's check order, each failure carrying one of the spec's
  machine-readable codes (`invalid_siwx_domain_mismatch`,
  `invalid_siwx_uri_mismatch`, `invalid_siwx_issued_at_too_old`,
  `invalid_siwx_expired`, `invalid_siwx_nonce`,
  `invalid_siwx_unsupported_chain`, `invalid_siwx_signature`, ...).
  Nonces are tracked through any `X402.Extensions.PaymentIdentifier.Cache`
  adapter (`:nonce_cache`): a proof verifies only against a nonce the
  server issued and is consumed atomically, so it authenticates at most
  once. `X402.Extensions.SIWX.Verifier.Ed25519` verifies Solana proofs over
  OTP `:crypto` (small-order public keys refused); the existing
  `X402.Extensions.SIWX.Verifier.Default` covers EVM
- **`X402.Extensions.SIWX.Server`**: the server side in one struct —
  `new/1` validates `:domain`, `:uri`, `:supported_chains`, `:statement`,
  `:resources`, `:expiration_seconds`, `:max_age_seconds`,
  `:clock_skew_seconds`, `:nonce_cache`, `:storage`, `:ttl_ms`,
  `:verifier`, and `:ed25519_verifier`; `challenge/1` issues (and records)
  a challenge, `verify/2` checks a proof, `record_payment/4` remembers
  which address paid for which resource after settlement, and
  `authenticate/3` combines verification with that history
  (`{:error, :not_authorized}` when the wallet has not paid). Usable from
  any framework
- **`X402.Plug.PaymentGate` `:siwx` option** (a keyword list of
  `X402.Extensions.SIWX.Server.new/1` options): every 402 advertises a
  fresh challenge (exempt from the extension echo check because it changes
  per response); a request carrying `SIGN-IN-WITH-X` is authenticated
  against the resource URL the gate advertises — a previously paying
  address runs the handler without payment, with `:x402_siwx_address` and
  `:x402_siwx_chain_id` assigned and `[:x402, :plug, :siwx_authenticated]`
  emitted; an address with no record falls through to the normal payment
  flow when `PAYMENT-SIGNATURE` is also present and otherwise receives
  **402** with a fresh challenge; a proof that fails verification receives
  **402** with the `invalid_siwx_*` code as the `error` string (telemetry
  `reason: {:siwx, code}`); an undecodable header receives **400**
  `invalid_siwx_header`. After a successful settlement the payer (the
  settle response's `payer`, falling back to the authorization's `from`)
  is recorded for the resource URL through `:storage` for `:ttl_ms`
- **`X402.Signer.sign_message/2`** and the optional
  `c:X402.Signer.sign_message/2` signer callback: EIP-191 `personal_sign` over an arbitrary message,
  returning the `0x`-prefixed 65-byte `r || s || v` hex signature (`v`
  normalized to 27/28). `X402.Signer.LocalKey` implements it; signers
  without it return `{:error, :unsupported_signer}`
- **Payment-identifier spec format — `X402.Extensions.PaymentIdentifier`**:
  the [payment-identifier extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/payment_identifier.md)
  under its spec key `"payment-identifier"`. Servers advertise it with
  `extension/1` (`info.required` plus the JSON `schema/0`); clients echo the
  advertisement and add `info.id` through the new `enricher/1` for
  `X402.Client.build_payment/3`'s `:extensions` option (fresh
  `generate_id/0` per payment, or an explicit `:id`; `always: true` attaches
  it even when not advertised). Ids are 16–128 characters of
  `[A-Za-z0-9_-]` (`valid_id?/1`); servers read them with `extract_id/1`
  (tagged `{:spec, id}` or `{:legacy, id}`), check `required?/1`, and bind
  them to a request through `fingerprint/2` (SHA-256 over scheme, network,
  asset, amount, `payTo`, HTTP method, path, and MCP tool name)
- **Payment-identifier enforcement in `X402.Plug.PaymentGate` and
  `X402.MCP.Server`**: a malformed spec id is rejected with **400**
  `invalid_payload`; a missing id under `required: true` with **400**
  `payment_identifier_required`. With a `:payment_identifier_cache`, each id
  is bound to its request fingerprint under a `"pid:"`-prefixed key: reusing
  it for a different request is rejected with **409**
  `payment_identifier_conflict`, while the same request proceeds and stays
  subject to the signature-derived replay key. A binding is released
  together with the replay claim (handler status >= 400, verification or
  settlement failure), so the id may be retried. The MCP server reports the
  same three reasons in its payment-required result and fingerprints the
  tool name instead of method/path
- **`EXTENSION-RESPONSES` sidechannel — `X402.ExtensionResponses`**:
  encode/decode of the facilitator's per-extension outcome header (x402 v2
  §7.2.1; `encode/1`, `decode/1`, `from_headers/1`,
  `from_headers_lenient/1`, 8 KB cap). `X402.Facilitator.verify/2` and
  `settle/2` results now carry the response `:headers` and the decoded
  sidechannel as `:extension_responses` (`nil` when absent or malformed — a
  bad header is dropped with a `[:x402, :extension_responses, :decode]`
  telemetry event rather than failing the payment). `X402.Plug.PaymentGate`
  assigns the verify-time outcomes as `:x402_extension_responses` and adds
  the settle-time outcomes as `:extension_responses` to the
  `[:x402, :plug, :payment_verified]` metadata; the sidechannel is never
  forwarded to the buyer. Engines behind `X402.Plug.Facilitator` may return
  `{:ok, wire_response, extension_responses}` from `verify/3` / `settle/3`
  and the plug emits the header (an unencodable map is logged and dropped)
- **Bazaar service metadata — `X402.Extensions.Bazaar.Metadata`**: the
  bazaar spec's validation and soft-drop rules for provider metadata
  (`valid_service_name?/1`, `sanitize_tags/1`, `valid_icon_url?/1`,
  `sanitize_resource/1`) and dynamic-route templates
  (`valid_route_template?/1`, `extract_route_template/1`), mirroring the
  reference SDKs. `X402.Extensions.Bazaar.build_extension/1` gains
  `:route_template`, published as the extension's top-level
  `routeTemplate` catalog key. `X402.Plug.PaymentGate` now validates
  `:service_name` (non-empty printable ASCII, at most 32 characters),
  `:tags` (at most 5 unique case-insensitive entries under the same rule),
  and `:icon_url` (absolute http(s), no userinfo, no IP literal or loopback
  host, at most 2048 characters) at init and rejects invalid values

### Changed

- **`X402.Client.Finch.request/3` and `X402.MCP.Client.call/3` responses
  gain `:siwx_authenticated`** (`true` when the server accepted a
  Sign-In-With-X proof instead of a payment); code that pattern-matches
  the whole response map must allow it. Their error unions gain
  `{:siwx, reason}`, `{:budget_exceeded, details}`, and the
  `X402.Client.Hooks` hook errors
- **`X402.Plug.PaymentGate` and `X402.MCP.Server` may now emit
  `:pass_through` for a matched route or paid tool** — with
  `reason: :hook_skipped` when `on_protected_request/2` returned
  `{:halt, :skip_payment}` — where previously the event only meant "route
  did not match". `:payment_rejected` gains the reasons
  `{:hook_halted, status}` and `{:invalid_builder_code, detail}` on both
  transports, and `{:dynamic_route_error, reason}` and
  `{:extension_invalid, key, reason}` on the gate
- `X402.Client` no longer selects requirements whose `extra.paymentFlow`
  names a flow it cannot run: only the default `"authorization"` flow
  (explicit or omitted) is recognized, so `upfront` and `escrow` entries —
  which commit funds before the resource executes — are skipped, per spec
  §6.1. A `PAYMENT-REQUIRED` offering only such entries yields
  `{:error, :no_acceptable_requirements}`
- **Upgrading.** Custom `X402.Extensions.PaymentIdentifier.Cache` adapters
  must accept two new `value` forms in `put_new/3` and `put/3`:
  `{:bound, fingerprint}` (payment-id bindings, stored under `"pid:"`
  keys) and `{:siwx_nonce, :issued | :used}` (Sign-In-With-X nonces, under
  `"siwx:issued:"` / `"siwx:used:"` keys). Adapters that serialize values
  by pattern-matching on `:verified` / `{:rejected, reason}` need updating;
  the bundled ETS and Redis adapters already do. `X402.Facilitator.verify/2`
  and `settle/2` results gain `:headers` and `:extension_responses` keys
  (previously `%{status: ..., body: ...}`); code that pattern-matches the
  whole map must allow them, and hooks see them in `context.result`

### Deprecated

- The pre-0.7.0 `"paymentIdentifier"` extension format (a Base64 JSON
  `{"paymentId": ...}` string or a `%{"paymentId" => ...}` map, optionally
  wrapped in `%{"info" => ...}`). It is still accepted by the gate and the
  MCP server with the same assign, telemetry, and fingerprint binding —
  each one emits `[:x402, :payment_identifier, :legacy]` and the first logs
  a warning — and will be removed in 1.0.0. Legacy ids satisfy
  `required: true` and are exempt from the spec's length and character
  rules. `X402.Extensions.PaymentIdentifier.encode/1`, `decode/1`, and
  `fetch_payment_id/1` are deprecated with it
- The pre-0.7.0 `SIGN-IN-WITH-X` header format (a Base64 JSON
  `{"message", "signature"}` object carrying the signed EIP-4361 text).
  `X402.Extensions.SIWX.decode_signed/1` still reports it as
  `{:legacy, proof}` and `verify/2` applies the same checks to the exact
  text that was signed; the gate emits `[:x402, :siwx, :legacy]` per proof
  and logs a one-time warning. Removed in 1.0.0 together with
  `X402.Extensions.SIWX.encode_header/1` and `decode_header/1`
  (`encode/1` and `decode/1` remain as the EIP-4361 text codec)

### Security

- Pin every GitHub Actions step in `.github/workflows/ci.yml` to a commit
  SHA (with the tag recorded in a comment) and grant the workflow
  least-privilege `permissions: contents: read`

## [0.6.1] - 2026-09-16

### Fixed

- Accept Solana signers in `X402.Client.Finch` and `X402.MCP.Client` option
  validation. Both clients now require `address/1` plus either `sign_eip712/3`
  or `sign_ed25519/2`, allowing `X402.Signer.SolanaKey` to reach the SVM
  payment flow. Scheme-specific callback checks remain in the signer dispatcher.

### Security

- Update the repository lockfile to Mint `1.10.0`, which fixes
  [CVE-2026-82728](https://github.com/elixir-mint/mint/security/advisories/GHSA-g83f-2j6r-q6m4)
  and [CVE-2026-82729](https://github.com/elixir-mint/mint/security/advisories/GHSA-7p8w-j234-7qc8).
  Applications using Finch should also run `mix deps.update mint` to update
  their own lockfiles; upgrading x402 alone does not ensure this transitive
  dependency is updated.

## [0.6.0] - 2026-08-28

### Added

- **SVM on-chain facilitator — `X402.Facilitator.SVMEngine`**: verify and
  settle `exact` payments on `solana:*` networks yourself, completing the
  facilitator role for Solana (previously client-signing + structural
  validation only). `X402.Verify.SVM` runs the reference static-path
  checklist locally — mandatory Ed25519 verification of every required
  signer except the fee-payer slot (simulation runs `sigVerify: false`, so
  local verification is the signature check), fee-payer identity and
  isolation, the instruction whitelist via `X402.Scheme.ExactSVM`, and
  `simulateTransaction` at `:full` — emitting the TypeScript reference's
  `invalid_exact_svm_*` reason strings. Settlement co-signs the fee-payer
  slot (`X402.Solana.Transaction.attach_signature/3`), broadcasts with
  `skipPreflight: true`, polls `getSignatureStatuses` to
  confirmed/finalized, and dedups duplicate settlements atomically
  (`duplicate_settlement`, 120s TTL) through any
  `X402.Extensions.PaymentIdentifier.Cache` adapter. `X402.Solana.RPC`
  provides the underlying Solana JSON-RPC calls over the existing
  `X402.RPC` transport. Transactions using address lookup tables are
  rejected fail-closed
- **Multi-engine `X402.Plug.Facilitator`**: the new `engines:` option
  serves several engines from one endpoint, routed by the request's
  (scheme, network) against each engine's `supported/1`; `GET /supported`
  merges kinds, extensions, and signers across engines. A single EVM +
  SVM facilitator process is now one Plug
- **ERC-6492 counterfactual settlement** in `X402.Facilitator.Engine`:
  with the new `eip6492_allowed_factories:` allowlist (default `[]` keeps
  the previous fail-closed behavior), settlement of a payment signed by a
  not-yet-deployed smart wallet broadcasts the wrapper's factory calldata
  as its own transaction first — gated by the allowlist and the new
  `max_deploy_gas_limit:` ceiling — then settles with the unwrapped inner
  signature, mirroring the reference facilitators
  (`eip6492_factory_not_allowed` / `smart_wallet_deployment_failed`).
  `X402.Verify.EVM`'s `:simulate` option gains `:counterfactual_only` so
  settle's independent re-verify keeps the atomic Multicall3
  deploy-and-transfer proof even with simulation otherwise off
- **Transfer-event verification on settlement receipts**: a confirmed
  settlement is reported successful only when the receipt carries the
  matching ERC-20 `Transfer(from, to, value)` log for the verified
  payment (`invalid_exact_evm_transfer_event_mismatch` otherwise),
  closing the gap between "transaction mined" and "payment delivered"
- **Pending-settlement reconciliation** —
  `X402.Facilitator.PendingSettlementStore` behaviour with a bundled
  supervised ETS adapter (5-minute TTL): when a broadcast's confirmation
  cannot be established, both engines record the transaction before
  returning `settlement_pending`, and a retried settle reconciles against
  the already-broadcast transaction (delete-before-reconcile) instead of
  broadcasting twice. `X402.Plug.PaymentGate` complements it from the
  resource-server side by retrying a `settlement_pending` settle exactly
  once, mirroring the reference SDKs' `settleWithPendingRetry`
- **Inline local verification in `X402.Plug.PaymentGate`** — the new
  `local_verification:` option runs `X402.Verify.EVM` (at `:structural`,
  `:signature`, or `:full` with an `X402.RPC` config) inside the gate
  before the facilitator round-trip for exact-EVM payments; rejections
  answer 402 with the canonical reason strings, infrastructure failures
  fail closed as 500, and non-EVM kinds skip it (the facilitator remains
  the authority)

- `X402.Facilitator.NonceManager` — serializes fee-payer transaction nonces
  for concurrent settlements (fetch-once-then-increment, reset on broadcast
  rejection); pass to `X402.Facilitator.Engine.new/1` via `nonce_manager:`.
  Without it, concurrent settles race on the pending nonce and a valid
  payment can fail with an unused authorization

- **Client-side `upto` payments via Permit2** (ecosystem report §8 P2.2):
  the new `X402.Permit2` module builds and signs the upto-EVM scheme's
  Permit2 `PermitWitnessTransferFrom` — `permitted.amount` is the
  advertised **maximum** (the server settles for actual usage up to it),
  the spender is the canonical `x402UptoPermit2Proxy`
  (`0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002`), and the witness struct
  `Witness(address to,address facilitator,uint256 validAfter)` binds the
  requirements' `payTo` and `extra.facilitatorAddress` so only the
  announced facilitator can settle. Signing hashes against the canonical
  version-less Permit2 EIP-712 domain (name `"Permit2"`, chain id from
  the CAIP-2 network, verifying contract
  `0x000000000022D473030F116dDEE9F6B43aC78BA3`);
  `X402.EIP712.domain_separator/1` now supports such version-less
  domains. `X402.Scheme.UptoEVM` implements `sign/3` and `signable?/1`
  (an `eip155:*` network plus `extra.facilitatorAddress`, as delivered
  by the facilitator's `GET /supported`), so
  `X402.Client.build_payment/3` and `X402.Client.Finch.request/3` pay
  `upto` requirements out of the box; entries without a facilitator
  address are never selected, and signing one returns
  `{:error, {:missing_extra, "facilitatorAddress"}}`. See the new
  Metered `upto` payments section in the client guide
- **SVM (Solana) `exact` scheme — `X402.Scheme.ExactSVM`** (ecosystem
  report §8 P2.3): the client half of `exact` on `solana:*` networks plus
  structural server-side validation, registered as a built-in. `sign/3`
  builds the reference v0 transaction byte-for-byte (`SetComputeUnitLimit`,
  `SetComputeUnitPrice`, SPL Token / Token-2022 `TransferChecked` to the
  ATA derived from `payTo` + `asset`, and a Memo — the seller's
  `extra.memo` or a random nonce), signs it with the payer's Ed25519 key,
  and leaves the sponsor's (`extra.feePayer`, required) signature slot as
  the zeroed placeholder of a partially signed transaction. Blockhash
  resolution follows the spec (server's `extra.recentBlockhash` hint, then
  the new `:svm_blockhash` / `:svm_blockhash_fetcher` client options), and
  `:svm_decimals` / `:svm_token_program` cover mints outside the built-in
  known-asset table. `validate_payload/3` enforces the wire shape (Base64,
  1232-byte cap, decodable v0/legacy transaction, advertised fee payer as
  account 0); `precheck/3` enforces the facilitator's static-path
  whitelist (spec §3.1: 3–7 instructions in the reference order, the
  5 lamports/CU cap, §2.1.1 fee payer isolation, transfer semantics, memo
  enforcement) without any RPC. Full on-chain verification and settlement are
  available through `X402.Verify.SVM` and `X402.Facilitator.SVMEngine`.
  Transactions using address lookup tables bypass the pure `precheck/3`, then
  the bundled verifier and engine reject them fail-closed because lookup-table
  resolution is not implemented
- **`X402.Signer.SolanaKey` and the optional `sign_ed25519/2` signer
  callback**: Ed25519 signing over OTP's `:crypto` (no new dependencies);
  `new/1` accepts a raw 32-byte seed, a 64-byte `solana-keygen` keypair,
  or Base58/Base64 encodings of either. The `X402.Signer` chain-family
  callbacks are now both optional — a signer implements the families it
  supports and the dispatchers return `{:error, :unsupported_signer}` for
  the rest
- **Solana primitives, dependency-free**: `X402.Base58` (Bitcoin-alphabet
  encode/decode), `X402.Solana` (address validation, Ed25519 on-curve
  check, `find_program_address/2`, `associated_token_address/3`), and
  `X402.Solana.Transaction` (compact-u16, v0 message compilation matching
  `@solana/kit`'s account ordering byte-for-byte, wire
  serialization/decoding). Cross-checked against fixtures generated with
  the official Solana TypeScript stack
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
- **Browser paywall** (ecosystem report §8 P2.5): new `paywall:` option on
  `X402.Plug.PaymentGate` (default `nil` — behavior unchanged). When set to a
  module implementing the new `X402.Paywall` behaviour, pre-handler 402
  responses to requests that look like a browser page load (`Accept` header
  containing `text/html` **and** `User-Agent` containing `Mozilla`, the
  heuristic shared by the reference Go/TypeScript middlewares) carry a
  human-usable HTML body instead of the `{}` JSON body. The
  `PAYMENT-REQUIRED` header is identical on both forms, and API clients,
  absent-`Accept` requests, 400/500 statuses, and post-handler settlement
  failures remain byte-identical to previous releases. Ships
  `X402.Paywall.Default`, a self-contained few-KB page (inline CSS, no
  external requests, no build step) that shows the advertised price, asset,
  network, and recipient, embeds the exact Base64 `PAYMENT-REQUIRED` value
  with manual retry instructions, and includes a dependency-free EIP-1193
  wallet flow for `exact`/`eip3009` EVM options — sign the
  `TransferWithAuthorization` typed data via `eth_signTypedData_v4`, retry
  with `PAYMENT-SIGNATURE`, replace the document — degrading gracefully
  without a wallet. All interpolated values are HTML-escaped and the embedded
  config JSON is script-safe, so hostile route descriptions or service names
  cannot inject markup. A renderer returning `{:error, reason}` logs a
  warning and falls back to the JSON body. See the new "Browser Paywall"
  guide.
- **`X402.Scheme` behaviour — pluggable payment schemes** (ecosystem report
  §5.3.1/§8 P1.1): everything scheme-specific now dispatches through one
  behaviour, so adding a chain or scheme means writing one module and
  passing it as an option instead of editing core modules. Callbacks:
  `scheme/0` and `networks/0` (metadata — CAIP-2 patterns with trailing-`*`
  wildcards), `sign/3` and the optional `signable?/1` (client side),
  `validate_payload/3` and `precheck/3` (server side). Resolution lives in
  `X402.Scheme.Registry` (exact CAIP-2 match beats wildcard, longest
  wildcard prefix wins, user modules beat built-ins) and is seeded with
  `X402.Scheme.ExactEVM` (`exact` on `eip155:*`, EIP-3009 signing plus the
  existing local pre-checks) and `X402.Scheme.UptoEVM` (`upto` on
  `eip155:*`, the existing ceiling validation) — extracted from
  `X402.Client`, `X402.Plug.PaymentGate`, and `X402.PaymentSignature`
  with unchanged external behavior. Custom schemes register via the new
  `schemes:` option on `X402.Plug.PaymentGate` (routes may then use the
  registered scheme names), `X402.Client.build_payment/3` /
  `select_requirements/2`, `X402.Client.Finch.request/3`, and the new
  `X402.PaymentSignature.validate/3` / `decode_and_validate/3` — no
  application environment, no global registration. Kinds with no
  registered module keep their historical behavior: validation passes
  through, the gate skips pre-checks, and the client returns
  `{:error, {:unsupported_kind, scheme, network}}`. Scheme
  `validate_payload/3` failures shaped `{:invalid_scheme_payment, reason}`
  are answered with HTTP 400 by the gate. Shared EVM authorization
  pre-checks are reusable via `X402.Scheme.EVM.authorization_precheck/3`.
  See the new Custom Payment Schemes guide
- **Run your own facilitator** (ecosystem report §8 P2.1 — no official SDK
  ships a runnable facilitator server; this SDK now does):
  - `X402.Facilitator.Engine` — the facilitator role engine behind the
    v2 facilitator API wire shapes: `verify/3` delegates to
    `X402.Verify.EVM` at the `:full` level and returns the `/verify`
    response with canonical `invalidReason` strings; `settle/3`
    re-verifies independently (normative for exact-EVM), builds the
    `transferWithAuthorization` EIP-1559 transaction (batched
    `eth_estimateGas` with a safety margin, `eth_maxPriorityFeePerGas` +
    `eth_feeHistory` fees with an `eth_gasPrice` fallback, `pending`
    nonce), signs its digest through the `X402.Signer` behaviour
    (27/28 recovery ids normalized to the EIP-1559 `yParity`), broadcasts
    via `eth_sendRawTransaction`, and polls the receipt — returning the
    spec's non-terminal `"settlement_pending"` with the transaction hash
    when confirmation cannot be established; `supported/1` derives the
    `GET /supported` response from the configured networks. Fee-payer
    safety is structural: the engine only ever signs
    `transferWithAuthorization` calldata built from verified
    authorization fields with `to` = the requirements' `asset` and
    `value` `0` — counterfactual ERC-6492 payments are rejected
    fail-closed at verify and settle (deployed ERC-1271 wallets are fully
    supported). `X402.Hooks` wraps both operations, and
    `[:x402, :facilitator_engine, :verify | :settle]` telemetry is
    emitted.
  - `X402.Plug.Facilitator` — a compile-guarded Plug scaffold serving
    `POST /verify`, `POST /settle`, and `GET /supported` over an engine:
    strict v2 wire-object parsing (400 otherwise), an 8KB body cap
    consistent with the SDK's header caps (413), an optional
    constant-time bearer-token check (401), and opaque 500 bodies for
    infrastructure errors. Protocol-level rejections are 200s per the
    facilitator API convention; the optional `/discovery/resources`
    answers 404.
  - `X402.RLP` and `X402.Transaction` — minimal pure RLP and EIP-1559
    typed-transaction encoders (no new dependencies), tested against the
    published RLP specification vectors and a signed-transaction
    sender-recovery proof.
  - `X402.EIP3009.transfer_calldata/3` — the `transferWithAuthorization`
    calldata builder (both the `(v, r, s)` and dynamic-`bytes` variants),
    extracted from `X402.Verify.EVM` so verification's simulation and the
    engine's settlement sign the exact same bytes; plus
    `X402.EIP712.encode_dynamic_bytes/1`.
  - `examples/facilitator/` — a runnable facilitator (env-driven
    `PRIVATE_KEY` / `RPC_URL` / `NETWORK` / `PORT`, Bandit + Finch)
    mirroring the upstream `examples/typescript/facilitator`, with a
    self-contained boot check. Documented in the new "Run Your Own
    Facilitator" guide.
- **Full local payment verification for EVM `exact`/`eip3009` payments**
  (`X402.Verify.EVM`, ecosystem report §8 P1.2 and the verification half of
  P2.1): runs the reference facilitator verify checklist locally instead of
  trusting a remote facilitator's verdict, at three explicit levels that
  never silently downgrade — `:structural` (pure checks: scheme/network/
  domain requirements, payload shape, `payTo` equality, exact amount, timing
  with the 6-second settlement buffer), `:signature` (EIP-712 digest
  recomputation + EOA recovery via the optional crypto deps, else
  `{:error, :missing_dependency}`), and `:full` (on-chain: chain-id
  cross-check, payer-bytecode signature routing — ECDSA with no code, strict
  ERC-1271 `isValidSignature` with code and no ECDSA fallback — asset
  bytecode presence, `balanceOf` funding, and `transferWithAuthorization`
  `eth_call` simulation with failure diagnosis mirroring the reference
  `invalidReason` set, else `{:error, :rpc_not_configured}`). ERC-6492
  counterfactual signatures copy the reference Go fail-closed design: the
  deployment factory must be explicitly allowlisted
  (`eip6492_allowed_factories`, default `[]` rejects all) and validity is
  proven only by an atomic Multicall3 deploy-and-transfer simulation.
  `reason_string/1` maps local reason atoms onto the canonical cross-SDK
  `invalidReason` strings. Documented in the new "Local Payment
  Verification" guide, including the `before_verify` hook pattern for
  gating `X402.Plug.PaymentGate` requests on local verification.
- `X402.RPC` — a minimal Ethereum JSON-RPC client over the user's own Finch
  pool (`eth_call`, `eth_getCode`, `eth_chainId`, and ordered batch requests
  in one HTTP round-trip), with NimbleOptions-validated configuration,
  structured errors, `[:x402, :rpc, :request]` telemetry, and the same
  https-with-localhost-exemption enforcement as `X402.Facilitator.HTTP`.
  Compiles and fails cleanly (`{:error, :missing_dependency}`) without the
  optional Finch dependency.
- `X402.ERC6492` — pure parsing and building of ERC-6492 counterfactual
  signature wrappers (magic-suffix detection, bounds-checked ABI decoding of
  the factory/calldata/inner-signature tuple); classification policy lives
  in the verifier, which never treats a wrapper as proof by itself.
- `X402.Extensions.OfferReceipt` — the
  [offer-and-receipt extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md):
  servers sign the payment terms they advertise (offers under
  `extensions["offer-receipt"].info.offers[]`) and confirm delivery after
  settlement (a receipt under `info.receipt`); clients verify both. Supports
  the spec's two artifact formats — EIP-712 (fixed chain-agnostic domain
  `{name, version: "1", chainId: 1}`, canonical `Offer`/`Receipt` types,
  signing through `X402.Signer`, verification by signer recovery) and compact
  JWS (`ES256K`/`EdDSA` via OTP `:crypto` in
  `X402.Extensions.OfferReceipt.JWS`, with RFC 8785 JCS payload
  canonicalization and mandatory `alg`/`kid` headers). Includes the
  `info`/`schema` declaration builders mirroring the spec's §6 schemas,
  fail-closed `fetch_offers/1` / `fetch_receipt/1` extraction, structural
  `validate_offer/1` / `validate_receipt/1`, the v1-name → CAIP-2 network
  conversion (`to_caip2/1`), and payload builders. Boundaries: JWS
  verification takes an explicit public key (`kid` DID URLs are never
  resolved — no network access), and signer *authorization* (§4.5.1) remains
  caller policy, supported via `:expected_signer`
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

- The dialyzer PLT filename now carries the OTP/Elixir versions
  (`priv/plts/project-otp<release>-<version>.plt`), and the CI PLT cache no
  longer falls back to other toolchains' entries — after a toolchain bump,
  `mix dialyzer` builds a fresh PLT instead of slowly migrating the old
  toolchain's file in place (the near-silent churn that read as a hang;
  note the first run on a new OTP still spends several minutes building
  the core PLTs)
- Development and CI toolchain bumped to Elixir 1.20.4 / Erlang OTP 29.0.5;
  CI now tests both the supported floor (Elixir 1.19 / OTP 27) and the
  latest stack. The library still requires only `~> 1.19`. Bitstring
  patterns that read a size from an outer variable now use the explicit
  pin operator (`binary-size(^len)`), fixing the deprecation warnings the
  Elixir 1.20 type checker emits for the implicit form. `credo` updated to
  1.7.19 for Elixir 1.20 compatibility
- **Replay/dedup keys are now canonical**: `X402.Plug.PaymentGate` keys
  its replay claim on signature-covered payment identity — the EIP-3009
  `from` + `nonce` for exact-EVM, the Permit2 owner + nonce for upto, and
  the sha256 of the signed message bytes for exact-SVM — instead of the
  raw header hash, so a re-encoded duplicate of the same authorization
  (JSON key order, whitespace, Base64 variant) can no longer bypass
  replay protection. Unknown schemes keep the raw-header-hash behavior.
  The gate also decodes an echoed `payment_identifier` extension
  (malformed → 400) and surfaces the client's `paymentId` in
  `conn.assigns[:x402_payment_id]`, the settlement context, and telemetry
  — deliberately **not** as the dedup key, which must never derive from
  unsigned client-controlled fields
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
  and the SDK's multi-role trust model: delegated versus optional local
  verification, transport hardening, replay/settlement configuration, and the
  pre-1.0 independent-audit boundary
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

### Client and transport additions

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
