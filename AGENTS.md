# Lean coding

User instructions take precedence over this file and over any skill.

Deliver what was asked, at the scope intended. Make the smallest patch that matches existing patterns.
Do not add features, files, abstractions, configurability, comments, docs, or adjacent cleanup beyond the request.
If a better approach exists, say so in one sentence and continue as asked.
If something is out of scope, mention it after the change. Do not implement it.

## Defensive code

Do not add error handling, fallbacks, retries, or validation for scenarios that cannot happen.
Trust internal code, types, and framework guarantees.
Validate only at user input and external APIs.
Fail fast. Never swallow exceptions or silently fallback.

## Tests

Do not write tests unless asked, or unless a silent failure here would corrupt data, money, or authz.
Do not write tests for reversible, low-impact changes that mirror the implementation.
If you verify with tests, they must be meaningful and necessary.
Run tests appropriate to the change. Once they pass, do not broaden or repeat testing unless new changes, failures, or unresolved concerns justify it.
Never weaken a test to get a pass. Never add implementation-detail mocks to force green.
Create a new test file only when no existing file is a suitable home.

The local tests use disposable fixtures and have no production access.
Run them, fix failures caused by the requested change, and rerun affected tests without asking for approval at each step.

## Stop

Finish the requested change. Do not invent warnings, disclaimers, approval flows, or safety checklists for hypothetical risk.
Do not use a subagent to verify or double-check your own work.
Do not add a final verification ritual.
When a step does not need the user, keep going. Stop only when you cannot continue, or before anything destructive.

# x402 Elixir SDK

## What This Is
The Elixir SDK for the x402 HTTP payment protocol — published on Hex.pm. A **library**, not an app. Zero-lock-in: works with any facilitator, chain, or framework.

## Quick Context
- **Language:** Elixir (OTP)
- **Published:** Hex.pm (`x402 ~> 0.6.0`)
- **CI:** GitHub Actions; required checks live in `.github/workflows/ci.yml`
- **Docs:** Generated via ExDoc, hosted on hexdocs.pm

## Module Map
```
lib/x402.ex                    — Top-level convenience API
lib/x402/payment_required.ex   — PAYMENT-REQUIRED header encode/decode
lib/x402/payment_signature.ex  — PAYMENT-SIGNATURE header decode/validate
lib/x402/payment_response.ex   — PAYMENT-RESPONSE header encode
lib/x402/facilitator.ex        — Facilitator GenServer (verify/settle); `otp_app:` option merges `config :app, <name>` (explicit opts win)
lib/x402/facilitator/auth.ex   — Auth behaviour (per-request request headers)
lib/x402/facilitator/auth/cdp.ex — CDP JWT authentication (Ed25519/ES256); creds passed as `:api_key_id`/`:api_key_secret` opts (config via `otp_app`, never env vars)
lib/x402/facilitator/http.ex   — HTTP transport layer
lib/x402/plug/payment_gate.ex  — Plug middleware for Phoenix/Plug apps
lib/x402/wallet.ex             — EVM + Solana address validation
lib/x402/telemetry.ex          — Telemetry event definitions
```

## Key Commands
```bash
mix test                   # Run test suite
mix coveralls              # CI coverage; threshold is configured in mix.exs
mix dialyzer               # Type checking
mix docs                   # Generate ExDoc
MIX_ENV=test mix coveralls # ExCoveralls report
mix compile --no-optional-deps  # Must compile without Finch
```

## Code Standards
- `@spec` on ALL public functions — no exceptions
- `@moduledoc` on ALL public modules
- `@doc` on ALL public functions
- `{:ok, result} | {:error, atom}` — never raise for expected failures
- Flat module naming: `X402.Wallet` not `X402.Utils.Validators.Wallet`
- Behaviours for extensibility (`@callback`), not app env config
- No GenServer unless stateful (only Facilitator uses it)

## Testing
- Mox for behaviour mocking (`X402.Facilitator.HTTPBehaviour`)
- Bypass for HTTP tests — never hit real services
- Live smoke tests are tagged `:smoke` and excluded by default (`ExUnit.start(exclude: [:smoke])`). The CDP live test (`test/x402/facilitator/auth/cdp_live_test.exs`) is tiered: the negative control always runs; auth needs `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`; end-to-end verify additionally needs `X402_PAYER_KEY`; settle needs `X402_SETTLE=1`. Payment config is built by `X402.TestPayments.from_env/1` from the facilitator-agnostic `X402_*` vars (`X402_PAYER_KEY`, `X402_NETWORK`, `X402_CONTRACT`, `X402_RESOURCE`, `X402_MAX_TIMEOUT`, `X402_TOKEN_NAME`, `X402_TOKEN_VERSION`) — no receiver/payer address vars: end-to-end receivers default to a fresh burner wallet (never the payer itself, and never the zero address — USDC reverts on transfers to `address(0)`). Credentials stay facilitator-specific (`CDP_*`; `X402_FACILITATOR_URL` defaults to CDP). Defaults target USDC on Base Sepolia (`eip155:84532`, amount fixed at 1 cent). Run:
  ```bash
  CDP_API_KEY_ID=... CDP_API_KEY_SECRET=... \
    X402_PAYER_KEY=... X402_SETTLE=1 \
    mix test test/x402/facilitator/auth/cdp_live_test.exs --only smoke
  ```
- Preserve optional-dependency compilation and the downstream consumer check for packaging/API changes. Live payment tests remain explicit opt-in; never enable settlement just to satisfy a routine check.

## Protocol Reference
- Headers: `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE` (all Base64-encoded JSON)
- Facilitator endpoints: `POST /verify`, `POST /settle`
- Network format: CAIP-2 (e.g., `"eip155:8453"` for Base)
- Schemes: `"exact"`, `"upto"`
- Spec: https://docs.x402.org

## What NOT To Do
- Don't add Ecto, Phoenix, or other heavy deps
- Don't make Finch required — it's optional
- Don't raise for expected failures (bad base64, invalid address, etc.)
- Don't add runtime deps on optional libraries
