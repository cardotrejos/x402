# AGENTS.md — x402 Elixir SDK

## What This Is
The Elixir SDK for the x402 HTTP payment protocol — published on Hex.pm. A **library**, not an app. Zero-lock-in: works with any facilitator, chain, or framework.

## Quick Context
- **Language:** Elixir (OTP)
- **Published:** Hex.pm (`x402 ~> 0.5.0`)
- **CI:** GitHub Actions → `mix test --cover`
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
mix test --cover           # With coverage (target >90%)
mix dialyzer               # Type checking
mix docs                   # Generate ExDoc
MIX_ENV=test mix coveralls # ExCoveralls report
mix compile --no-optional-deps  # Must compile without Finch
```

## Code Standards (Dashbit-level)
- `@spec` on ALL public functions — no exceptions
- `@moduledoc` on ALL public modules
- `@doc` on ALL public functions, with doctests for pure return values
- `{:ok, result} | {:error, atom}` — never raise for expected failures
- Flat module naming: `X402.Wallet` not `X402.Utils.Validators.Wallet`
- Behaviours for extensibility (`@callback`), not app env config
- No GenServer unless stateful (only Facilitator uses it)

## Testing Rules
- Unit test per source file: `test/x402/foo_test.exs` ↔ `lib/x402/foo.ex`
- `doctest X402.ModuleName` in every test file
- Mox for behaviour mocking (`X402.Facilitator.HTTPBehaviour`)
- Bypass for HTTP tests — never hit real services
- Live smoke tests are tagged `:smoke` and excluded by default (`ExUnit.start(exclude: [:smoke])`). The CDP live test (`test/x402/facilitator/auth/cdp_live_test.exs`) is tiered: the negative control always runs; auth needs `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`; end-to-end verify additionally needs `X402_PAYER_KEY`; settle needs `X402_SETTLE=1`. Payment config is built by `X402.TestPayments.from_env/1` from the facilitator-agnostic `X402_*` vars (`X402_PAYER_KEY`, `X402_NETWORK`, `X402_CONTRACT`, `X402_RESOURCE`, `X402_MAX_TIMEOUT`, `X402_TOKEN_NAME`, `X402_TOKEN_VERSION`) — no receiver/payer address vars: end-to-end receivers default to a fresh burner wallet (never the payer itself, and never the zero address — USDC reverts on transfers to `address(0)`). Credentials stay facilitator-specific (`CDP_*`; `X402_FACILITATOR_URL` defaults to CDP). Defaults target USDC on Base Sepolia (`eip155:84532`, amount fixed at 1 cent). Run:
  ```bash
  CDP_API_KEY_ID=... CDP_API_KEY_SECRET=... \
    X402_PAYER_KEY=... X402_SETTLE=1 \
    mix test test/x402/facilitator/auth/cdp_live_test.exs --only smoke
  ```
- >90% line coverage required

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
