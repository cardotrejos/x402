# x402 — Elixir SDK for the x402 Protocol

## What This Is
First Elixir SDK for x402 (HTTP-native payments). Pure library, no Phoenix.
Public repo → will be published to Hex.pm as `x402`.

## Architecture Map
```
lib/x402/
├── payment_required.ex    # 402 response parsing/building
├── payment_signature.ex   # PAYMENT-SIGNATURE header handling
├── payment_response.ex    # PAYMENT-RESPONSE header handling
├── facilitator.ex         # GenServer client for facilitator API
├── facilitator/http.ex    # HTTP transport (Req)
├── plug/payment_gate.ex   # Plug middleware for payment gating
├── wallet.ex              # Wallet address utilities
├── telemetry.ex           # :telemetry events
├── hooks.ex               # Lifecycle hooks (before/after verify)
├── hooks/context.ex       # Hook context struct
├── hooks/default.ex       # Default hook implementations
└── extensions/
    ├── payment_identifier.ex  # Payment dedup/tracking
    ├── siwx.ex                # Sign-In with X (wallet identity)
    └── siwx/verifier/         # SIWx verification
```

## Key Decisions
- **HTTP client:** Req (not HTTPoison/Tesla)
- **No Phoenix dependency** — this is a pure library
- **Headers are Base64-encoded JSON** (V2 spec)
- **ETS for caching** — payment identifiers, SIWx sessions
- **Telemetry events** for all operations

## Development
```bash
mix deps.get          # Install deps
mix test              # Run tests (128 tests, 95.4% coverage)
mix credo --strict    # Lint
mix dialyzer          # Type checking
```

## Docs
- `docs/architecture.md` — module relationships and data flow
- `docs/quality.md` — coverage, lint, dialyzer status
- Protocol spec: https://docs.x402.org

## Rules
- All public functions must have @doc and @spec
- Doctests count as tests — keep them current
- No Phoenix imports — this must stay a pure library
- Run `mix test && mix credo --strict && mix dialyzer` before any PR
