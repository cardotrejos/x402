# Task: X402.Plug.PaymentGate

Build a drop-in Plug middleware for x402 payment gating.

## Read First
- CLAUDE.md — all coding standards
- lib/x402/ — existing protocol types and facilitator client
- mix.exs — deps and project config

## Requirements

### X402.Plug.PaymentGate
A Plug that:
1. Accepts NimbleOptions config: `:facilitator` (facilitator pid/name), `:routes` (list of route configs)
2. Each route config: `%{method: :get|:post|etc, path: "/api/resource", price: "0.01", network: "base-sepolia", asset: "USDC", receiver: "0x..."}`
3. On matching request WITHOUT payment header → respond 402 with X402.PaymentRequired JSON
4. On matching request WITH `x-payment` header → decode, verify via facilitator, settle on success
5. On non-matching request → pass through (call next plug)
6. Emit telemetry events: `[:x402, :plug, :pass_through]`, `[:x402, :plug, :payment_required]`, `[:x402, :plug, :payment_verified]`, `[:x402, :plug, :payment_rejected]`

### Route Matching
- Support exact path match and glob patterns (e.g., "/api/*")
- Method matching (or `:any` for all methods)
- Path params should be normalized (strip trailing slash)

### Response Format
402 response body (JSON):
```json
{
  "x402Version": 1,
  "accepts": [{
    "scheme": "exact",
    "network": "base-sepolia",
    "maxAmountRequired": "0.01",
    "resource": "/api/resource",
    "description": "Payment required",
    "mimeType": "application/json",
    "payTo": "0x...",
    "maxTimeoutSeconds": 60,
    "extra": {}
  }],
  "error": ""
}
```

### Tests (comprehensive)
- Route matching (exact, glob, method filtering)
- 402 response format correctness
- Payment verification flow (mock facilitator)
- Pass-through for non-gated routes
- Invalid payment header handling
- Telemetry event emission
- NimbleOptions validation errors

### Quality Gates
- mix compile --warnings-as-errors
- mix compile --no-optional-deps --warnings-as-errors (Plug is optional!)
- mix test — 0 failures
- mix format --check-formatted
- mix credo --strict — 0 issues
- Every public function has @spec and @doc
- Every module has @moduledoc

### Dependencies
Add `plug` as optional dependency in mix.exs if not already present.

When done, run: openclaw system event --text "Done: x402 plug payment gate" --mode now
