# Architecture — x402 Elixir SDK

> Last updated: 2026-08-15

## Overview

A pure Elixir library implementing the x402 HTTP payment protocol. Ships as a Hex package; no web server, no database, no external services required by default.

## Design Philosophy

- **Zero lock-in**: works with any facilitator, chain, or framework
- **Minimal deps**: only `jason` and `nimble_options` are required
- **Behaviours over config**: extensibility via `@callback`, not application environment
- **Flat modules**: short, discoverable names (`X402.Wallet`, not `X402.Utils.Validators.Wallet`)

## Module Structure

```
X402                         # Top-level convenience API (delegates to submodules)
├── Utils                    # Shared utilities (decimal parsing, common helpers)
├── Header                   # Shared header utilities
├── PaymentRequired          # Encode/decode PAYMENT-REQUIRED header (Base64 JSON)
├── PaymentRequirements      # Validate and match v2 accepted requirements
├── PaymentSignature         # Decode and validate PAYMENT-SIGNATURE header
├── PaymentResponse          # Encode PAYMENT-RESPONSE header
├── Facilitator              # GenServer — HTTP client for /verify + /settle
│   └── HTTP                 # Transport implementation (uses Finch, optional)
├── Plug
│   └── PaymentGate          # Drop-in Plug middleware for Phoenix/Plug pipelines
├── Wallet                   # EVM (secp256k1) + Solana (ed25519) address validation
├── Hooks                    # Behaviour: before_verify / after_verify / on_failure
├── Telemetry                # Telemetry event definitions and metadata
└── Extensions
    ├── PaymentIdentifier    # Idempotency — pluggable cache (ETS default)
    └── SIWX                 # Sign-In-With-X (wallet-authenticated repeat access)
```

## Payment Flow (SDK perspective)

```
Incoming HTTP request
        │
        ▼
X402.Plug.PaymentGate
        │
        ├─ No PAYMENT-SIGNATURE? → 402 + PAYMENT-REQUIRED (v2 PaymentRequired)
        │
        └─ PAYMENT-SIGNATURE present?
                │
                ├─ Decode PaymentPayload (x402Version must be 2)
                │     malformed / wrong version → 400 + PAYMENT-REQUIRED
                │
                ├─ Match complete payload.accepted + extension echoes
                │     no match → 402 + PAYMENT-REQUIRED
                │
                ├─ Facilitator.verify
                │     invalid payment → 402; server/facilitator fault → 500
                │
                ├─ Assign payload/requirements → protected handler
                │     handler status >= 400 → skip settlement
                │
                └─ Successful handler → Facilitator.settle before send
                      success → PAYMENT-RESPONSE + original resource response
                      payment failure → 402; server/facilitator fault → 500
```

## Optional Dependencies

| Dep | When Required |
|-----|--------------|
| `finch` | HTTP calls to facilitator (`X402.Facilitator`) |
| `plug` | Phoenix/Plug middleware (`X402.Plug.PaymentGate`) |
| `ex_secp256k1` | SIWX signature verification (EVM) |
| `ex_keccak` | SIWX keccak hashing |

All optional integrations are guarded by dependency-availability checks. The
package must compile successfully with `mix compile --no-optional-deps`.

## Data Formats (x402 v2)

All x402 headers carry **Base64-encoded JSON payloads**:

- `PAYMENT-REQUIRED`: `{x402Version: 2, error?, resource, accepts[], extensions?}`
  - Each accept: `{scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra}`
  - `resource`: `{url, description?, mimeType?, serviceName?, tags?, iconUrl?}`
- `PAYMENT-SIGNATURE` (PaymentPayload): `{x402Version: 2, resource?, accepted, payload, extensions?}`
  - `accepted` is a full PaymentRequirements object (must match a server accept)
- `PAYMENT-RESPONSE` (SettleResponse): `{success, transaction, network, payer?, amount?, errorReason?, extensions?}`

Network IDs use CAIP-2 format: `"eip155:8453"` (Base mainnet), `"eip155:84532"` (Base Sepolia).

## Error Handling Convention

Fallible public functions return tagged tuples such as
`{:ok, result} | {:error, atom_or_structured_reason}`. Expected protocol,
validation, and transport failures are returned rather than raised. Option
validation may raise only in APIs whose contract explicitly uses
`NimbleOptions.validate!/2`, such as Plug initialization.

## Telemetry Events

```
[:x402, :facilitator, :verify, :start]
[:x402, :facilitator, :verify, :stop]
[:x402, :facilitator, :verify, :exception]
[:x402, :facilitator, :settle, :start]
[:x402, :facilitator, :settle, :stop]
[:x402, :facilitator, :settle, :exception]
[:x402, :plug, :payment_required]
[:x402, :plug, :payment_verified]
[:x402, :plug, :payment_rejected]
```

## v0.4 payment lifecycle

- The Plug validates a v2 payload and verifies payment before invoking the handler.
- Settlement is deferred until a successful handler response is ready to send.
- `"upto"` routes may replace the advertised maximum with the actual metered
  settlement amount through `put_settlement_amount/2`.
- Missing facilitator decision fields fail closed, and internal/facilitator
  failures are separated from client and payment failures by HTTP status.
- Only authorization-flow timing is supported; upfront and escrow requirements
  are rejected during route compilation.
