# Architecture — x402 Elixir SDK

> Last updated: 2026-04-01

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
                ├─ Match payload.accepted to route accepts
                │     (scheme, network, amount, asset, payTo)
                │     no match → 402 + PAYMENT-REQUIRED
                │
                ├─ Facilitator.verify → Facilitator.settle
                │     failure → 402 (+ PAYMENT-RESPONSE when settle body present)
                │
                └─ Success → PAYMENT-RESPONSE, assigns, pass through
```

## Optional Dependencies

| Dep | When Required |
|-----|--------------|
| `finch` | HTTP calls to facilitator (`X402.Facilitator`) |
| `ex_secp256k1` | SIWX signature verification (EVM) |
| `ex_keccak` | SIWX keccak hashing |

All optional deps are guarded by compile-time checks. Must `mix compile --no-optional-deps` successfully.

## Data Formats (x402 v2)

All x402 headers carry **Base64-encoded JSON payloads**:

- `PAYMENT-REQUIRED`: `{x402Version: 2, error?, resource, accepts[], extensions?}`
  - Each accept: `{scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra?}`
  - `resource`: `{url, description?, mimeType?, serviceName?, tags?, iconUrl?}`
- `PAYMENT-SIGNATURE` (PaymentPayload): `{x402Version: 2, resource?, accepted, payload, extensions?}`
  - `accepted` is a full PaymentRequirements object (must match a server accept)
- `PAYMENT-RESPONSE` (SettleResponse): `{success, transaction, network, payer?, amount?, errorReason?, extensions?}`

Network IDs use CAIP-2 format: `"eip155:8453"` (Base mainnet), `"eip155:84532"` (Base Sepolia).

## Error Handling Convention

All fallible public functions return `{:ok, result} | {:error, atom_reason}`.  
Structured atoms, never string reasons: `{:error, :invalid_base64}` not `{:error, "bad base64"}`.  
Only raise on programmer errors (wrong type passed to function, etc.).

## Telemetry Events

```
[:x402, :verify, :start]
[:x402, :verify, :stop]
[:x402, :verify, :exception]
[:x402, :settle, :start]
[:x402, :settle, :stop]
[:x402, :settle, :exception]
```

## Recent Changes (v0.3.2 → v0.3.3)

- **`X402.Utils`** — new centralized utilities module; decimal parsing optimized, shared helpers extracted from multiple modules
- **`X402.Facilitator.HTTP`** — TLS peer verification now enforced; secure pool options exposed via `HTTP.secure_pool_opts/0`; HTTPS-only on `base_url` (rejects `http://` at config time)
- **`X402.PaymentSignature`** — format validation tightened; 8KB size cap enforced to prevent oversized headers
- **`X402.PaymentRequired` / `X402.PaymentResponse`** — 8KB payload size cap added
- **`X402.Extensions.SIWX.ETSStorage`** — ETS size cap added; read consistency fixes; atomic claim to prevent double-settle; safe cache eviction
- **Elixir minimum** — bumped to `~> 1.19`
- **`X402.Header`** — new shared header utilities module
- **`X402.Wallet`** — Solana address validation tightened
