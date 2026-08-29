# Architecture — x402 Elixir SDK

> Last updated: 2026-08-28

## Overview

A pure Elixir library implementing the x402 HTTP payment protocol. Ships as a Hex package; no web server, no database, no external services required by default.

## Design Philosophy

- **Zero lock-in**: works with any facilitator, chain, or framework
- **Minimal deps**: only `jason`, `nimble_options`, and `telemetry` are required
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
├── Client                   # Payer: select, sign, 402 → sign → retry
│   └── Finch                # HTTP payer flow over Finch (optional)
├── Signer                   # Behaviour — LocalKey (secp256k1), SolanaKey (Ed25519)
├── Scheme                   # Behaviour + Registry — ExactEVM, UptoEVM, ExactSVM
├── EIP3009 / EIP712 / Permit2  # EVM authorization building and typed-data signing
├── Facilitator              # GenServer — HTTP client for /verify + /settle
│   ├── HTTP                 # Transport implementation (uses Finch, optional)
│   ├── Engine               # Facilitator role, EVM — verify/settle/supported,
│   │                        #   ERC-6492 counterfactual deploy-then-settle,
│   │                        #   Transfer-event receipt verification
│   ├── SVMEngine            # Facilitator role, Solana — co-sign fee payer,
│   │                        #   broadcast, confirm, duplicate-settlement dedup
│   ├── NonceManager         # Serialized fee-payer nonces for concurrent settles
│   └── PendingSettlementStore  # Behaviour + ETS adapter — settlement_pending
│                            #   reconciliation (delete-before-reconcile)
├── Verify
│   ├── EVM                  # Local verify checklist (EIP-712, ERC-1271/6492,
│   │                        #   balance, simulation) at explicit levels
│   └── SVM                  # Local verify checklist (Ed25519 signatures,
│                            #   fee-payer isolation, instruction whitelist)
├── RPC                      # Minimal JSON-RPC transport (EVM and Solana hosts)
├── RLP / Transaction        # EIP-1559 typed-transaction encoding for settlement
├── Solana                   # Address, PDA, and ATA primitives (+ Base58)
│   ├── RPC                  # Solana JSON-RPC calls over X402.RPC
│   └── Transaction          # v0 message compile/serialize/decode, co-signing
├── Plug
│   ├── PaymentGate          # Drop-in Plug middleware for Phoenix/Plug pipelines
│   └── Facilitator          # Facilitator API endpoint — one engine or many
│                            #   (engines: routed by scheme/network)
├── MCP                      # Paid MCP tools — Server and Client transports
├── Paywall                  # Browser 402 page behaviour + Default renderer
├── Wallet                   # EVM (secp256k1) + Solana (ed25519) address validation
├── Hooks                    # Behaviour: before/after verify and settle
├── Telemetry                # Telemetry event definitions and metadata
└── Extensions
    ├── PaymentIdentifier    # Idempotency — pluggable cache (ETS, Redis)
    ├── SIWX                 # Sign-In-With-X (wallet-authenticated repeat access)
    ├── OfferReceipt         # Signed offers and receipts (EIP-712 + JWS)
    └── Bazaar, gas sponsoring extensions
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
                ├─ Inline local verification (optional :local_verification, exact-EVM)
                │     rejection → 402; infrastructure failure → 500
                │
                ├─ Facilitator.verify + signature-bound replay claim (:claim_order)
                │     invalid or replayed payment → 402; server/facilitator fault → 500
                │
                ├─ Assign payload/requirements → protected handler
                │     handler status >= 400 → skip settlement
                │
                └─ Successful handler → Facilitator.settle before send
                      settlement_pending → exactly one retried settle
                      success → PAYMENT-RESPONSE + original resource response
                      payment failure → 402; server/facilitator fault → 500
```

## Optional Dependencies

| Dep | When Required |
|-----|--------------|
| `finch` | HTTP calls to facilitator and RPC endpoints (`X402.Facilitator`, `X402.RPC`) |
| `plug` | Phoenix/Plug middleware (`X402.Plug.PaymentGate`, `X402.Plug.Facilitator`) |
| `ex_secp256k1` | EVM signing and signature recovery (client signing, SIWX, facilitator engine) |
| `ex_keccak` | Keccak hashing (EIP-712, local verification, settlement transactions) |
| `redix` | Redis payment-identifier cache adapter (`RedisCache`) |

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
[:x402, :facilitator, :verify | :settle, :start | :stop | :exception]
[:x402, :facilitator_engine, :verify | :settle]
[:x402, :plug, :payment_required | :payment_verified | :payment_rejected]
[:x402, :client, :select | :sign | :build | :request]
[:x402, :verify, :evm | :svm]
[:x402, :rpc, :request]
[:x402, :payment_required | :payment_signature | :payment_response, ...]
```

The full event list lives in `X402.Telemetry`.

## Payment lifecycle

- The Plug validates a v2 payload and verifies payment before invoking the handler.
- Replay claims use a signature-covered key per scheme family (EIP-3009
  `from` + nonce, Permit2 owner + canonicalized nonce, SVM message hash;
  raw-header hash for unknown schemes). The `paymentId` extension is decoded
  and surfaced but is deliberately **not** the dedup key — it is
  client-chosen and not covered by the payment signature.
- Settlement is deferred until a successful handler response is ready to
  send; a `settlement_pending` settle is retried exactly once, and engines
  reconcile the retry against the already-broadcast transaction.
- `"upto"` routes may replace the advertised maximum with the actual metered
  settlement amount through `put_settlement_amount/2`.
- Missing facilitator decision fields fail closed, and internal/facilitator
  failures are separated from client and payment failures by HTTP status.
- Only authorization-flow timing is supported; upfront and escrow requirements
  are rejected during route compilation.
