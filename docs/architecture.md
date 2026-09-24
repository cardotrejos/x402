# Architecture

The x402 Elixir SDK is an Elixir library implementing the x402 HTTP
payment protocol (v2). It ships as a Hex package with no web server, database,
or external service required by default. Behaviours allow applications to
replace transports, signing, payment schemes, and storage.

## Design principles

- **Behaviours over config**: extensibility via `@callback` (`X402.Scheme`,
  `X402.Signer`, `X402.Hooks`, `X402.Extension`, `X402.Paywall`, storage and
  cache adapters), not application environment.
- **Flat module naming**: `X402.Wallet`, not `X402.Utils.Validators.Wallet`.
- **Tagged tuples, no exceptions for expected failures**: fallible functions
  return `{:ok, result} | {:error, reason}`. Option validation may raise only
  where the contract explicitly uses `NimbleOptions.validate!/2` (for example
  Plug initialization).
- **Minimal required deps**: `jason`, `nimble_options`, and `telemetry`.
  Finch, Plug, `ex_secp256k1`, `ex_keccak`, Redix, and `telemetry_metrics` are optional and guarded
  by compile-time availability checks; the package must compile with
  `mix compile --no-optional-deps`.
- **Processes only where state lives**: facilitator clients, spend budgets,
  nonce managers, cache adapters, and ETS table ownership use long-lived
  processes. Wire codecs, signing, and validation are function-based.

## Module map

### Wire format

| Module | Role |
|--------|------|
| `X402` | Top-level convenience API delegating to the header modules |
| `X402.PaymentRequired` | Encode/decode the `PAYMENT-REQUIRED` header |
| `X402.PaymentRequirements` | Validate and match v2 accepted requirements |
| `X402.PaymentSignature` | Decode/validate the `PAYMENT-SIGNATURE` header (PaymentPayload) |
| `X402.PaymentResponse` | Encode/decode the `PAYMENT-RESPONSE` header (SettleResponse) |
| `X402.ExtensionResponses` | Encode/decode the `EXTENSION-RESPONSES` facilitator sidechannel |
| `X402.Wallet` | EVM and Solana address validation |
| `X402.Utils`, `X402.Base58`, `X402.Behaviour` | Shared helpers (decimal parsing, Base58, callback introspection) |

### Schemes and signing

| Module | Role |
|--------|------|
| `X402.Scheme` | Behaviour for pluggable payment schemes |
| `X402.Scheme.Registry` | Resolves `(scheme, network)` pairs to scheme modules |
| `X402.Scheme.ExactEVM`, `X402.Scheme.UptoEVM` | Built-in `exact` / `upto` schemes for `eip155:*` |
| `X402.Scheme.ExactSVM` | Built-in `exact` scheme for `solana:*` |
| `X402.Scheme.EVM` | Shared local pre-checks for EVM authorization payloads |
| `X402.Signer` | Behaviour for client-side signers |
| `X402.Signer.LocalKey`, `X402.Signer.SolanaKey` | In-memory secp256k1 and Ed25519 signers |
| `X402.EIP3009` | `TransferWithAuthorization` building and EIP-712 signing |
| `X402.Permit2` | `PermitWitnessTransferFrom` building, signing, and proxy calldata |

ERC-7710 delegated transfers remain unsupported. Unknown transfer methods
fail closed rather than falling back to another authorization.

### Local verification

| Module | Role |
|--------|------|
| `X402.Verify.EVM` | Local verify checklist for EVM `exact` (EIP-3009, Permit2) and `upto`: EIP-712 recovery, ERC-1271/6492, balance, simulation |
| `X402.Verify.SVM` | Local verify checklist for SVM `exact`: Ed25519 signatures, fee-payer isolation, instruction whitelist |

### Facilitator

| Module | Role |
|--------|------|
| `X402.Facilitator` | Client for a remote facilitator API: verify, settle, supported, discovery |
| `X402.Facilitator.HTTP` | HTTP transport for facilitator requests (retries, timeouts) |
| `X402.Facilitator.Failover` | Endpoint selection and conservative fallback policy |
| `X402.Facilitator.Auth`, `X402.Facilitator.Auth.CDP` | Request-auth behaviour and the Coinbase Developer Platform JWT implementation |
| `X402.Facilitator.Error` | Structured facilitator client error |
| `X402.Facilitator.Engine` | Facilitator-role engine: verify and settle EVM payments yourself |
| `X402.Facilitator.SVMEngine` | Facilitator-role engine for Solana `exact` payments |
| `X402.Facilitator.NonceManager` | Serializes fee-payer transaction nonces across concurrent settlements |
| `X402.Facilitator.PendingSettlementStore`, `.ETS` | Behaviour and ETS adapter for reconciling `settlement_pending` retries |
| `X402.Plug.Facilitator` | Plug exposing one or more engines as a facilitator HTTP API |

### Resource server

| Module | Role |
|--------|------|
| `X402.Plug.PaymentGate` | Plug middleware gating routes behind payment verification and deferred settlement |
| `X402.Hooks`, `X402.Hooks.Default` | Lifecycle hooks around verify and settle |
| `X402.Hooks.Context`, `X402.Hooks.RequestContext` | State passed between hook callbacks |
| `X402.Extension` | Behaviour for extension adapters run by `PaymentGate` |
| `X402.Paywall`, `X402.Paywall.Default` | Browser-facing HTML 402 page behaviour and default renderer |
| `X402.RateLimiter`, `.ETS` | Verified-request rate-limit behaviour and per-node fixed-window store |

### Payer client

| Module | Role |
|--------|------|
| `X402.Client` | Transport-agnostic payer: select requirements, sign, build headers |
| `X402.Client.Finch` | Finch-backed payer with the 402 → sign → retry flow |
| `X402.Client.Hooks`, `.Hooks.Context`, `.Hooks.Default` | Lifecycle hooks around payment creation |
| `X402.Client.Policy` | Ready-made requirement selection policies |
| `X402.Client.Budget` | Session spend budget shared by payer clients |
| `X402.Client.SIWX` | Client side of `sign-in-with-x`: answering a challenge |

### MCP transport

| Module | Role |
|--------|------|
| `X402.MCP` | Payment flows over the Model Context Protocol (`_meta` plumbing) |
| `X402.MCP.Server` | Gates a tool handler behind payment |
| `X402.MCP.Client` | Pays for tool calls automatically |

### Extensions

| Module | Role |
|--------|------|
| `X402.Extensions.PaymentIdentifier` | Client-generated idempotency ids |
| `X402.Extensions.PaymentIdentifier.Adapter` | `X402.Extension` adapter advertising `payment-identifier` |
| `X402.Extensions.PaymentIdentifier.Cache` | Behaviour for idempotency caches |
| `X402.Extensions.PaymentIdentifier.ETSCache` | ETS cache adapter |
| `X402.Extensions.PaymentIdentifier.RedisCache`, `.Command` | Redis cache adapter and its command behaviour |
| `X402.Extensions.SIWX` | CAIP-122 `sign-in-with-x` wallet authentication |
| `X402.Extensions.SIWX.Server` | Challenge issuance, proof verification, access records |
| `X402.Extensions.SIWX.Challenge`, `.Message` | Challenge advertisements and CAIP-122 message text |
| `X402.Extensions.SIWX.Verifier`, `.Verifier.Default`, `.Verifier.Ed25519` | Signature verification behaviour with EVM and Solana implementations |
| `X402.Extensions.SIWX.Storage`, `.ETSStorage` | Access-record storage behaviour and ETS adapter |
| `X402.Extensions.OfferReceipt` | Signed offers and signed receipts |
| `X402.Extensions.OfferReceipt.JWS` | Compact JWS signing and verification |
| `X402.Extensions.Bazaar`, `.Metadata` | Bazaar discovery extension builder, discovery client, and metadata validation |
| `X402.Extensions.BuilderCode`, `.Adapter` | ERC-8021 on-chain attribution codes and their adapter |
| `X402.Extensions.EIP2612GasSponsoring` | Builds, signs, and validates `eip2612GasSponsoring` |
| `X402.Extensions.ERC20ApprovalGasSponsoring` | Builds and validates `erc20ApprovalGasSponsoring` |
| `X402.Extensions.AuthHints`, `.Adapter` | Authentication-path discovery and advertisement |
| `X402.Extensions.HTTPMessageSignatures`, `.Adapter` | HTTP-message-signature capability declarations |

### HTTP authentication primitives

| Module | Role |
|--------|------|
| `X402.HTTPSignature` | Bounded RFC 9421 signing and verification profile |
| `X402.HTTPSignature.Key` | Ed25519, P-256, RSA-PSS-SHA512, and public JWK handling |
| `X402.HTTPSignature.StructuredField` | Signature header structured-field codec |
| `X402.Plug.HTTPSignatureDirectory` | Optional public-key directory with signed responses and key rotation |

Authentication declarations do not enforce access. Applications own credential
validation, trusted key discovery, nonce replay storage, body-digest checks, and
proxy-aware URI reconstruction. Discovery URLs are untrusted inputs, not
permission to fetch credentials or remote keys automatically.

### Infrastructure

| Module | Role |
|--------|------|
| `X402.RPC` | JSON-RPC transport over optional Finch |
| `X402.Solana`, `X402.Solana.RPC`, `X402.Solana.Transaction` | Program IDs, PDA/ATA derivation, JSON-RPC calls, v0 transaction building |
| `X402.EIP712` | Generic EIP-712 hashing primitives |
| `X402.ERC6492` | ERC-6492 signature wrapper parsing and building |
| `X402.RLP`, `X402.Transaction` | RLP and EIP-1559 typed-transaction encoding for settlement |
| `X402.Telemetry` | Telemetry event definitions and emission helpers |
| `X402.Telemetry.Metrics`, `.Stats` | Optional metric definitions and local ETS statistics |

## Request flow through `X402.Plug.PaymentGate`

Parameter routes match once-decoded Plug segments, not a rejoined path. An
encoded slash remains inside one capture and cannot bypass a paid route.
SIWX access grants bind the HTTP method and full URL, including origin and
query, before the handler runs. The flow below covers requests requiring payment.

```
Incoming HTTP request
        │
        ├─ No PAYMENT-SIGNATURE → 402 + PAYMENT-REQUIRED (or HTML paywall for browsers)
        │
        └─ PAYMENT-SIGNATURE present
                ├─ Decode PaymentPayload (x402Version must be 2)
                │     malformed / wrong version → 400 + PAYMENT-REQUIRED
                ├─ Match payload.accepted against route requirements + extension echoes
                │     no match → 402 + PAYMENT-REQUIRED
                ├─ Optional inline local verification (X402.Verify.*)
                │     rejection → 402; infrastructure failure → 500
                ├─ Facilitator.verify + signature-bound replay claim
                │     invalid or replayed → 402; server/facilitator fault → 500
                ├─ Optional verified-payer/IP rate limit
                │     exhausted → 429 + Retry-After, no handler or settlement
                ├─ Assign payload/requirements → protected handler
                │     handler status >= 400 → skip settlement
                └─ Successful handler → Facilitator.settle before send
                      settlement_pending → exactly one retried settle
                      success → PAYMENT-RESPONSE + resource response
                      payment failure → 402; server/facilitator fault → 500
```

Replay claims use a signature-covered key per scheme family (EIP-3009 `from`
+ nonce, Permit2 owner + canonicalized nonce, SVM message hash; raw-header hash
for unknown schemes). The `payment-identifier` extension is surfaced but is
deliberately not the dedup key: it is client-chosen and not covered by the
payment signature. `"upto"` routes may replace the advertised maximum with the
metered settlement amount. Missing facilitator decision fields fail closed.
For built-in EVM payments, verification, settlement, payer reporting, and
pending-settlement identity select authorization from the matched requirements.
Unsigned alternate authorization objects never override that selection.

## Operational boundaries

Rate limits run after payment verification, before resource execution and
settlement. Payer keys prefer the facilitator's verified payer; fallback
extraction is bound to the verified scheme, network, and transfer method.
Unauthenticated claimed payer fields never select another wallet's quota.
The default ETS limiter is per-node, defaults to allowing requests on store
failure, and does not cover MCP calls or payment-exempt requests.

Facilitator failover retries read and verification failures according to the
endpoint policy. With fallbacks configured, settlement makes one HTTP attempt
per endpoint and switches providers only after a classified non-delivery
failure. Timeouts, closed connections, TLS alerts, and server errors remain
ambiguous and must not trigger another provider's settlement.

Telemetry metrics and statistics are optional observability surfaces, not a
Phoenix dashboard or a durable accounting ledger.

## Optional dependencies

| Dep | Required for |
|-----|--------------|
| `finch` | HTTP calls to facilitators and RPC endpoints (`X402.Facilitator`, `X402.RPC`, `X402.Client.Finch`) |
| `plug` | `X402.Plug.PaymentGate`, `X402.Plug.Facilitator` |
| `ex_secp256k1` | EVM signing and recovery (signers, SIWX, local verification, engine) |
| `ex_keccak` | Keccak hashing (EIP-712, local verification, settlement transactions) |
| `redix` | `X402.Extensions.PaymentIdentifier.RedisCache` |
| `telemetry_metrics` | `X402.Telemetry.Metrics` definitions for application-owned reporters |

## Data formats (x402 v2)

All headers carry Base64-encoded JSON:

- `PAYMENT-REQUIRED`: `{x402Version: 2, error?, resource, accepts[], extensions?}`;
  each accept is `{scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra}`.
- `PAYMENT-SIGNATURE`: `{x402Version: 2, resource?, accepted, payload, extensions?}`;
  `accepted` is a full requirements object that must match a server accept.
- `PAYMENT-RESPONSE`: `{success, transaction, network, payer?, amount?, errorReason?, extensions?}`.

Networks use CAIP-2 identifiers, e.g. `"eip155:8453"` (Base) and
`"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"` (Solana mainnet).

## Telemetry

Events are `[:x402, module, operation]` with a `:status` metadata key; the
module and operation atoms are typed in `X402.Telemetry`, which is the
authoritative list.
