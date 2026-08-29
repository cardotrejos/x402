# Plug/Phoenix Integration

The `X402.Plug.PaymentGate` module provides drop-in payment gating for any
Plug-compatible application, including Phoenix. It implements the
[x402 v2 HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md).

## Configuration

The plug accepts these options (validated via `NimbleOptions`):

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `:facilitator` | `GenServer.server()` | no | `X402.Facilitator` | Facilitator process name or pid for verify/settle calls |
| `:hooks` | `module()` | no | `X402.Hooks.Default` | Lifecycle hook module implementing `X402.Hooks` |
| `:payment_identifier_cache` | `atom() \| pid() \| {module, cache}` | no | `nil` | Replay-protection cache: an `ETSCache` server, or an adapter tuple whose module implements `X402.Extensions.PaymentIdentifier.Cache` (strongly recommended — see "Replay Protection") |
| `:claim_order` | `:after_verify \| :before_verify` | no | `:after_verify` | When the replay claim is taken relative to facilitator verification (see "Replay Protection") |
| `:routes` | `[map()]` | **yes** | — | Route gate definitions (see below) |
| `:schemes` | `[module()]` | no | `[]` | Additional `X402.Scheme` modules for custom schemes — see the [Custom Payment Schemes](custom-schemes.html) guide |
| `:local_prechecks` | `boolean()` | no | `true` | Cheap scheme-dispatched checks before the facilitator call; certain mismatches answer 402 without a round-trip |
| `:local_verification` | `atom() \| keyword()` | no | `nil` | Inline cryptographic verification of exact-EVM payments before the facilitator verify (see "Local Verification") |
| `:paywall` | `module()` | no | `nil` | Browser paywall renderer implementing `X402.Paywall` — see the [Browser Paywall](paywall.html) guide |

> **Important:** When `:payment_identifier_cache` is not configured, the plug
> emits a runtime warning. Without it, concurrent identical requests can
> double-settle the same payment proof.

## Route Definitions

Routes are a list of maps. Each map describes one gated endpoint:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  routes: [
    %{
      method: :get,
      path: "/api/data",
      price: "10000",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWalletAddress"
    }
  ]
```

### Route options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `:method` | `atom()` | **yes** | HTTP method (`:get`, `:post`, `:put`, `:delete`, `:patch`, `:head`, `:options`, `:trace`, or `:any` for all) |
| `:path` | `String.t()` | **yes** | Route path. Exact matches (`/api/data`) or glob patterns (`/api/*`) |
| `:accepts` | `[map()]` | no | Multiple payment options (see "Multiple Accepts" below) |
| `:scheme` | `String.t()` | no | `"exact"` (default), `"upto"`, or the scheme name of a module passed in the plug's `:schemes` option — see the [Custom Payment Schemes](custom-schemes.html) guide |
| `:price` | `String.t()` | conditionally | Payment amount in atomic token units. Required when `:accepts` is empty |
| `:network` | `String.t()` | conditionally | CAIP-2 network identifier (e.g. `"eip155:8453"`) |
| `:asset` | `String.t()` | conditionally | Token contract address |
| `:pay_to` | `String.t()` | conditionally | Recipient wallet address |
| `:description` | `String.t()` | no | Resource description (default: `"Payment required"`) |
| `:mime_type` | `String.t()` | no | Resource MIME type (default: `"application/json"`) |
| `:service_name` | `String.t()` | no | Service name for display (max 32 chars recommended) |
| `:tags` | `[String.t()]` | no | Resource tags (max 5 recommended) |
| `:icon_url` | `String.t()` | no | Absolute URL to a service icon |
| `:max_timeout_seconds` | `pos_integer()` | no | Max payment completion time (default: `60`) |
| `:extra` | `map()` | no | Scheme-specific extra fields |
| `:extensions` | `map()` | no | Protocol extensions advertised in `PAYMENT-REQUIRED` |

When `:accepts` is empty (the default), a single payment option is built from
the top-level `:scheme`, `:price`, `:network`, `:asset`, and `:pay_to` fields.
Amounts are strings in atomic token units; for six-decimal USDC, `"10000"`
represents `0.01` USDC.

The Plug currently implements the post-handler `authorization` flow. It rejects
requirements whose `extra.paymentFlow` is `"upfront"` or `"escrow"` because
those flows require different handler and cancellation semantics.

### Multiple Accepts

For routes that accept multiple payment options (different schemes, networks, or
amounts), use the `:accepts` list:

```elixir
%{
  method: :post,
  path: "/api/generate",
  accepts: [
    %{
      scheme: "exact",
      price: "10000",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWallet"
    },
    %{
      scheme: "exact",
      price: "5000",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      pay_to: "YourSolanaAddress",
      extra: %{"feePayer" => "YourFacilitatorFeePayer"}
    }
  ]
}
```

The client's `PaymentPayload.accepted` is matched against the complete
server-advertised requirement. Every core field, including
`maxTimeoutSeconds`, must be equal. Client metadata may be added under
`accepted.extra`, but it cannot remove or mutate fields advertised by the
server. Echoed protocol extensions are validated with the same fail-closed
rule.

Exact-SVM options require `extra.feePayer` — the facilitator-managed
sponsor account that co-signs and pays fees at settlement. A facilitator's
`GET /supported` response advertises its fee payer in each SVM kind's
`extra.feePayer`; copy it into the route (or build routes from that
response).

### Metered `"upto"` settlement

For an `"upto"` option, `price` is the maximum authorization. The maximum is
sent to `/verify`; the protected handler can set the actual charge before
returning its response:

```elixir
def create(conn, params) do
  result = generate(params)

  {:ok, conn} =
    X402.Plug.PaymentGate.put_settlement_amount(conn, billable_atomic_units(result))

  json(conn, %{result: result})
end
```

The amount may be a non-negative integer or a digit-only string. It is written
to `PaymentRequirements.amount` for `/settle` and must not exceed the
advertised maximum. The maximum is settled when no override is supplied.

## Lifecycle Hooks

Hooks let you intercept the payment flow for logging, custom validation, or
post-settlement logic. Implement the `X402.Hooks` behaviour:

```elixir
defmodule MyApp.PaymentHooks do
  @behaviour X402.Hooks

  @impl true
  def before_verify(context, _metadata) do
    IO.inspect(context.payload, label: "Incoming payment")
    {:cont, context}
  end

  @impl true
  def after_verify(context, _metadata) do
    {:cont, context}
  end

  @impl true
  def after_settle(context, _metadata) do
    # Post-settlement: update DB, send receipt, etc.
    {:cont, context}
  end

  @impl true
  def before_settle(context, _metadata), do: {:cont, context}

  @impl true
  def on_verify_failure(context, _metadata), do: {:cont, context}

  @impl true
  def on_settle_failure(context, _metadata), do: {:cont, context}
end
```

Pass the module to the plug:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  hooks: MyApp.PaymentHooks,
  routes: [...]
```

## Local Verification

Facilitator verification is a delegation: the gate trusts the facilitator's
verdict. The `local_verification:` option narrows that gap by running
`X402.Verify.EVM` inline, before the facilitator verify, on every exact-EVM
payment (`"exact"` scheme, `eip155:*` network). It accepts a bare level
(`:structural`, `:signature`, or `:full`) or a keyword list with `:level`,
`:rpc` (required for `:full`), and the other `X402.Verify.EVM.verify/3`
options:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  local_verification: :signature,
  routes: [...]
```

Rejections answer 402 carrying the canonical `invalidReason` string, exactly
like a facilitator rejection; infrastructure failures (missing crypto
dependencies, RPC errors, chain-id mismatches) fail closed with 500; other
scheme/network kinds skip it silently, and the facilitator remains the
authority for every payment either way. See the
[Local Payment Verification](local-verification.html) guide for the levels,
their capability requirements, and ERC-6492 counterfactual handling.

## Replay Protection

A valid payment proof can be presented many times — concurrently to the same
server, or replayed after the client observed a response. Configure a cache
so the gate atomically claims each proof before the protected handler runs:

```elixir
# In your supervision tree
children = [
  {X402.Extensions.PaymentIdentifier.ETSCache, name: MyApp.PaymentCache},
  # ... other children
]

# In your plug config
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  payment_identifier_cache: MyApp.PaymentCache,
  routes: [...]
```

### Canonical replay keys

The claim key is derived from the payment proof itself. For the built-in
schemes the gate derives a canonical identity from the fields the payment's
signature covers, so re-encoding the same signed authorization (JSON key
order, whitespace, Base64 variant) cannot mint a fresh key:

| Kind | Key derives from |
|---|---|
| `"exact"` on `eip155:*` | the EIP-3009 authorization's `from` + `nonce` |
| `"upto"` on `eip155:*` | the Permit2 owner (`from`) + the nonce canonicalized to its 32-byte `uint256` encoding, so the equivalent JSON forms `1`, `"1"`, and `"01"` mint the same key |
| `"exact"` on `solana:*` | the SHA-256 of the transaction's **signed message bytes** — not the wire bytes, whose fee-payer signature slot is mutable (a co-signed or stripped slot must not mint a fresh key) |
| everything else | the SHA-256 of the raw `PAYMENT-SIGNATURE` header |

Every family's keys carry a distinct prefix, so keys from different families
can never collide. The consequence of the fallback row: re-encoded
duplicates of the same signed proof **are** caught for the built-in schemes,
while custom schemes without a canonical derivation catch byte-identical
replays only.

The key derives **only** from signature-covered content — never from
unsigned client-controlled fields, and in particular never from the payment
identifier extension's `paymentId` (see "Payment Identifiers" below). A
replayer could vary an unsigned field to mint a fresh key and bypass
deduplication, or squat another payment's id to deny it service.

### Claim lifecycle

The claim is an atomic `put_new` through the
`X402.Extensions.PaymentIdentifier.Cache` behaviour. A duplicate claim
rejects the request with 402 (`"payment already processed"`). The claim is
released when the protected handler responds with a status >= 400 or
settlement fails — so a client may retry a payment whose resource was never
delivered — and retained after a successful settlement.

The `:claim_order` option controls when the claim is taken relative to
facilitator verification:

- `:after_verify` (default) — verify first, then claim. A replayed proof can
  never strand a claim through verification, but **every** replayed request
  pays a full facilitator verify round-trip before it is rejected, so a
  replay storm translates directly into facilitator load.
- `:before_verify` — claim first, rejecting duplicates locally without any
  facilitator call, which sheds replay-storm load; the claim is released
  when verification fails for any reason. The trade-off: a node that
  crashes between claiming and releasing strands the claim until the cache
  TTL expires, so a legitimate retry of that same payment is rejected with
  402 until then.

### Cache adapters

The ETS cache is per-node: in a clustered deployment each node keeps its own
table, so a replayed proof routed to two nodes is served once per node. For
clusters, use the Redis adapter (requires the optional `redix` dependency;
you supervise the connection):

```elixir
# In your supervision tree
children = [
  {Redix, {System.fetch_env!("REDIS_URL"), name: MyApp.Redis}},
  # ... other children
]

# In your plug config
{:ok, cache} = X402.Extensions.PaymentIdentifier.RedisCache.new(conn: MyApp.Redis)

plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  payment_identifier_cache: {X402.Extensions.PaymentIdentifier.RedisCache, cache},
  routes: [...]
```

The claim is a single `SET NX PX` command, so it stays atomic across all
nodes; Redis or connection errors fail closed (the protected handler does not
run). Configure the Redis server with `maxmemory-policy noeviction` so live
claims are never evicted.

### Payment Identifiers

Separate from replay protection, a client may echo the payment identifier
extension under `extensions["paymentIdentifier"]` in its payment payload.
The gate decodes it — both the bare form and the `%{"info" => ...}` envelope
(`X402.Extensions.PaymentIdentifier`) — and rejects a malformed one (bad
Base64, invalid JSON, missing `paymentId`) with 400. A valid identifier is
surfaced for correlation:

- `conn.assigns[:x402_payment_id]` in the protected handler,
- the settlement context the gate carries into its before-send settlement,
- the `[:x402, :plug, :payment_verified]` telemetry metadata, as
  `:payment_id`.

It is deliberately **not** the deduplication key: `paymentId` is
client-controlled and covered by no signature, so building replay protection
on it would let a replayer mint fresh keys at will. The replay key comes
from the signed content above; the payment identifier is for tracing a
payment through your logs and the client's.

## Conn Assigns

After successful verification, the Plug assigns these to the connection before
the protected handler runs:

| Assign | Value |
|--------|-------|
| `:x402_payment_payload` | The decoded `PaymentPayload` map |
| `:x402_payment_requirements` | The matched `PaymentRequirements` map |
| `:x402_payment_id` | The client's echoed payment identifier (only set when the extension was present) |

Your controller can access these:

```elixir
def show(conn, _params) do
  payload = conn.assigns.x402_payment_payload
  requirements = conn.assigns.x402_payment_requirements

  # The payer's wallet address, transaction hash, etc.
  # are available in the payload

  json(conn, %{data: "premium content"})
end
```

## Payment Response

Settlement runs in a `before_send` callback only when the protected handler has
produced a response below HTTP 400. On successful settlement, a
`PAYMENT-RESPONSE` header is attached to the response. On payment failure, the
response includes both
`PAYMENT-REQUIRED` (so the client can retry) and `PAYMENT-RESPONSE` (with
the error reason).

### Settlement retries

A settle response of `success: false` with `errorReason:
"settlement_pending"` **and** a transaction hash means the facilitator
broadcast the transaction but could not confirm it within its wait window.
The gate retries such a settle exactly once, with the identical payload —
mirroring the reference SDKs' `settleWithPendingRetry` — so a facilitator
with a pending-settlement store reconciles against the already-broadcast
transaction instead of broadcasting twice (see
[Run Your Own Facilitator](facilitator.html)). A second pending verdict, or
any other failure, follows the normal failure path: the replay claim is
released and the response carries the failure headers described above.

## Signed Offers and Receipts

The [offer-and-receipt extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md)
lets a resource server cryptographically commit to the terms it advertises
(**signed offers**) and confirm delivery after payment (**signed
receipts**) — evidence for disputes, audits, and reputation systems.
`X402.Extensions.OfferReceipt` implements both artifact formats: EIP-712
(signed through `X402.Signer`, verified by signer recovery) and compact JWS
(`ES256K`/`EdDSA` via OTP `:crypto`).

Issue offers for the terms a route advertises and attach them through the
route's `extensions:` option (clients that ignore the extension are
unaffected):

```elixir
alias X402.Extensions.OfferReceipt

{:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("OFFER_SIGNING_KEY"))

{:ok, payload} =
  OfferReceipt.offer_payload(
    resource_url: "https://api.example.com/premium-data",
    scheme: "exact",
    network: "eip155:84532",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    amount: "10000"
  )

{:ok, offer} = OfferReceipt.sign_offer(payload, signer, accept_index: 0)

plug X402.Plug.PaymentGate,
  routes: [
    %{
      method: :get,
      path: "/premium-data",
      price: "10000",
      network: "eip155:84532",
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      extensions: %{"offer-receipt" => OfferReceipt.build_extension([offer])}
    }
  ]
```

Because route configuration is static, offers built this way should omit
`valid_until` (or set it generously); build the payment-required response
yourself with `X402.PaymentRequired.encode/1` when you want short-lived,
per-request offers.

After a successful settlement, issue a receipt from your handler (the payer
is available in the payment payload assign) and return it to the client —
for example in the response body, or from your settlement pipeline as
`extensions["offer-receipt"]` of a settlement response you construct:

```elixir
{:ok, receipt_payload} =
  OfferReceipt.receipt_payload(
    resource_url: "https://api.example.com/premium-data",
    network: "eip155:84532",
    payer: payer_address
  )

{:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload, signer)
extension = OfferReceipt.build_receipt_extension(receipt)
```

Clients extract and verify the artifacts — and must apply an authorization
policy for the signer (spec §4.5.1); the simplest is requiring the offer's
`payTo` key:

```elixir
{:ok, [offer]} = OfferReceipt.fetch_offers(payment_required)
{:ok, payload} = OfferReceipt.extract_payload(offer)

{:ok, %{signer: signer}} =
  OfferReceipt.verify_offer(offer, expected_signer: payload["payTo"])
```

JWS verification takes the resolved public key explicitly
(`verify_offer(offer, public_key: key)`) — the library carries the `kid`
DID URL but never resolves it over the network.

## HTTP Status Codes

The plug follows the x402 v2 HTTP transport status mapping:

| Status | When |
|--------|------|
| **402** | Payment required (no `PAYMENT-SIGNATURE` header), no matching requirements, a duplicate payment proof, a local pre-check or local-verification rejection, or facilitator verification/settlement failure |
| **400** | Malformed `PAYMENT-SIGNATURE` header, invalid Base64, invalid JSON, payload too large, wrong `x402Version`, a scheme payload validation failure, or a malformed payment identifier extension |
| **500** | Facilitator transport failure, malformed facilitator response, local-verification infrastructure failure (missing dependency, RPC error, chain-id mismatch), invalid server-provided settlement amount, or response-encoding failure |

## Telemetry Events

The plug emits these telemetry events:

| Event | When |
|-------|------|
| `[:x402, :plug, :pass_through]` | Route did not match — request passes through unguarded |
| `[:x402, :plug, :payment_required]` | 402 returned — no `PAYMENT-SIGNATURE` header |
| `[:x402, :plug, :payment_verified]` | Payment successfully verified and settled |
| `[:x402, :plug, :payment_rejected]` | Payment rejected (invalid payload, no match, verification failed, etc.) |

Metadata always includes `:method` and `:path`. Every event except
`:pass_through` adds `:route`; `:payment_rejected` adds `:reason`; and
`:payment_verified` adds `:payment_id` when the client echoed a payment
identifier extension.

## Full Example

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :paid_api do
    plug X402.Plug.PaymentGate,
      facilitator: MyApp.Facilitator,
      hooks: MyApp.PaymentHooks,
      payment_identifier_cache: MyApp.PaymentCache,
      local_verification: :signature,
      routes: [
        %{
          method: :get,
          path: "/api/weather",
          price: "5000",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          pay_to: "0xYourWalletAddress",
          description: "Weather data API"
        },
        %{
          method: :post,
          path: "/api/generate",
          price: "50000",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          pay_to: "0xYourWalletAddress",
          description: "AI generation endpoint"
        },
        %{
          method: :any,
          path: "/api/premium/*",
          accepts: [
            %{
              scheme: "exact",
              price: "10000",
              network: "eip155:8453",
              asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
              pay_to: "0xYourWalletAddress"
            },
            %{
              scheme: "upto",
              price: "1000000",
              network: "eip155:8453",
              asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
              pay_to: "0xYourWalletAddress"
            }
          ],
          description: "Premium tier — flexible pricing",
          service_name: "MyApp Premium",
          tags: ["premium", "ai"]
        }
      ]
  end

  scope "/api" do
    pipe_through [:paid_api]
    get "/weather", WeatherController, :show
    post "/generate", GenerateController, :create
    get "/premium/*path", PremiumController, :show
  end
end
```
