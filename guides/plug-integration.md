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
| `:payment_identifier_cache` | `atom() \| pid()` | no | `nil` | `ETSCache` server for idempotency (strongly recommended) |
| `:routes` | `[map()]` | **yes** | — | Route gate definitions (see below) |

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
      price: "0.01",
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
| `:scheme` | `String.t()` | no | `"exact"` (default) or `"upto"` |
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
      price: "0.01",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWallet"
    },
    %{
      scheme: "exact",
      price: "0.005",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      pay_to: "YourSolanaAddress"
    }
  ]
}
```

The client's `PaymentPayload.accepted` is matched against the server's
`accepts` by equality on `scheme`, `network`, `amount`, `asset`, and `payTo`.

## Lifecycle Hooks

Hooks let you intercept the payment flow for logging, custom validation, or
post-settlement logic. Implement the `X402.Hooks` behaviour:

```elixir
defmodule MyApp.PaymentHooks do
  @behaviour X402.Hooks

  @impl true
  def before_verify(context, _metadata) do
    IO.inspect(context.payment, label: "Incoming payment")
    {:ok, context}
  end

  @impl true
  def after_verify(context, _metadata) do
    {:ok, context}
  end

  @impl true
  def after_settle(context, _metadata) do
    # Post-settlement: update DB, send receipt, etc.
    {:ok, context}
  end

  @impl true
  def before_settle(context, _metadata), do: {:ok, context}

  @impl true
  def on_verify_failure(context, _metadata), do: {:ok, context}

  @impl true
  def on_settle_failure(context, _metadata), do: {:ok, context}
end
```

Pass the module to the plug:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  hooks: MyApp.PaymentHooks,
  routes: [...]
```

## Idempotency (Payment Identifier Cache)

To prevent double-settlement of the same payment proof from concurrent
requests, configure an ETS cache:

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

The plug performs an atomic `put_new` claim on the payment proof hash before
settlement. If the claim fails (duplicate), the request is rejected with
`"payment already processed"`.

## Conn Assigns

After successful verification and settlement, the plug assigns these to the
connection:

| Assign | Value |
|--------|-------|
| `:x402_payment_payload` | The decoded `PaymentPayload` map |
| `:x402_payment_requirements` | The matched `PaymentRequirements` map |

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

On successful settlement, a `PAYMENT-RESPONSE` header is attached to the
response. On settlement failure, the response includes both
`PAYMENT-REQUIRED` (so the client can retry) and `PAYMENT-RESPONSE` (with
the error reason).

## HTTP Status Codes

The plug follows the x402 v2 HTTP transport status mapping:

| Status | When |
|--------|------|
| **402** | Payment required (no `PAYMENT-SIGNATURE` header), no matching requirements, or payment verification/settlement failed |
| **400** | Malformed `PAYMENT-SIGNATURE` header, invalid Base64, invalid JSON, payload too large, or wrong `x402Version` |

## Telemetry Events

The plug emits these telemetry events:

| Event | When |
|-------|------|
| `[:x402, :plug, :pass_through]` | Route did not match — request passes through unguarded |
| `[:x402, :plug, :payment_required]` | 402 returned — no `PAYMENT-SIGNATURE` header |
| `[:x402, :plug, :payment_verified]` | Payment successfully verified and settled |
| `[:x402, :plug, :payment_rejected]` | Payment rejected (invalid payload, no match, verification failed, etc.) |

Metadata includes `%{method: atom(), path: String.t()}` and for
`:payment_required` / `:payment_rejected` also `:route` and `:reason`.

## Full Example

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :paid_api do
    plug X402.Plug.PaymentGate,
      facilitator: MyApp.Facilitator,
      hooks: MyApp.PaymentHooks,
      payment_identifier_cache: MyApp.PaymentCache,
      routes: [
        %{
          method: :get,
          path: "/api/weather",
          price: "0.005",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          pay_to: "0xYourWalletAddress",
          description: "Weather data API"
        },
        %{
          method: :post,
          path: "/api/generate",
          price: "0.05",
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
              price: "0.01",
              network: "eip155:8453",
              asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
              pay_to: "0xYourWalletAddress"
            },
            %{
              scheme: "upto",
              price: "1.00",
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
