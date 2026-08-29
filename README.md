# X402

[![Hex.pm](https://img.shields.io/hexpm/v/x402.svg)](https://hex.pm/packages/x402)
[![Downloads](https://img.shields.io/hexpm/dt/x402.svg)](https://hex.pm/packages/x402)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/x402)
[![CI](https://github.com/cardotrejos/x402/actions/workflows/ci.yml/badge.svg)](https://github.com/cardotrejos/x402/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

The Elixir SDK for the [x402](https://x402.org) HTTP payment protocol.

X402 is a library, not an application. It provides protocol headers, a facilitator
client, and optional Plug middleware without tying an application to a specific
facilitator, chain, or web framework.

## Features

- x402 v2 `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, and `PAYMENT-RESPONSE` headers with complete requirement and extension-echo validation
- Payer client signing `"exact"` (EIP-3009), metered `"upto"` (Permit2), and Solana `"exact"` payments, with an automatic `402 → sign → retry` Finch flow
- Plug/Phoenix payment gate with signature-bound replay protection, optional inline local verification, and settlement only after successful resource handling
- Local payment verification without trusting a facilitator: EVM (EIP-712 + ERC-1271/6492, balance and simulation checks) and Solana (Ed25519, fee-payer isolation, instruction whitelist)
- Facilitator `/verify` and `/settle` client with retries, hooks, and telemetry
- A runnable facilitator server for EVM and Solana from one Plug — ERC-6492 counterfactual settlement, ERC-20 Transfer-event proof of delivery, pending-settlement reconciliation
- Paid MCP tools over the x402 MCP transport, server and client side
- Browser paywall: a self-contained HTML 402 page with an EIP-1193 wallet flow
- Pluggable payment schemes through the `X402.Scheme` behaviour
- Extensions: payment-identifier idempotency (ETS or Redis), SIWX, signed offers and receipts, gas sponsoring, Bazaar discovery
- Optional Finch, Plug, Redix, and cryptography dependencies

## Installation

Add the library and only the optional integrations your application uses:

```elixir
def deps do
  [
    {:x402, "~> 0.5.0"},
    {:finch, "~> 0.19"}, # facilitator HTTP calls
    {:plug, "~> 1.14"}   # PaymentGate
  ]
end
```

Add `ex_secp256k1` and `ex_keccak` only when using the default EVM SIWX
signature verifier.

## Phoenix quick start

Start Finch, the facilitator client, and the idempotency cache in your
application supervision tree:

```elixir
children = [
  {Finch,
   name: MyApp.Finch,
   pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}},
  {X402.Facilitator,
   name: MyApp.Facilitator,
   url: "https://facilitator.example.com",
   finch: MyApp.Finch},
  {X402.Extensions.PaymentIdentifier.ETSCache, name: MyApp.PaymentCache}
]
```

Configure the Plug with the facilitator process, not a URL:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  payment_identifier_cache: MyApp.PaymentCache,
  routes: [
    %{
      method: :get,
      path: "/api/weather",
      scheme: "exact",
      price: "10000", # atomic units: 0.01 USDC when the asset has 6 decimals
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWalletAddress",
      description: "Weather data API"
    }
  ]
```

An unpaid request receives HTTP 402 and a Base64-encoded v2
`PAYMENT-REQUIRED` header. A paid request is decoded and matched against the
complete advertised requirement, verified, passed to the protected handler,
and settled immediately before a successful response is sent. Handler responses
with status 400 or greater are not settled.

The verified payload and matched requirement are available to the handler as
`conn.assigns.x402_payment_payload` and
`conn.assigns.x402_payment_requirements`.

## Run your own facilitator

The SDK also implements the facilitator role itself — verify and settle
payments on-chain instead of delegating to a hosted service:

```elixir
{:ok, engine} =
  X402.Facilitator.Engine.new(rpc: rpc, signer: signer, networks: ["eip155:84532"])

children = [
  {Bandit, plug: {X402.Plug.Facilitator, engine: engine}, port: 4022}
]
```

That serves `POST /verify`, `POST /settle`, and `GET /supported` over the
standard facilitator wire protocol. Pass `engines: [evm_engine, svm_engine]`
instead of `engine:` to serve EVM and Solana (`X402.Facilitator.SVMEngine`)
from the same endpoint. See the
[Run Your Own Facilitator](https://hexdocs.pm/x402/facilitator.html) guide.

## Metered `"upto"` payments

For an `"upto"` route, `price` is the maximum authorization in atomic token
units:

```elixir
%{
  method: :post,
  path: "/api/generate",
  scheme: "upto",
  price: "1000000", # authorize up to 1 USDC for a 6-decimal asset
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  pay_to: "0xYourWalletAddress"
}
```

After measuring resource use, store the actual amount on the connection before
building the response:

```elixir
def create(conn, params) do
  result = generate(params)
  actual_atomic_amount = billable_amount(result)

  {:ok, conn} =
    X402.Plug.PaymentGate.put_settlement_amount(conn, actual_atomic_amount)

  json(conn, %{result: result})
end
```

The facilitator receives the advertised maximum during `/verify` and the actual
amount during `/settle`. An amount above the authorized maximum fails closed.
If no actual amount is supplied, the advertised maximum is settled.

This release implements the post-handler `authorization` flow used by current
EVM `exact` and `upto` schemes. Route options declaring `paymentFlow: "upfront"`
or `paymentFlow: "escrow"` are rejected because those flows require different
handler and cancellation semantics.

## Lifecycle hooks

Hooks receive an `X402.Hooks.Context` and must use the return contract defined by
`X402.Hooks`:

```elixir
defmodule MyApp.PaymentHooks do
  @behaviour X402.Hooks

  @impl true
  def before_verify(context, _metadata) do
    IO.inspect(context.payload, label: "Incoming payment")
    {:cont, context}
  end

  @impl true
  def after_verify(context, _metadata), do: {:cont, context}

  @impl true
  def on_verify_failure(context, _metadata), do: {:cont, context}

  @impl true
  def before_settle(context, _metadata), do: {:cont, context}

  @impl true
  def after_settle(context, _metadata), do: {:cont, context}

  @impl true
  def on_settle_failure(context, _metadata), do: {:cont, context}
end
```

Pass the module with `hooks: MyApp.PaymentHooks`. Before hooks may return
`{:halt, reason}`; failure hooks may return `{:recover, result}`.

## Multiple payment options

Use `accepts` to advertise more than one valid requirement:

```elixir
%{
  method: :get,
  path: "/api/data",
  accepts: [
    %{
      scheme: "exact",
      price: "10000",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWalletAddress"
    },
    %{
      scheme: "exact",
      price: "5000",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      pay_to: "YourSolanaAddress"
    }
  ]
}
```

Every core field must match exactly. Client-added metadata is allowed only
under `accepted.extra` and cannot remove or mutate values advertised by the
server.

## Facilitator API

The lower-level client can be called directly:

```elixir
case X402.Facilitator.verify(
       MyApp.Facilitator,
       payment_payload,
       payment_requirements
     ) do
  {:ok, %{status: 200, body: %{"isValid" => true} = result}} ->
    {:ok, result}

  {:ok, %{status: 200, body: %{"isValid" => false} = result}} ->
    {:error, result}

  {:error, reason} ->
    {:error, reason}
end
```

Facilitator requests use the v2 wire object:
`%{"x402Version" => 2, "paymentPayload" => payload,
"paymentRequirements" => requirements}`.

## HTTP outcomes

`X402.Plug.PaymentGate` follows the v2 HTTP transport mapping:

| Status | Meaning |
|--------|---------|
| 400 | Malformed or invalid payment input |
| 402 | Payment required, unmatched terms, or verification/settlement failure |
| 500 | Facilitator transport failure, malformed facilitator response, or internal payment-processing error |

## Documentation

- [Getting Started](https://hexdocs.pm/x402/getting-started.html)
- [Paying for Resources](https://hexdocs.pm/x402/client.html)
- [Plug/Phoenix Integration](https://hexdocs.pm/x402/plug-integration.html)
- [Custom Payment Schemes](https://hexdocs.pm/x402/custom-schemes.html)
- [Paid MCP Tools](https://hexdocs.pm/x402/mcp.html)
- [Browser Paywall](https://hexdocs.pm/x402/paywall.html)
- [Local Payment Verification](https://hexdocs.pm/x402/local-verification.html)
- [Run Your Own Facilitator](https://hexdocs.pm/x402/facilitator.html)
- [Live Smoke Tests](https://hexdocs.pm/x402/live-smoke-tests.html)
- [API Reference](https://hexdocs.pm/x402/api-reference.html)
- [Official x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Official HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md)

## License

MIT License — see [LICENSE](LICENSE) for details.
