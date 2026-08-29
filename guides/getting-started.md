# Getting Started

This guide adds an x402 v2 payment gate to an Elixir application. Gating
is one of four roles the SDK covers end to end:

- **Pay** for x402-protected resources from Elixir —
  [Paying for Resources](client.html)
- **Gate** your own routes behind payment — this guide, then
  [Plug/Phoenix Integration](plug-integration.html) for the full option
  reference
- **Verify** payments locally instead of trusting a remote facilitator —
  [Local Payment Verification](local-verification.html)
- **Run the facilitator** yourself, on EVM and Solana —
  [Run Your Own Facilitator](facilitator.html)

## Install the integrations you use

```elixir
def deps do
  [
    {:x402, "~> 0.6.0"},
    {:finch, "~> 0.19"},
    {:plug, "~> 1.14"}
  ]
end
```

Finch and Plug are optional library dependencies, so applications must include
them when using the facilitator client or `X402.Plug.PaymentGate`.

## Start the payment processes

Add Finch, the facilitator client, and an idempotency cache to the application
supervision tree:

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

Replace the example URL with the HTTPS endpoint for your facilitator.

## Add the Plug

```elixir
pipeline :paid_api do
  plug X402.Plug.PaymentGate,
    facilitator: MyApp.Facilitator,
    payment_identifier_cache: MyApp.PaymentCache,
    routes: [
      %{
        method: :get,
        path: "/api/data",
        scheme: "exact",
        price: "10000",
        network: "eip155:8453",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        pay_to: "0xYourWalletAddress",
        description: "Premium data"
      }
    ]
end

scope "/api" do
  pipe_through [:api, :paid_api]
  get "/data", DataController, :show
end
```

`price` is a string containing atomic token units. For a six-decimal asset,
`"10000"` represents `0.01` tokens.

An unpaid request receives HTTP 402 with a Base64-encoded v2
`PAYMENT-REQUIRED` header. For a paid request, the Plug:

1. Validates the v2 payload, complete accepted requirement, and extension echo.
2. Calls the facilitator's `/verify` endpoint.
3. Assigns the payload and matched requirements, then runs the protected handler.
4. Skips settlement when the handler response is an error.
5. Otherwise calls `/settle` immediately before sending the response and adds
   `PAYMENT-RESPONSE`.

The handler can read `conn.assigns.x402_payment_payload` and
`conn.assigns.x402_payment_requirements` after verification.

## Meter an `"upto"` request

Set `scheme: "upto"` and advertise the maximum amount with `price`. The handler
must put the actual charge on the connection before returning its response:

```elixir
def create(conn, params) do
  result = generate(params)

  {:ok, conn} =
    X402.Plug.PaymentGate.put_settlement_amount(conn, billable_atomic_units(result))

  json(conn, %{result: result})
end
```

The actual amount may be zero but cannot exceed the advertised maximum. Omitting
it settles the maximum. See the
[Plug/Phoenix Integration](plug-integration.html) guide for route, hook, and
error details.
