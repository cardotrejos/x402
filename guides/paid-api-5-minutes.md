# Build a Paid API in 5 Minutes

This guide puts a paid route in a Phoenix or Plug application and calls it from
an Elixir client that pays for it. Unpaid requests get HTTP 402 with a
`PAYMENT-REQUIRED` header. Paid requests are verified, handled, and settled.

The steps below assume an existing application. For the full option reference,
read [Getting Started](getting-started.html) and
[Plug/Phoenix Integration](plug-integration.html) after this guide.

## 1. Add the dependencies

```elixir
def deps do
  [
    {:x402, "~> 0.9.0"},
    {:finch, "~> 0.19"},
    {:plug, "~> 1.14"}
  ]
end
```

The server needs only these. The client in step 6 also needs `ex_secp256k1`
and `ex_keccak` to sign EVM payments.

## 2. Start the payment processes

Add these to your supervision tree. Replace the facilitator URL with the HTTPS
endpoint of the facilitator you use.

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

`X402.Extensions.PaymentIdentifier.ETSCache` keeps replay protection on one
node. For several nodes, see the [Deployment](deployment.html) guide.

## 3. Gate the route

Put the gate in the pipeline for the paid routes:

```elixir
pipeline :paid_api do
  plug X402.Plug.PaymentGate,
    facilitator: MyApp.Facilitator,
    payment_identifier_cache: MyApp.PaymentCache,
    routes: [
      %{
        method: :get,
        path: "/api/weather",
        scheme: "exact",
        price: "10000",
        network: "eip155:8453",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        pay_to: "0xYourWalletAddress",
        description: "Weather data"
      }
    ]
end

scope "/api" do
  pipe_through [:api, :paid_api]
  get "/weather", WeatherController, :show
end
```

`price` is in atomic token units. For a six-decimal asset such as USDC, `"10000"`
is 0.01 tokens. Replace `pay_to` with the wallet that receives payments.

## 4. Write the handler

The handler runs only after the payment is verified. A response with status 400
or higher is not settled, so a failed request costs the payer nothing:

```elixir
defmodule MyAppWeb.WeatherController do
  use MyAppWeb, :controller

  def show(conn, _params) do
    json(conn, %{temperature_c: 21, source: "example"})
  end
end
```

Inside the handler, `conn.assigns.x402_payment_payload` and
`conn.assigns.x402_payment_requirements` hold the verified payment and the
requirement it matched.

## 5. Check the 402 response

Start the server and request the route without a payment:

```bash
curl -i http://localhost:4000/api/weather
```

The response is HTTP 402 with a `PAYMENT-REQUIRED` header. That header is
Base64-encoded JSON that lists the payment options the server accepts.

## 6. Pay from an Elixir client

The client signs the payment, retries the request once, and returns the
settlement receipt:

```elixir
{:ok, _pid} =
  Finch.start_link(
    name: MyApp.PayerFinch,
    pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}
  )

# Load the payer key from a secret store or runtime configuration. Never commit it.
{:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_PRIVATE_KEY"))

{:ok, %{status: 200, body: body, payment_response: receipt}} =
  X402.Client.Finch.request(MyApp.PayerFinch, "https://api.example.com/api/weather",
    signer: signer,
    max_amount: "10000"
  )

IO.inspect(receipt["transaction"], label: "settlement transaction")
```

`max_amount` is the largest payment, in atomic units, the client will sign for
one request. Payment options above it are never selected. Payments are only
signed when the server responds with 402, so a request that needs no payment is
returned unchanged.

## Next steps

- [Paying for Resources](client.html) covers policies, session budgets, and
  consent hooks.
- [Plug/Phoenix Integration](plug-integration.html) covers route options, hooks,
  rate limits, and error responses.
- [Deployment](deployment.html) covers production configuration.
- [AI Agents](ai-agents.html) covers spend controls for autonomous payers.
