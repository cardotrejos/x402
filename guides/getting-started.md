# Getting Started

This guide walks you through adding x402 payments to an Elixir application.

## Installation

Add `x402` and a HTTP client to your dependencies:

```elixir
def deps do
  [
    {:x402, "~> 0.3"},
    {:finch, "~> 0.19"}
  ]
end
```

## Start the Facilitator Client

Add the facilitator to your application's supervision tree:

```elixir
# lib/my_app/application.ex
children = [
  {Finch, name: MyApp.Finch},
  {X402.Facilitator,
    name: MyApp.X402,
    url: "https://x402.org/facilitator",
    finch: MyApp.Finch}
]
```

## Verify a Payment

```elixir
payment_payload = %{
  "transactionHash" => "0xabc...",
  "network" => "eip155:8453",
  "scheme" => "exact",
  "payerWallet" => "0x1234..."
}

requirements = %{
  "scheme" => "exact",
  "network" => "eip155:8453",
  "price" => "0.01",
  "payTo" => "0xYourWallet"
}

case X402.Facilitator.verify(MyApp.X402, payment_payload, requirements) do
  {:ok, %{status: 200}} -> IO.puts("Payment verified!")
  {:error, reason} -> IO.inspect(reason, label: "Verification failed")
end
```

## Use the Plug Middleware

For the simplest integration, use the Plug middleware in your Phoenix router:

```elixir
# lib/my_app_web/router.ex
pipeline :paid_api do
  plug X402.Plug.PaymentGate,
    facilitator_url: "https://x402.org/facilitator",
    routes: [
      %{
        method: :get,
        path: "/api/data",
        price: "0.01",
        network: "eip155:8453",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        pay_to: "0xYourWallet"
      }
    ]
end

scope "/api" do
  pipe_through [:api, :paid_api]
  get "/data", DataController, :show
end
```

Unpaid requests receive a `402 Payment Required` response with a
`PAYMENT-REQUIRED` header containing v2 payment options. Clients that include
a valid `PAYMENT-SIGNATURE` header are verified, settled, and passed through
to your controller. The decoded payment payload and matched requirements are
available on `conn.assigns.x402_payment_payload` and
`conn.assigns.x402_payment_requirements`.
