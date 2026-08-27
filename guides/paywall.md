# Browser Paywall

By default, `X402.Plug.PaymentGate` answers unpaid requests with a bare
machine-readable 402: an empty JSON body plus the Base64 `PAYMENT-REQUIRED`
header. That is exactly right for API clients and agents — and useless for a
person who opens the gated URL in a browser.

The `:paywall` option adds a human-usable HTML page for that case:

```elixir
plug X402.Plug.PaymentGate,
  paywall: X402.Paywall.Default,
  routes: [
    %{
      method: :get,
      path: "/premium/report",
      description: "Premium market report",
      price: "10000",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      pay_to: "0xYourWallet",
      extra: %{"name" => "USD Coin", "version" => "2"}
    }
  ]
```

## Content negotiation

The gate mirrors the browser heuristic used by the reference x402
middlewares (Go and TypeScript): a request receives HTML only when its
`Accept` header contains `text/html` **and** its `User-Agent` contains
`Mozilla`. Everything else — an absent `Accept` header, `application/json`,
`*/*`, curl, SDK clients — keeps today's JSON body.

| Request                                             | 402 body |
| --------------------------------------------------- | -------- |
| Browser page load (`text/html` Accept + Mozilla UA) | HTML     |
| `Accept: text/html` without a Mozilla User-Agent    | JSON     |
| `Accept: application/json`, `*/*`, or no Accept     | JSON     |
| Any request when `:paywall` is not set              | JSON     |

Both forms carry the identical `PAYMENT-REQUIRED` header, so tooling that
inspects headers works regardless of which body it receives. The paywall
applies only to pre-handler 402 responses (missing or rejected payments);
400 invalid-payload responses, 500 responses, and post-handler settlement
failures are always JSON.

Leaving `:paywall` unset (the default) keeps every response byte-identical
to previous releases.

## The default page

`X402.Paywall.Default` renders a single self-contained page — inline CSS,
no external requests, no build step, a few KB:

  * the resource description plus amount, asset, network, and recipient for
    every advertised payment option
  * the exact Base64 `PAYMENT-REQUIRED` header value with manual retry
    instructions, for people driving their own tooling
  * a minimal EIP-1193 (`window.ethereum`) wallet flow for `"exact"` EVM
    options using the default `eip3009` asset transfer method

The wallet flow builds the `TransferWithAuthorization` EIP-712 typed data in
the page from the advertised requirements (domain `name`/`version` from
`extra`, chain id from the CAIP-2 network, verifying contract from `asset`),
signs it with `eth_signTypedData_v4`, assembles the v2 `PaymentPayload`
(echoing the selected requirement and any advertised extensions), retries the
request with the `PAYMENT-SIGNATURE` header via `fetch`, and replaces the
document with the paid response.

Without a browser wallet — or when no advertised option is wallet-payable
(non-EVM networks, `upto` routes, non-`eip3009` transfer methods, missing
`extra.name`/`extra.version`) — the page degrades gracefully to the
requirement details and the copyable header instructions.

All interpolated values are HTML-escaped and the configuration JSON embedded
for the script is encoded script-safe, so hostile route descriptions or
service names cannot inject markup.

## Custom paywalls

Implement the `X402.Paywall` behaviour to serve your own page:

```elixir
defmodule MyApp.Paywall do
  @behaviour X402.Paywall

  @impl X402.Paywall
  def render(payment_required, _conn_info) do
    description = payment_required["resource"]["description"]
    {:ok, MyAppWeb.PaywallHTML.page(description: description)}
  end
end
```

`render/2` receives the exact v2 `PaymentRequired` map the gate encodes into
the `PAYMENT-REQUIRED` header — `X402.PaymentRequired.encode/1` reproduces
the header value byte for byte — plus a `conn_info` map with the request
`:method`, `:request_path`, and response `:status`. Return `{:ok, html}` with
the complete page as iodata; returning `{:error, reason}` logs a warning and
falls back to the JSON body, so a renderer failure never blocks the payment
flow.

Escape everything you interpolate: route descriptions and service names are
configuration, but defense in depth is cheap and `X402.Paywall.Default`
treats them as untrusted.
