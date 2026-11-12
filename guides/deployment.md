# Deploying x402 in Production

This guide covers the decisions that change when an x402 gate or payer moves
from development to a running service: where configuration comes from, how
replay protection is shared between nodes, how rate limits are counted, and what
to observe. It assumes you have already read
[Getting Started](getting-started.html) or
[Build a Paid API in 5 Minutes](paid-api-5-minutes.html).

## Configuration

Keep facilitator settings in `config/runtime.exs`, so the same release reads
them from the environment at boot. `X402.Facilitator` merges
`config :my_app, <name>` under the options you pass, and explicit options win:

```elixir
# config/runtime.exs
import Config

config :my_app, MyApp.Facilitator,
  url: System.get_env("FACILITATOR_URL", "https://facilitator.example.com")
```

```elixir
# application.ex
{X402.Facilitator,
 name: MyApp.Facilitator,
 otp_app: :my_app,
 finch: MyApp.Finch}
```

Secrets follow the same path. The CDP facilitator authenticator takes its
`:api_key_id` and `:api_key_secret` as options. Read them from the environment
in `config/runtime.exs` and pass them through `auth:`. Do not commit them to
source control, and do not put them in compile-time configuration, because
compile-time values end up in build artifacts.

## HTTP connections

Start Finch with TLS verification for the facilitator and any other remote
host:

```elixir
{Finch,
 name: MyApp.Finch,
 pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}}
```

Use HTTPS for every facilitator URL. The facilitator client sends payment
payloads over that connection.

## Replay protection across nodes

`payment_identifier_cache:` stops the same signed payment from being settled
twice. Its backend depends on how many nodes serve the route:

- **One node:** `X402.Extensions.PaymentIdentifier.ETSCache`, started in your
  supervision tree.
- **Several nodes:** a shared store. `X402.Extensions.PaymentIdentifier.RedisCache`
  makes the claim with one atomic `SET NX PX` command, so all nodes see the same
  claims. Start Redix in your supervision tree and build the cache from its
  connection:

  ```elixir
  {:ok, cache} = X402.Extensions.PaymentIdentifier.RedisCache.new(conn: MyApp.Redis)

  plug X402.Plug.PaymentGate,
    facilitator: MyApp.Facilitator,
    payment_identifier_cache: {X402.Extensions.PaymentIdentifier.RedisCache, cache},
    routes: [...]
  ```

Configure the Redis server with `maxmemory-policy noeviction`. Under eviction,
a live claim can disappear before its payment is settled. Redis or connection
errors fail closed: the protected handler does not run.

## Rate limits

`rate_limit:` caps verified payments per payer or per IP over a window:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  routes: [...],
  rate_limit: [limit: 60, window_ms: 60_000]
```

The default store, `X402.RateLimiter.ETS`, counts in each node's memory. A
payer who reaches the limit on one node can still get through on another. For a
limit that holds across the cluster, pass a shared store as `store:`, using
`X402.RateLimiter` or a `{module, ref}` pair. A denied request answers 429 with
`Retry-After` and is never settled.

`on_error` decides what happens when the store fails. It defaults to `:allow`,
so a store failure admits the request. Set `on_error: :deny` to refuse requests
while the store is unavailable. See the `rate_limit:` options in the
[Plug/Phoenix Integration](plug-integration.html) guide.

## Observability

x402 emits telemetry events under the `[:x402, ...]` prefix. The gate emits
events for rejected payments and rate-limited requests, and the client emits
events for each step of a payment:

- `[:x402, :plug, :payment_rejected]`
- `[:x402, :plug, :rate_limited]`
- `[:x402, :client, :request]`
- `[:x402, :client, :build]`

`X402.Telemetry` lists every event. `X402.Telemetry.Metrics` builds the
`telemetry_metrics` definitions for them, and is compiled only when the optional
`telemetry_metrics` dependency is present.
Attach a handler to log rejections:

```elixir
:telemetry.attach(
  "my-app-x402-rejections",
  [:x402, :plug, :payment_rejected],
  &MyApp.X402Logger.handle_event/4,
  nil
)
```

Handlers run inside the request process. Keep them short and do not raise.

## Running your own facilitator

If you serve the facilitator endpoints yourself, the EVM and Solana engines need
an RPC connection, a signer, and a nonce manager. The
[Run Your Own Facilitator](facilitator.html) guide covers the engine options,
the pending-settlement store, and the HTTP endpoints. Read it before you run
settlement on a live network.

## Before you go live

- Facilitator URLs use HTTPS, and Finch uses `secure_pool_opts/0`.
- Credentials come from runtime configuration, not from source or compile-time
  config.
- `payment_identifier_cache:` is set on every gated route. Without it, the gate
  logs a warning and concurrent identical requests can settle the same payment
  twice.
- Multi-node deployments use a shared replay cache, and Redis uses
  `maxmemory-policy noeviction`.
- Rate limits use a store that matches your node count.
- Telemetry handlers are attached and logging is in place.
- Live settlement tests run only in an environment you control. See
  [Live Smoke Tests](live-smoke-tests.html).
