# Paid MCP Tools in Elixir

The [x402 MCP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md)
lets AI agents pay for MCP tool calls: a paid tool advertises its price in a
payment-required tool result, the client retries the call with a signed
payment in request `_meta`, and the settlement receipt comes back in result
`_meta`. This guide covers both halves — charging for a tool you serve, and
paying for a tool you call.

For local auth-capture escrow, configure `auth_capture_resource:` and return
`{:ok, result_map, actual_amount}` from paid handlers. Funding precedes the
handler; synchronous settlement or durable deferred metering precedes content.
See [Auth-capture on EVM](auth-capture.html) for recovery and retained-budget rules.

## How a paid tool call happens

1. The client calls a paid tool without payment. The server returns a tool
   result with `isError: true` whose `structuredContent` (and JSON-encoded
   `content[0].text`) carry the `PaymentRequired` object — the price list.
2. The client picks a payment option, signs it (EIP-3009 for `exact` on EVM
   networks — an off-chain signature, no gas), and retries the tool call with
   the `PaymentPayload` in request params `_meta["x402/payment"]`.
3. The server verifies the payment through its facilitator, runs the tool,
   settles, and attaches the settlement receipt to result
   `_meta["x402/payment-response"]`.

The SDK implements this as **library-agnostic pure functions over plain
maps** — `X402.MCP`, `X402.MCP.Server`, and `X402.MCP.Client` work with any
Elixir MCP library (Anubis/Hermes, Phantom, gen_mcp, a hand-rolled JSON-RPC
loop) because MCP tool-call requests and results are just maps.

## Serving a paid tool

Compile the pricing once (at boot or module level), then wrap your tool
handler with `X402.MCP.Server.call/3`:

```elixir
# In your application supervision tree:
children = [
  {X402.Facilitator, name: MyApp.Facilitator, finch: MyApp.Finch},
  {X402.Extensions.PaymentIdentifier.ETSCache, name: MyApp.PaymentCache}
]

config =
  X402.MCP.Server.init(
    tool: "premium_search",
    description: "Premium search with fresh data",
    accepts: [
      %{
        price: "10000",                                        # atomic units
        network: "eip155:84532",                               # Base Sepolia
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",   # USDC
        pay_to: "0xYourReceivingWallet",
        extra: %{"name" => "USDC", "version" => "2"}
      }
    ],
    facilitator: MyApp.Facilitator,
    payment_identifier_cache: MyApp.PaymentCache
  )

def handle_tool_call("premium_search", params) do
  X402.MCP.Server.call(params, config, fn request ->
    results = MyApp.Search.run(request["arguments"]["query"])
    %{"content" => [%{"type" => "text", "text" => results}]}
  end)
end
```

`call/3` always returns a tool result map, so it drops straight into any
dispatch function:

- **No payment** (or an invalid one) → the spec's payment-required result.
  The wrapped handler never runs.
- **Valid payment** → verified against the facilitator, the handler runs,
  the payment is settled, and the receipt lands in
  `_meta["x402/payment-response"]`.
- **Handler returns `"isError" => true`** → returned unchanged, nothing is
  settled, and the replay claim is released so the client can retry with the
  same payment.
- **Settlement fails after execution** → only the payment error is returned,
  never the tool's content (per the spec).

Validation is as strict as `X402.Plug.PaymentGate`: the payload must be
x402 v2, its `accepted` must match an advertised option exactly (including
`extra` preservation), and advertised `extensions` must be echoed without
dropping values.

`payment_identifier_cache:` enables replay protection — an
`X402.Extensions.PaymentIdentifier.ETSCache` server or any
`X402.Extensions.PaymentIdentifier.Cache` adapter, the same option the Plug
gate takes. Each payment proof is atomically claimed before settlement, so
the same signed payment cannot be settled twice. The claim key is a
deterministic hash of the signed scheme payload — never the
client-controlled payment identifier — so neither re-encoding the
payment envelope nor varying the id can mint a fresh claim for the same
signed authorization.

### Payment identifiers

The server supports the
[payment-identifier extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/payment_identifier.md)
in its spec format. Advertise it with
`extensions: %{"payment-identifier" => X402.Extensions.PaymentIdentifier.extension(required: true)}`;
clients echo it with their id under
`extensions["payment-identifier"]["info"]["id"]` (the
[client guide](client.html) shows the enricher). The id must be 16–128
characters of `[A-Za-z0-9_-]`, otherwise the payment-required result's
`error` is `invalid_payload`; with `required: true` a payment without an
id yields `payment_identifier_required`. When `payment_identifier_cache:`
is configured, the id is bound to a fingerprint of the matched
requirements and the **tool name**
(`X402.Extensions.PaymentIdentifier.fingerprint/2`) under a `"pid:"` key:
reusing it for a different tool or different requirements yields
`payment_identifier_conflict`, while the same request proceeds normally.
A binding is released whenever the tool result is not settled (handler
error, verification or settlement failure), so the client can retry with
the same id. The pre-0.7.0 `"paymentIdentifier"` format is still accepted
but deprecated (removed in 1.0.0) and emits
`[:x402, :payment_identifier, :legacy]`.

### Builder codes

A payment echoing the
[builder-code extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md)
is validated whether or not you advertise it (with
`extensions: %{"builder-code" => X402.Extensions.BuilderCode.extension("my_app")}`):
malformed codes or more than ten service codes yield `invalid_payload`,
and an app code that differs from the advertised one is an extension echo
mismatch. The codes travel to the facilitator inside the payload, which
encodes them into the settlement calldata.

### Lifecycle hooks

The `hooks:` module (an `X402.Hooks` implementation, as for the Plug gate)
may define the two optional resource-server callbacks, which receive an
`X402.Hooks.RequestContext` with `transport: :mcp`, the `request` params,
the `tool` name, and the advertised `requirements` and `extensions`:

- `on_protected_request/2` runs on every call before the payment is
  inspected. Continue with `{:cont, context}` (optionally with replaced
  requirements or extensions), answer with `{:halt, {status, body}}` — an
  `isError` result carrying `body` in `structuredContent` — or run the
  handler unpaid with `{:halt, :skip_payment}` (telemetry
  `[:x402, :mcp, :pass_through]`, `reason: :hook_skipped`).
- `on_verified_payment_canceled/2` runs when a verified payment is not
  settled: the handler returned an error result
  (`reason: :handler_failed`), raised or threw (`:handler_raised`, with
  `:error`), or settlement failed (`:settlement_failed`, with `:error`).

See the [Plug/Phoenix Integration](plug-integration.html) guide for an
example module.

To advertise the price outside a rejection (for example in a `tools/list`
response), use `X402.MCP.Server.payment_required_result/2`.

### Wiring into an MCP library

The wrapper needs the raw `tools/call` **params map including `_meta`** —
that is where the payment travels. Run it at whatever layer of your MCP stack
sees those params, and return the resulting map through the library's
tool-result path (results are plain maps on the wire, and `_meta` on a result
is standard MCP). The wrapper never touches the transport, so stdio, SSE, and
streamable HTTP all work unchanged.

With a hand-rolled JSON-RPC loop (or any library that hands you the request):

```elixir
def handle_request(%{"method" => "tools/call", "params" => params} = rpc) do
  result =
    case params["name"] do
      "premium_search" ->
        X402.MCP.Server.call(params, MyServer.Pricing.premium_search(), fn req ->
          %{"content" => [%{"type" => "text", "text" => search(req["arguments"])}]}
        end)

      other ->
        free_tool(other, params)
    end

  %{"jsonrpc" => "2.0", "id" => rpc["id"], "result" => result}
end
```

Support for exposing per-call `_meta` to tool handlers varies across the
current Elixir MCP libraries — as of Anubis MCP 2.0 (`anubis_mcp`, the
successor to `hermes_mcp`), component callbacks receive the initialize-time
`_meta` (`frame.context.init_meta`) but not the tool call's own `_meta`, so
the wrapper belongs in a lower-level handler or plug in front of tool
dispatch. If your library of choice surfaces the raw `tools/call` params
anywhere, the integration is the one-liner above.

## Paying for a paid tool

`X402.MCP.Client.call/3` drives any tool-call function through the
detect → sign → retry-once loop. Add `ex_secp256k1` and `ex_keccak` for
signing:

```elixir
{:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_PRIVATE_KEY"))

request = %{"name" => "premium_search", "arguments" => %{"query" => "x402"}}

{:ok, %{result: result, payment_response: receipt, paid: true}} =
  X402.MCP.Client.call(request, &MyMCP.call_tool/1,
    signer: signer,
    max_amount: "10000",
    on_payment_required: fn payment_required ->
      Logger.info("paying for tool", accepts: payment_required["accepts"])
      :ok
    end
  )

IO.inspect(receipt["transaction"], label: "settlement tx")
```

The tool-call function receives the (possibly payment-carrying) request map
and may return the tool result map directly, `{:ok, result}`, or
`{:error, reason}`. Payment challenges are detected in payment-required tool
results and in `402`/`-32042` JSON-RPC errors (the SEP-1036 elicitation code
some MCP stacks use for payment flows).

Guardrails, matching `X402.Client.Finch` (the
[client guide](client.html) covers each in depth):

- **`max_amount:`** — a per-payment ceiling; options above it are never
  selected. `network:`, `scheme:`, and `asset:` filter selection the same
  way.
- **`policies:`** — `X402.Client.Policy` functions (`max_amount/1`,
  `networks/1`, `assets/1`, `schemes/1`, or your own); every policy must
  accept an entry for it to be selected.
- **`budget:`** — an `X402.Client.Budget` shared across calls. The selected
  amount is reserved before the paid retry and released when that retry
  comes back as another payment-required result without a successful
  receipt; a reservation that does not fit fails the call with
  `{:error, {:budget_exceeded, details}}`.
- **`on_payment_required:`** — a veto hook invoked with the decoded
  `PaymentRequired` before anything is signed. Return `:cancel` to abort with
  `{:error, :payment_cancelled}`.
- **`hooks:`** — an `X402.Client.Hooks` module run around payment creation
  (`before_payment/2`, `after_payment/2`, `on_payment_failure/2`).
- **Never pays twice** — at most one payment retry per call; a second
  payment-required response is returned as-is, and requests that already
  carry `_meta["x402/payment"]` are refused with
  `{:error, :payment_already_attempted}`.

When none of `max_amount:`, `policies:`, or `budget:` is given a warning is
logged once per VM.

### Signing in with X

With `siwx:` configured the client answers a `sign-in-with-x` challenge
advertised in the payment-required result before paying: the tool call is
retried with the proof in `_meta["x402/sign-in-with-x"]` and no payment.
A result that is not payment-required is returned with
`siwx_authenticated: true`; another payment-required result continues
with the payment flow, the paid call carrying a proof for the new
challenge so the server records the payer. MCP resources have no HTTP
origin, so `domain:` is required to pin the challenge to the server you
expect. Without it, an advertised challenge fails with
`{:error, {:siwx, :domain_mismatch}}` before signing or retrying. Do not
take this pin from the challenge or its advertised resource URL.

```elixir
X402.MCP.Client.call(request, &MyMCP.call_tool/1,
  signer: signer,
  max_amount: "10000",
  siwx: [chain_id: :auto, domain: "mcp.example.com"]
)
```

`chain_id:` is a CAIP-2 chain or `:auto` (the first advertised chain the
signer can sign); `address:` and `signature_scheme:` are optional. If you
drive the retry yourself, `X402.MCP.put_siwx/2` attaches a proof to a
request's `_meta` and `X402.MCP.fetch_siwx/1` reads it back;
`X402.MCP.siwx_meta_key/0` returns the key.

If your MCP client library exposes request `_meta` but you want to drive the
retry yourself, `X402.MCP.Client.build_payment_meta/3` turns a
payment-required response (tool result or bare `PaymentRequired`) into the
`_meta` entries for the retried call:

```elixir
with {:ok, result} <- MyMCP.call_tool(request),
     {:ok, payment_required} <- X402.MCP.fetch_payment_required(result),
     {:ok, meta} <- X402.MCP.Client.build_payment_meta(payment_required, signer) do
  MyMCP.call_tool(request, meta: meta)
end
```

## Telemetry

- `[:x402, :mcp, :payment_required]` — server advertised payment requirements
- `[:x402, :mcp, :payment_verified]` — server verified and settled a payment
- `[:x402, :mcp, :payment_rejected]` — server rejected a payment (`:reason`;
  `{:hook_halted, status}` when `on_protected_request/2` answered the call)
- `[:x402, :mcp, :pass_through]` — an `on_protected_request/2` hook let the
  handler run unpaid (`reason: :hook_skipped`)
- `[:x402, :mcp, :call]` — client drove a tool call (`:status`, `:paid`)
- `[:x402, :client, :siwx]` — client answered a Sign-In-With-X challenge
  (`transport: :mcp`, `:chain_id`, `:outcome` or `:reason`)

All events carry `%{count: 1}` measurements.

## References

- [MCP transport specification](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md)
- [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Paying for x402 Resources from Elixir](client.html) — the HTTP payer client
- [Plug/Phoenix Integration](plug-integration.html) — the HTTP server half
