# Paid MCP Tools in Elixir

The [x402 MCP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md)
lets AI agents pay for MCP tool calls: a paid tool advertises its price in a
payment-required tool result, the client retries the call with a signed
payment in request `_meta`, and the settlement receipt comes back in result
`_meta`. This guide covers both halves — charging for a tool you serve, and
paying for a tool you call.

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

`payment_identifier_cache:` enables replay protection — the same
`X402.Extensions.PaymentIdentifier.ETSCache` option the Plug gate takes. Each
payment proof is atomically claimed before settlement, so the same signed
payment cannot be settled twice.

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

Guardrails, matching `X402.Client.Finch`:

- **`max_amount:`** — the budget guard; options above it are never selected.
  `network:`, `scheme:`, and `asset:` filter selection the same way.
- **`on_payment_required:`** — a veto hook invoked with the decoded
  `PaymentRequired` before anything is signed. Return `:cancel` to abort with
  `{:error, :payment_cancelled}`.
- **Never pays twice** — at most one payment retry per call; a second
  payment-required response is returned as-is, and requests that already
  carry `_meta["x402/payment"]` are refused with
  `{:error, :payment_already_attempted}`.

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
- `[:x402, :mcp, :payment_rejected]` — server rejected a payment (`:reason`)
- `[:x402, :mcp, :call]` — client drove a tool call (`:status`, `:paid`)

All events carry `%{count: 1}` measurements.

## References

- [MCP transport specification](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md)
- [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
- [Paying for x402 Resources from Elixir](client.html) — the HTTP payer client
- [Plug/Phoenix Integration](plug-integration.html) — the HTTP server half
