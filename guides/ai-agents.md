# x402 for AI Agents

An x402 payer signs a payment for a single request and retries it once. An
autonomous agent that calls paid HTTP routes or paid MCP tools needs the same
payment flow, plus limits on what it may spend and a record of what it spent.
This guide covers the payer side. The server side is in
[Paid MCP Tools](mcp.html) and
[Plug/Phoenix Integration](plug-integration.html).

## What an agent can pay for

- **Paid HTTP routes.** `X402.Client.Finch.request/3` performs the request, pays
  on HTTP 402, and retries once. See [Paying for Resources](client.html).
- **Paid MCP tools.** `X402.MCP.Client.call/3` drives any MCP tool-call function
  through the same detect, sign, and retry loop. See [Paid MCP Tools](mcp.html).

Both calls sign with a signer you provide. The SDK does not create, store, or
custody keys. Load the signer key from a secret store or runtime configuration:

```elixir
{:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("AGENT_PAYER_KEY"))
```

## Set limits before the first payment

An agent signs whatever a server offers unless you constrain it. The options
below compose:

- `:max_amount` caps one payment in atomic units. Options above it are never
  selected.
- `:policies` restricts which options are acceptable, for example by network,
  asset, scheme, or receiver. `X402.Client.Policy` provides common policies.
- `:budget` caps total spend across requests. Create the budget process with
  `X402.Client.Budget.start_link/1`, which takes a total `:limit` and optional
  `:per_asset` limits in atomic units:

  ```elixir
  {:ok, budget} =
    X402.Client.Budget.start_link(
      limit: "5000000",
      per_asset: %{"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" => "5000000"}
    )

  X402.Client.Finch.request(MyApp.Finch, "https://api.example.com/api/data",
    signer: signer,
    max_amount: "10000",
    budget: budget
  )
  ```

  The selected amount is reserved against the budget before the paid retry is
  sent. `X402.Client.Budget.spent/1` returns the totals so far.
- `:on_payment_required` is a consent hook. It receives the decoded
  `PaymentRequired` map before anything is signed. Return `:cancel` to stop with
  `{:error, :payment_cancelled}`.

When none of `:max_amount`, `:policies`, or `:budget` is set, the Finch client and
the MCP client log a warning once per VM. Set at least one of them for an agent
that runs unattended.

## A paid tool call

`X402.MCP.Client.call/3` takes the tool request and a function that performs the
tool call. The function receives the request map and returns the tool result:

```elixir
request = %{"name" => "premium_search", "arguments" => %{"query" => "x402"}}

{:ok, %{result: result, payment_response: receipt, paid: paid?}} =
  X402.MCP.Client.call(request, &MyMCP.call_tool/1,
    signer: signer,
    max_amount: "10000",
    budget: budget,
    on_payment_required: fn payment_required ->
      if MyApp.Policy.approve?(payment_required), do: :ok, else: :cancel
    end
  )
```

The client never pays for the same call twice. It makes at most one payment
retry. A second payment-required result is returned as it is, so the agent sees
the failure and does not sign again.

## Watch what the agent spends

Attach telemetry handlers to the client events to record each step:

- `[:x402, :client, :select]` when a payment option is chosen
- `[:x402, :client, :sign]` when a payment is signed
- `[:x402, :client, :request]` for each paid request
- `[:x402, :client, :siwx]` when a Sign-In-With-X proof is returned

The `X402.Telemetry` module lists every event and its metadata. Keep the
handler short. Telemetry handlers run in the calling process.

## Limits of the SDK

- The SDK signs and retries. It does not decide whether a purchase is a good
  idea. Your policies, budgets, and consent hooks make that decision.
- A budget is a single process. The SDK does not share one budget across nodes.
