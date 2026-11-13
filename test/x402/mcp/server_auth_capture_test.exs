defmodule X402.MCP.ServerAuthCaptureTest do
  @moduledoc """
  `X402.MCP.Server` with auth-capture (escrow) payments: handler result
  shapes the server refuses to meter, and payments whose signed material
  cannot yield a replay identity.
  """

  use ExUnit.Case, async: true

  alias X402.AuthCapture.Resource
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.MCP
  alias X402.MCP.Server
  alias X402.TestAuthCaptureNode, as: Node

  @internal_error %{
    "isError" => true,
    "content" => [%{"type" => "text", "text" => "Internal server error"}]
  }

  setup do
    ctx = Node.setup(__MODULE__, :sync)
    Agent.update(ctx.node, &%{&1 | advance_state: true})
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: ctx.authorizer, mode: :sync)
    cache = start_supervised!({ETSCache, name: nil})
    handler_id = "mcp-auth-capture-#{System.unique_integer([:positive])}"
    parent = self()

    :telemetry.attach(
      handler_id,
      [:x402, :mcp, :payment_rejected],
      fn _event, _measurements, metadata, _config -> send(parent, {:rejected, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    Map.merge(ctx, %{resource: resource, cache: cache})
  end

  test "a handler that returns an error tuple discloses no paid content", ctx do
    config = mcp(ctx)
    request = MCP.put_payment(%{"name" => "paid"}, ctx.envelope)

    result = Server.call(request, config, fn _ -> {:error, :tool_failed} end)

    assert result == @internal_error
    assert MCP.fetch_payment_response(result) == :error
  end

  test "a handler that returns anything but a metered result discloses no paid content", ctx do
    config = mcp(ctx)
    request = MCP.put_payment(%{"name" => "paid"}, ctx.envelope)

    result =
      Server.call(request, config, fn _ ->
        %{"content" => [%{"type" => "text", "text" => "unmetered"}]}
      end)

    assert result == @internal_error
    assert MCP.fetch_payment_response(result) == :error
  end

  test "a payment from the zero address has no replay identity", ctx do
    config = mcp(ctx)

    envelope =
      put_in(
        ctx.envelope,
        ["payload", "authorization", "from"],
        "0x0000000000000000000000000000000000000000"
      )

    request = MCP.put_payment(%{"name" => "paid"}, envelope)

    result = Server.call(request, config, fn _ -> flunk("unauthorized payment executed") end)

    assert {:ok, %{"error" => "invalid_payload"}} = MCP.fetch_payment_required(result)
    assert_received {:rejected, %{tool: "paid", reason: :invalid_payload}}
  end

  @spec accept(map()) :: map()
  defp accept(ctx) do
    req = ctx.requirements

    %{
      scheme: req["scheme"],
      network: req["network"],
      price: req["amount"],
      asset: req["asset"],
      pay_to: req["payTo"],
      max_timeout_seconds: req["maxTimeoutSeconds"],
      extra: req["extra"]
    }
  end

  @spec mcp(map()) :: map()
  defp mcp(ctx) do
    Server.init(
      tool: "paid",
      accepts: [accept(ctx)],
      payment_identifier_cache: ctx.cache,
      auth_capture_resource: ctx.resource
    )
  end
end
