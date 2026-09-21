defmodule X402.AuthCapture.TransportTest do
  use ExUnit.Case, async: true

  import Plug.Conn

  alias X402.AuthCapture.Resource
  alias X402.AuthCapture.Transport
  alias X402.Extensions.PaymentIdentifier
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.MCP
  alias X402.MCP.Server
  alias X402.PaymentResponse
  alias X402.Plug.PaymentGate
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCaptureNode, as: Node

  defmodule SkipPayment do
    @moduledoc false
    @behaviour X402.Hooks
    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default
    def on_protected_request(_context, _metadata), do: {:halt, :skip_payment}
  end

  defmodule TransientSigner do
    @moduledoc false
    @behaviour X402.Signer
    defstruct [:inner, :attempts]
    def address(signer), do: X402.Signer.address(signer.inner)

    def sign_eip712(signer, digest, data) do
      case Agent.get_and_update(signer.attempts, fn n -> {n, n + 1} end) do
        0 -> {:error, :temporarily_unavailable}
        _next -> X402.Signer.sign_eip712(signer.inner, digest, data)
      end
    end
  end

  setup context do
    mode = Map.get(context, :mode, :sync)
    ctx = Node.setup(__MODULE__, mode)
    Agent.update(ctx.node, &%{&1 | advance_state: true})
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: ctx.authorizer, mode: mode)
    cache = start_supervised!({ETSCache, name: nil})
    Map.merge(ctx, %{resource: resource, cache: cache})
  end

  test "Plug confirms funding before callbacks and sends only settled metered output", ctx do
    handler = fn conn ->
      assert Agent.get(ctx.node, & &1.sends) == 1
      assert conn.assigns.x402_payment_requirements == ctx.requirements

      conn
      |> register_before_send(fn ready ->
        send(self(), :callback)
        {:ok, ready} = PaymentGate.put_settlement_amount(ready, 750_000)
        ready |> put_resp_header("x-paid", "yes") |> put_resp_cookie("paid", "yes")
      end)
      |> send_resp(201, <<0, 255, 1>>)
    end

    conn = paid_conn(ctx.envelope)
    result = PaymentGate.call(conn, gate(ctx, handler))
    assert result.halted
    assert {201, headers, <<0, 255, 1>>} = Plug.Test.sent_resp(result)
    assert {"x-paid", "yes"} in headers
    assert length(Enum.filter(headers, &(elem(&1, 0) == "set-cookie"))) == 1
    assert_received :callback
    refute_received :callback
    assert Agent.get(ctx.node, & &1.sends) == 3

    assert {:ok, receipt} =
             PaymentResponse.decode(hd(get_resp_header(result, "payment-response")))

    assert receipt["amount"] == "750000"
    assert receipt["settlementStatus"] == "settled"
    assert receipt["paymentInfoHash"] == ctx.payment_info_hash
  end

  test "Plug withholds all paid output and callbacks during pending funding", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
    config = gate(ctx, fn _ -> flunk("pending hold") end)
    result = PaymentGate.call(paid_conn(ctx.envelope), config)
    assert {503, _, "{}"} = Plug.Test.sent_resp(result)
    assert get_resp_header(result, "payment-response") == []
    assert result.halted
    assert Agent.get(ctx.node, & &1.sends) == 1

    assert Resource.resume(ctx.resource, ctx.payment_info_hash) ==
             {:pending, ctx.payment_info_hash}
  end

  for outcome <- [:success, :exception, :pending] do
    @tag adapter_outcome: outcome
    test "Plug keeps the updated body adapter after #{outcome}", ctx do
      config =
        gate(ctx, fn conn ->
          {:ok, "request body", conn} = read_body(conn)

          case ctx.adapter_outcome do
            :exception -> raise "after reading body"
            :pending -> Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
            :success -> :ok
          end

          {:ok, conn} = PaymentGate.put_settlement_amount(conn, 0)
          resp(conn, 200, "paid")
        end)

      conn =
        Plug.Test.conn(:get, "/paid", "request body")
        |> put_req_header("payment-signature", header(ctx.envelope))

      result = PaymentGate.call(conn, config)
      assert {:ok, "", _} = read_body(result)
      assert result.status == %{success: 200, exception: 500, pending: 503}[ctx.adapter_outcome]
    end
  end

  test "canonical replay identity ignores encoding, metadata and unsigned alternatives", ctx do
    {:ok, key} = Transport.replay_key(ctx.envelope["payload"], ctx.requirements)

    changed =
      ctx.envelope["payload"]
      |> Map.put("ignored", "metadata")
      |> update_in(
        ["authorization", "nonce"],
        &("0x" <> String.upcase(String.slice(&1, 2..-1//1)))
      )
      |> update_in(
        ["authorization", "from"],
        &("0x" <> String.upcase(String.slice(&1, 2..-1//1)))
      )

    assert Transport.replay_key(changed, ctx.requirements) == {:ok, key}

    permit =
      Enum.find(
        Fixture.fixture()["vectors"],
        &(&1["requirements"]["extra"]["assetTransferMethod"] == "permit2")
      )

    {:ok, permit_key} = Transport.replay_key(permit["payload"], permit["requirements"])

    altered =
      permit["payload"]
      |> Map.put("authorization", ctx.envelope["payload"]["authorization"])
      |> update_in(["permit2Authorization", "nonce"], &String.to_integer/1)

    assert Transport.replay_key(altered, permit["requirements"]) == {:ok, permit_key}
    assert Transport.replay_key(nil, ctx.requirements) == :error
    assert Transport.replay_key(%{}, ctx.requirements) == :error
  end

  test "pending re-encodings cannot consume extra verified limiter hits", ctx do
    test = self()
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})

    config =
      gate(ctx, fn _ -> flunk("pending") end,
        rate_limit: [
          limit: 2,
          window_ms: 60_000,
          key: fn _ ->
            send(test, :limiter_hit)
            {:unique, test}
          end
        ]
      )

    assert PaymentGate.call(paid_conn(ctx.envelope), config).status == 503
    assert_received :limiter_hit
    replay = Map.put(ctx.envelope, "ignored", true)
    assert PaymentGate.call(paid_conn(replay), config).status in [400, 402, 500]
    refute_received :limiter_hit
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  for transport <- [:plug, :mcp] do
    @tag transient_transport: transport
    test "#{transport} releases claims when consent preparation never reached admission", ctx do
      attempts = start_supervised!({Agent, fn -> 0 end})
      signer = %TransientSigner{inner: ctx.authorizer, attempts: attempts}
      {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: signer)
      ctx = %{ctx | resource: resource}
      key = "authcap_transient_01"
      ext = %{"payment-identifier" => PaymentIdentifier.extension(required: true)}

      envelope =
        Map.put(
          ctx.envelope,
          "extensions",
          put_in(ext, ["payment-identifier", "info", "id"], key)
        )

      if ctx.transient_transport == :plug do
        config =
          gate(ctx, fn conn ->
            {:ok, conn} = PaymentGate.put_settlement_amount(conn, 0)
            resp(conn, 200, "paid")
          end)

        [route] = config.routes
        config = %{config | routes: [%{route | extensions: ext}]}
        assert PaymentGate.call(paid_conn(envelope), config).status == 500
        assert Resource.resume(resource, ctx.payment_info_hash) == {:error, :unknown_payment}
        assert ETSCache.get(ctx.cache, "pid:" <> key) == :miss
        assert PaymentGate.call(paid_conn(envelope), config).status == 200
      else
        config = mcp(ctx, extensions: ext)
        request = MCP.put_payment(%{"name" => "paid"}, envelope)
        handler = fn _ -> {:ok, %{"content" => []}, 0} end
        assert Server.call(request, config, handler)["isError"]
        assert Resource.resume(resource, ctx.payment_info_hash) == {:error, :unknown_payment}
        assert ETSCache.get(ctx.cache, "pid:" <> key) == :miss
        assert {:ok, _} = MCP.fetch_payment_response(Server.call(request, config, handler))
      end

      assert Agent.get(ctx.node, & &1.sends) == 2
    end
  end

  test "Plug withholds handler headers and body when capture remains pending", ctx do
    config =
      gate(ctx, fn conn ->
        Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
        {:ok, conn} = PaymentGate.put_settlement_amount(conn, 750_000)

        conn
        |> put_resp_header("x-secret", "secret")
        |> put_resp_cookie("private", "secret")
        |> resp(200, "private content")
      end)

    result = PaymentGate.call(paid_conn(ctx.envelope), config)
    assert {503, headers, "{}"} = Plug.Test.sent_resp(result)
    refute Enum.any?(headers, &(elem(&1, 0) in ["x-secret", "set-cookie", "payment-response"]))
    assert Agent.get(ctx.node, & &1.sends) == 2
    Agent.update(ctx.node, &%{&1 | receipt_mode: :confirmed})

    assert {:ok, %{"body" => body}, %{status: :settled}} =
             Resource.resume(ctx.resource, ctx.payment_info_hash)

    assert Base.decode64!(body) == "private content"
    assert Agent.get(ctx.node, & &1.sends) == 3
  end

  for kind <- [:failure, :no_meter, :stream, :overcharge, :exception] do
    @tag failure_kind: kind
    test "Plug never returns paid output for #{kind}", ctx do
      kind = ctx.failure_kind

      config =
        gate(ctx, fn conn ->
          bad_response(conn, kind)
        end)

      result = PaymentGate.call(paid_conn(ctx.envelope), config)
      assert {500, _, "{}"} = Plug.Test.sent_resp(result)
      assert get_resp_header(result, "payment-response") == []
      assert Agent.get(ctx.node, & &1.sends) == if(kind in [:failure, :no_meter], do: 2, else: 1)
    end
  end

  test "verified limiter rejects before funding and releases attempt claims", ctx do
    test = self()

    config =
      gate(ctx, fn _ -> flunk("limited") end,
        rate_limit: [
          limit: 1,
          window_ms: 60_000,
          key: fn context ->
            send(test, {:verified_payer, context.payer})
            {:auth_capture_limiter, test}
          end
        ]
      )

    assert {:allow, _} = X402.RateLimiter.check(config.rate_limit, {:auth_capture_limiter, test})
    result = PaymentGate.call(paid_conn(ctx.envelope), config)
    assert result.status == 429
    assert_received {:verified_payer, payer}
    assert payer == ctx.envelope["payload"]["authorization"]["from"]
    assert Agent.get(ctx.node, & &1.sends) == 0

    handler = fn conn ->
      {:ok, conn} = PaymentGate.put_settlement_amount(conn, 0)
      resp(conn, 200, "retry")
    end

    allowed = %{config | rate_limit: nil, auth_capture: %{config.auth_capture | handler: handler}}
    result = PaymentGate.call(paid_conn(ctx.envelope), allowed)
    assert {200, _, "retry"} = Plug.Test.sent_resp(result)
  end

  test "bad consent does not consume a verified-payer limiter hit", ctx do
    test = self()

    config =
      gate(ctx, fn _ -> flunk("forged") end,
        rate_limit: [
          limit: 1,
          window_ms: 60_000,
          key: fn _ ->
            send(test, :limited)
            :payer
          end
        ]
      )

    forged = put_in(ctx.envelope, ["payload", "signature"], "0x" <> String.duplicate("00", 65))
    result = PaymentGate.call(paid_conn(forged), config)
    assert result.status in [400, 402]
    refute_received :limited
    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "MCP confirms and meters tool output and rejects durable replay", ctx do
    config = mcp(ctx)
    request = MCP.put_payment(%{"name" => "paid"}, ctx.envelope)

    result =
      Server.call(request, config, fn _ ->
        assert Agent.get(ctx.node, & &1.sends) == 1
        {:ok, %{"content" => [%{"type" => "text", "text" => "paid"}]}, 750_000}
      end)

    assert result["content"] == [%{"type" => "text", "text" => "paid"}]

    assert {:ok, %{"amount" => "750000", "settlementStatus" => "settled"}} =
             MCP.fetch_payment_response(result)

    replay = put_in(request, ["_meta", "x402/payment", "ignored"], true)
    assert Server.call(replay, config, fn _ -> flunk("replayed") end)["isError"]
    assert Agent.get(ctx.node, & &1.sends) == 3
  end

  test "MCP pending, malformed output and tool failures disclose no paid content", ctx do
    config = mcp(ctx)
    request = MCP.put_payment(%{"name" => "paid"}, ctx.envelope)

    result =
      Server.call(request, config, fn _ ->
        {:ok, %{"isError" => true, "content" => [%{"text" => "private"}]}, 750_000}
      end)

    assert result["isError"]
    assert result["content"] == [%{"type" => "text", "text" => "Internal server error"}]
    assert MCP.fetch_payment_response(result) == :error
    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  @tag mode: :deferred
  test "deferred MCP and Plug outputs are explicitly unsettled and recoverable", ctx do
    config = mcp(ctx)
    request = MCP.put_payment(%{"name" => "paid"}, ctx.envelope)
    result = Server.call(request, config, fn _ -> {:ok, %{"content" => []}, 750_000} end)
    assert {:ok, %{"settlementStatus" => "deferred"}} = MCP.fetch_payment_response(result)
    assert Agent.get(ctx.node, & &1.sends) == 1
    assert {:ok, _, %{status: :settled}} = Resource.resume(ctx.resource, ctx.payment_info_hash)
    assert Agent.get(ctx.node, & &1.sends) == 3
  end

  test "missing payment challenges never enter local execution", ctx do
    result =
      PaymentGate.call(Plug.Test.conn(:get, "/paid"), gate(ctx, fn _ -> flunk("unpaid") end))

    assert result.status == 402

    assert {:ok, challenge} =
             MCP.fetch_payment_required(
               Server.call(%{"name" => "paid"}, mcp(ctx), fn _ -> flunk("unpaid") end)
             )

    assert challenge["accepts"] == [ctx.requirements]
    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "unpaid hooks unwrap metered MCP handlers without touching escrow", ctx do
    config = mcp(ctx, hooks: SkipPayment)
    result = %{"content" => []}
    assert Server.call(%{"name" => "paid"}, config, fn _ -> {:ok, result, 10} end) == result
    assert Server.call(%{"name" => "paid"}, config, fn _ -> result end) == result
    assert Server.call(%{"name" => "paid"}, config, fn _ -> {:error, :private} end)["isError"]
    refute_received {:auth_rpc, _, _}
    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "identifier conflicts stay bound to the server-owned tool", ctx do
    ext = %{"payment-identifier" => PaymentIdentifier.extension(required: true)}

    envelope =
      Map.put(ctx.envelope, "extensions", %{
        "payment-identifier" =>
          put_in(ext["payment-identifier"], ["info", "id"], "authcap_payment_01")
      })

    config = mcp(ctx, extensions: ext)

    result =
      Server.call(MCP.put_payment(%{"name" => "paid"}, envelope), config, fn _ ->
        {:ok, %{"content" => []}, 0}
      end)

    assert {:ok, _} = MCP.fetch_payment_response(result)
    other = %{config | tool: "different"}

    result =
      Server.call(MCP.put_payment(%{"name" => "different"}, envelope), other, fn _ ->
        flunk("conflicting identifier")
      end)

    assert {:ok, %{"error" => "payment_identifier_conflict"}} = MCP.fetch_payment_required(result)
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

  @spec bad_response(Plug.Conn.t(), atom()) :: Plug.Conn.t()
  defp bad_response(conn, :failure), do: resp(conn, 500, "private error")
  defp bad_response(conn, :no_meter), do: resp(conn, 200, "unmetered")
  defp bad_response(conn, :stream), do: send_chunked(conn, 200)

  defp bad_response(conn, :overcharge) do
    {:ok, conn} = PaymentGate.put_settlement_amount(conn, 1_000_001)
    resp(conn, 200, "overcharge")
  end

  defp bad_response(_conn, :exception), do: raise("private error")

  @spec gate(map(), function(), keyword()) :: map()
  defp gate(ctx, handler, opts \\ []) do
    PaymentGate.init(
      [
        routes: [%{method: :get, path: "/paid", accepts: [accept(ctx)]}],
        payment_identifier_cache: ctx.cache,
        auth_capture: [resource: ctx.resource, handler: handler]
      ] ++ opts
    )
  end

  @spec mcp(map(), keyword()) :: map()
  defp mcp(ctx, opts \\ []) do
    Server.init(
      [
        tool: "paid",
        accepts: [accept(ctx)],
        payment_identifier_cache: ctx.cache,
        auth_capture_resource: ctx.resource
      ] ++ opts
    )
  end

  @spec header(map()) :: binary()
  defp header(envelope), do: envelope |> Jason.encode!() |> Base.encode64()
  @spec paid_conn(map()) :: Plug.Conn.t()
  defp paid_conn(envelope),
    do: Plug.Test.conn(:get, "/paid") |> put_req_header("payment-signature", header(envelope))
end
