defmodule X402.MCP.ServerTest do
  @moduledoc """
  Spec-conformance tests for `X402.MCP.Server` against the x402 MCP transport.

  https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md

  Sections map to protocol concerns:

  * PaymentRequired signaling (isError result with structuredContent +
    content[0].text)
  * PaymentPayload validation (version, accepted matching, extension echo)
  * Facilitator verify/settle + `_meta["x402/payment-response"]`
  * Settlement failure (payment error without tool content)
  * Replay protection and handler failures
  """

  use ExUnit.Case, async: true

  doctest X402.MCP.Server

  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.MCP.Server

  defmodule MockFacilitator do
    @moduledoc false
    use GenServer

    @default_verify {:ok, %{status: 200, body: %{"isValid" => true, "payer" => "0xpayer"}}}

    @default_settle {
      :ok,
      %{
        status: 200,
        body: %{
          "success" => true,
          "transaction" => "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
          "network" => "eip155:84532",
          "payer" => "0x1111111111111111111111111111111111111111"
        }
      }
    }

    def start_link(opts) when is_list(opts), do: GenServer.start_link(__MODULE__, opts)

    def default_settle_body, do: elem(@default_settle, 1).body

    @impl true
    def init(opts) do
      {:ok,
       %{
         owner: Keyword.fetch!(opts, :owner),
         verify: Keyword.get(opts, :verify, @default_verify),
         settle: Keyword.get(opts, :settle, @default_settle)
       }}
    end

    @impl true
    def handle_call({:verify, payment_payload, requirements}, _from, state) do
      send(state.owner, {:verify_called, payment_payload, requirements, nil})
      {:reply, state.verify, state}
    end

    def handle_call({:verify, payment_payload, requirements, hooks_module}, _from, state) do
      send(state.owner, {:verify_called, payment_payload, requirements, hooks_module})
      {:reply, state.verify, state}
    end

    def handle_call({:settle, payment_payload, requirements}, _from, state) do
      send(state.owner, {:settle_called, payment_payload, requirements, nil})
      {:reply, state.settle, state}
    end

    def handle_call({:settle, payment_payload, requirements, hooks_module}, _from, state) do
      send(state.owner, {:settle_called, payment_payload, requirements, hooks_module})
      {:reply, state.settle, state}
    end
  end

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @network "eip155:84532"
  @amount "10000"

  @accept %{
    price: @amount,
    network: @network,
    asset: @asset,
    pay_to: @receiver,
    extra: %{"name" => "USDC", "version" => "2"}
  }

  @requirements %{
    "scheme" => "exact",
    "network" => @network,
    "amount" => @amount,
    "asset" => @asset,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 60,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  defp start_facilitator(opts \\ []) do
    start_supervised!({MockFacilitator, [owner: self()] ++ opts}, id: make_ref())
  end

  defp config(facilitator, overrides \\ []) do
    Server.init(
      Keyword.merge(
        [tool: "premium_search", accepts: [@accept], facilitator: facilitator],
        overrides
      )
    )
  end

  defp payment(overrides \\ %{}) do
    Map.merge(
      %{
        "x402Version" => 2,
        "accepted" => @requirements,
        "payload" => %{"signature" => "0xsignature", "authorization" => %{"value" => @amount}}
      },
      overrides
    )
  end

  defp request(payment_payload) do
    %{
      "name" => "premium_search",
      "arguments" => %{"query" => "x402"},
      "_meta" => %{"x402/payment" => payment_payload}
    }
  end

  defp ok_handler do
    parent = self()

    fn request ->
      send(parent, {:handler_called, request})
      %{"content" => [%{"type" => "text", "text" => "results"}]}
    end
  end

  defp refute_handler do
    parent = self()
    fn _request -> send(parent, :handler_called) end
  end

  # ---------------------------------------------------------------------------
  # init/1
  # ---------------------------------------------------------------------------

  describe "init/1" do
    test "compiles accepts, resource, and extensions" do
      config =
        Server.init(
          tool: "premium_search",
          accepts: [@accept],
          service_name: "Example",
          tags: ["search"],
          icon_url: "https://example.com/icon.png",
          extensions: %{example: %{"info" => %{"required" => true}}}
        )

      assert config.accepts == [@requirements]

      assert config.resource == %{
               "url" => "mcp://tool/premium_search",
               "description" => "Tool: premium_search",
               "mimeType" => "application/json",
               "serviceName" => "Example",
               "tags" => ["search"],
               "iconUrl" => "https://example.com/icon.png"
             }

      assert config.extensions == %{"example" => %{"info" => %{"required" => true}}}
    end

    test "honors resource_url and description overrides" do
      config =
        Server.init(
          tool: "premium_search",
          accepts: [@accept],
          resource_url: "mcp://tool/custom",
          description: "Premium search"
        )

      assert config.resource["url"] == "mcp://tool/custom"
      assert config.resource["description"] == "Premium search"
    end

    test "rejects empty accepts" do
      assert_raise ArgumentError, ~r/at least one payment option/, fn ->
        Server.init(tool: "premium_search", accepts: [])
      end
    end

    test "rejects non-atomic prices" do
      assert_raise NimbleOptions.ValidationError, fn ->
        Server.init(tool: "premium_search", accepts: [%{@accept | price: "$0.10"}])
      end
    end

    test "rejects unsupported payment flows" do
      accept = %{@accept | extra: %{"paymentFlow" => "pre-settlement"}}

      assert_raise ArgumentError, ~r/unsupported payment flow/, fn ->
        Server.init(tool: "premium_search", accepts: [accept])
      end
    end

    test "rejects non-JSON-encodable advertised data" do
      accept = %{@accept | extra: %{"nope" => {:not, :json}}}

      assert_raise ArgumentError, ~r/JSON-encodable/, fn ->
        Server.init(tool: "premium_search", accepts: [accept])
      end
    end

    test "accepts an explicit authorization payment flow" do
      accept = %{@accept | extra: %{"paymentFlow" => "authorization"}}
      config = Server.init(tool: "premium_search", accepts: [accept])

      assert hd(config.accepts)["extra"]["paymentFlow"] == "authorization"
    end

    test "omits empty optional resource fields" do
      config = Server.init(tool: "premium_search", accepts: [@accept], service_name: "")

      refute Map.has_key?(config.resource, "serviceName")
    end

    test "option validators reject invalid raw values" do
      assert Server.validate_extra_map("nope") == {:error, "expected a map"}

      assert Server.validate_atomic_amount(100) ==
               {:error, "expected a digit-only atomic-unit amount"}
    end
  end

  # ---------------------------------------------------------------------------
  # PaymentRequired signaling
  # ---------------------------------------------------------------------------

  describe "payment required signaling" do
    test "returns the spec result when no payment is provided" do
      config = config(start_facilitator())
      request = %{"name" => "premium_search", "arguments" => %{}}

      result = Server.call(request, config, refute_handler())

      assert result["isError"] == true

      assert result["structuredContent"] == %{
               "x402Version" => 2,
               "error" => "Payment required to access this tool",
               "resource" => config.resource,
               "accepts" => [@requirements],
               "extensions" => %{}
             }

      assert [%{"type" => "text", "text" => text}] = result["content"]
      assert Jason.decode!(text) == result["structuredContent"]
      refute_received :handler_called
      refute_received {:verify_called, _payload, _requirements, _hooks}
    end

    test "payment_required_result/2 exposes the advertised result" do
      config = config(start_facilitator())

      result = Server.payment_required_result(config, "Pay up")

      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "Pay up"
      assert result["structuredContent"]["accepts"] == [@requirements]
    end

    test "payment_required_result/1 uses the default message" do
      config = config(start_facilitator())

      result = Server.payment_required_result(config)

      assert result["structuredContent"]["error"] == "Payment required to access this tool"
    end

    test "payment_required_result/2 falls back to an internal error for corrupt configs" do
      config = %{config(start_facilitator()) | extensions: %{"bad" => {:not, :json}}}

      assert Server.payment_required_result(config) == %{
               "isError" => true,
               "content" => [%{"type" => "text", "text" => "Internal server error"}]
             }
    end
  end

  # ---------------------------------------------------------------------------
  # PaymentPayload validation
  # ---------------------------------------------------------------------------

  describe "payment validation" do
    test "rejects non-v2 payloads without contacting the facilitator" do
      config = config(start_facilitator())

      result = Server.call(request(payment(%{"x402Version" => 1})), config, refute_handler())

      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "invalid_x402_version"
      refute_received {:verify_called, _payload, _requirements, _hooks}
      refute_received :handler_called
    end

    test "rejects structurally invalid payloads" do
      config = config(start_facilitator())
      invalid = payment(%{"accepted" => %{"scheme" => "exact"}})

      result = Server.call(request(invalid), config, refute_handler())

      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "invalid_payload"
      refute_received {:verify_called, _payload, _requirements, _hooks}
    end

    test "rejects accepted values that do not match the advertised requirements" do
      config = config(start_facilitator())
      mismatched = payment(%{"accepted" => %{@requirements | "amount" => "1"}})

      result = Server.call(request(mismatched), config, refute_handler())

      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "No matching payment requirements"
      refute_received {:verify_called, _payload, _requirements, _hooks}
    end

    test "rejects accepted values that drop advertised extra entries" do
      config = config(start_facilitator())
      dropped = payment(%{"accepted" => %{@requirements | "extra" => %{"name" => "USDC"}}})

      result = Server.call(request(dropped), config, refute_handler())

      assert result["structuredContent"]["error"] == "No matching payment requirements"
    end

    test "rejects payments that cannot be encoded for the replay claim" do
      config = config(start_facilitator())
      unencodable = payment(%{"payload" => %{"bad" => {:not, :json}}})

      result = Server.call(request(unencodable), config, refute_handler())

      assert result["structuredContent"]["error"] == "invalid_payload"
      refute_received {:verify_called, _payload, _requirements, _hooks}
    end

    test "rejects extension echoes that drop advertised values" do
      extensions = %{"example" => %{"info" => %{"required" => true}}}
      config = config(start_facilitator(), extensions: extensions)
      echo = payment(%{"extensions" => %{"example" => %{"info" => %{}}}})

      result = Server.call(request(echo), config, refute_handler())

      assert result["structuredContent"]["error"] == "invalid_payload"
      refute_received {:verify_called, _payload, _requirements, _hooks}
    end

    test "accepts extension echoes that preserve advertised values" do
      extensions = %{"example" => %{"info" => %{"required" => true}}}
      config = config(start_facilitator(), extensions: extensions)

      echo =
        payment(%{
          "extensions" => %{"example" => %{"info" => %{"required" => true, "client" => "x"}}}
        })

      result = Server.call(request(echo), config, ok_handler())

      refute result["isError"]
      assert_received {:verify_called, _payload, _requirements, _hooks}
    end
  end

  # ---------------------------------------------------------------------------
  # Verify / settle flow
  # ---------------------------------------------------------------------------

  describe "verify and settle" do
    test "verifies, executes, settles, and attaches the receipt to _meta" do
      config = config(start_facilitator())
      payment = payment()

      result = Server.call(request(payment), config, ok_handler())

      assert result["content"] == [%{"type" => "text", "text" => "results"}]
      refute result["isError"]
      assert result["_meta"]["x402/payment-response"] == MockFacilitator.default_settle_body()

      assert_received {:handler_called, %{"arguments" => %{"query" => "x402"}}}
      assert_received {:verify_called, ^payment, @requirements, nil}
      assert_received {:settle_called, ^payment, @requirements, nil}
    end

    test "preserves existing result _meta entries" do
      config = config(start_facilitator())

      handler = fn _request ->
        %{"content" => [], "_meta" => %{"traceId" => "abc"}}
      end

      result = Server.call(request(payment()), config, handler)

      assert result["_meta"]["traceId"] == "abc"
      assert result["_meta"]["x402/payment-response"]["success"] == true
    end

    test "passes a custom hooks module through to the facilitator" do
      defmodule PassthroughHooks do
        @moduledoc false
        @behaviour X402.Hooks

        alias X402.Hooks.Context

        def before_verify(%Context{} = context, _metadata), do: {:cont, context}
        def after_verify(%Context{} = context, _metadata), do: {:cont, context}
        def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
        def before_settle(%Context{} = context, _metadata), do: {:cont, context}
        def after_settle(%Context{} = context, _metadata), do: {:cont, context}
        def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
      end

      config = config(start_facilitator(), hooks: PassthroughHooks)

      Server.call(request(payment()), config, ok_handler())

      assert_received {:verify_called, _payload, _requirements, PassthroughHooks}
      assert_received {:settle_called, _payload, _requirements, PassthroughHooks}
    end

    test "returns the payment-required result with the facilitator's reason on failed verification" do
      facilitator =
        start_facilitator(
          verify: {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "expired"}}}
        )

      config = config(facilitator)

      result = Server.call(request(payment()), config, refute_handler())

      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "expired"
      assert result["structuredContent"]["accepts"] == [@requirements]
      refute_received :handler_called
      refute_received {:settle_called, _payload, _requirements, _hooks}
    end

    test "returns an opaque internal error on facilitator transport failures" do
      facilitator = start_facilitator(verify: {:ok, %{status: 503, body: %{}}})
      config = config(facilitator)

      result = Server.call(request(payment()), config, refute_handler())

      assert result == %{
               "isError" => true,
               "content" => [%{"type" => "text", "text" => "Internal server error"}]
             }
    end

    test "treats malformed verify responses as internal errors" do
      internal_error = %{
        "isError" => true,
        "content" => [%{"type" => "text", "text" => "Internal server error"}]
      }

      for verify <- [
            {:ok, %{status: 200, body: %{"payer" => "0xpayer"}}},
            {:ok, %{status: 200, body: "not a map"}},
            {:ok, %{}}
          ] do
        facilitator = start_facilitator(verify: verify)
        config = config(facilitator)

        assert Server.call(request(payment()), config, refute_handler()) == internal_error
      end
    end

    test "reports a generic reason when verification fails without invalidReason" do
      facilitator = start_facilitator(verify: {:ok, %{status: 200, body: %{"isValid" => false}}})
      config = config(facilitator)

      result = Server.call(request(payment()), config, refute_handler())

      assert result["structuredContent"]["error"] == "facilitator rejected payment"
    end
  end

  # ---------------------------------------------------------------------------
  # Settlement failure
  # ---------------------------------------------------------------------------

  describe "settlement failure" do
    test "returns the payment error without the tool's content" do
      facilitator =
        start_facilitator(
          settle:
            {:ok,
             %{
               status: 200,
               body: %{
                 "success" => false,
                 "errorReason" => "insufficient_funds",
                 "transaction" => "",
                 "network" => @network
               }
             }}
        )

      config = config(facilitator)

      result = Server.call(request(payment()), config, ok_handler())

      assert_received {:handler_called, _request}
      assert result["isError"] == true

      assert result["structuredContent"]["error"] ==
               "Payment settlement failed: insufficient_funds"

      assert [%{"type" => "text", "text" => text}] = result["content"]
      refute text =~ "results"
    end

    test "returns an opaque internal error on malformed settle responses" do
      for settle <- [
            {:ok, %{status: 200, body: %{"success" => true}}},
            {:ok, %{status: 200, body: %{"transaction" => "0xabc"}}},
            {:ok, %{status: 200, body: "not a map"}},
            {:ok, %{status: 500, body: %{}}},
            {:ok, %{}}
          ] do
        facilitator = start_facilitator(settle: settle)
        config = config(facilitator)

        result = Server.call(request(payment()), config, ok_handler())

        assert result["content"] == [%{"type" => "text", "text" => "Internal server error"}]
      end
    end

    test "reports a generic reason when settlement fails without errorReason" do
      facilitator =
        start_facilitator(
          settle:
            {:ok,
             %{status: 200, body: %{"success" => false, "transaction" => "", "network" => "n"}}}
        )

      config = config(facilitator)

      result = Server.call(request(payment()), config, ok_handler())

      assert result["structuredContent"]["error"] ==
               "Payment settlement failed: facilitator rejected payment"
    end
  end

  # ---------------------------------------------------------------------------
  # Handler behavior
  # ---------------------------------------------------------------------------

  describe "handler behavior" do
    test "returns handler error results unchanged without settling" do
      config = config(start_facilitator())

      error_result = %{
        "isError" => true,
        "content" => [%{"type" => "text", "text" => "tool blew up"}]
      }

      result = Server.call(request(payment()), config, fn _request -> error_result end)

      assert result == error_result
      assert_received {:verify_called, _payload, _requirements, _hooks}
      refute_received {:settle_called, _payload, _requirements, _hooks}
    end

    test "raises when the handler returns a non-map" do
      config = config(start_facilitator())

      assert_raise ArgumentError, ~r/tool result map/, fn ->
        Server.call(request(payment()), config, fn _request -> :ok end)
      end
    end

    test "re-raises handler exceptions" do
      config = config(start_facilitator())

      assert_raise RuntimeError, "boom", fn ->
        Server.call(request(payment()), config, fn _request -> raise "boom" end)
      end
    end

    test "re-throws handler throws after releasing the claim" do
      cache =
        start_supervised!({ETSCache, name: :"mcp_throw_#{System.unique_integer([:positive])}"})

      config = config(start_facilitator(), payment_identifier_cache: cache)
      request = request(payment())

      assert catch_throw(Server.call(request, config, fn _request -> throw(:tool_bail) end)) ==
               :tool_bail

      retry = Server.call(request, config, ok_handler())
      assert retry["_meta"]["x402/payment-response"]["success"] == true
    end
  end

  # ---------------------------------------------------------------------------
  # Replay protection
  # ---------------------------------------------------------------------------

  describe "replay protection" do
    setup do
      cache =
        start_supervised!({ETSCache, name: :"mcp_replay_#{System.unique_integer([:positive])}"})

      %{cache: cache}
    end

    test "rejects a second settlement of the same payment", %{cache: cache} do
      config = config(start_facilitator(), payment_identifier_cache: cache)
      request = request(payment())

      first = Server.call(request, config, ok_handler())
      second = Server.call(request, config, refute_handler())

      assert first["_meta"]["x402/payment-response"]["success"] == true
      assert second["isError"] == true
      assert second["structuredContent"]["error"] == "payment already processed"

      assert_received {:settle_called, _payload, _requirements, _hooks}
      refute_received {:settle_called, _payload, _requirements, _hooks}
    end

    test "releases the claim when the handler fails", %{cache: cache} do
      config = config(start_facilitator(), payment_identifier_cache: cache)
      request = request(payment())

      error_result = %{"isError" => true, "content" => []}
      first = Server.call(request, config, fn _request -> error_result end)
      second = Server.call(request, config, ok_handler())

      assert first == error_result
      assert second["_meta"]["x402/payment-response"]["success"] == true
    end

    test "releases the claim when the handler raises", %{cache: cache} do
      config = config(start_facilitator(), payment_identifier_cache: cache)
      request = request(payment())

      assert_raise RuntimeError, fn ->
        Server.call(request, config, fn _request -> raise "boom" end)
      end

      retry = Server.call(request, config, ok_handler())
      assert retry["_meta"]["x402/payment-response"]["success"] == true
    end

    test "releases the claim when settlement fails", %{cache: cache} do
      facilitator =
        start_facilitator(
          settle:
            {:ok,
             %{
               status: 200,
               body: %{
                 "success" => false,
                 "errorReason" => "nope",
                 "transaction" => "",
                 "network" => @network
               }
             }}
        )

      config = config(facilitator, payment_identifier_cache: cache)
      request = request(payment())

      Server.call(request, config, ok_handler())
      second = Server.call(request, config, ok_handler())

      # The claim was released, so the second call reaches settlement again.
      assert_received {:settle_called, _payload, _requirements, _hooks}
      assert_received {:settle_called, _payload, _requirements, _hooks}
      assert second["structuredContent"]["error"] =~ "settlement failed"
    end
  end

  # ---------------------------------------------------------------------------
  # Telemetry
  # ---------------------------------------------------------------------------

  describe "telemetry" do
    test "emits payment lifecycle events" do
      handler_id = "mcp-server-test-#{System.unique_integer([:positive])}"
      parent = self()

      :telemetry.attach_many(
        handler_id,
        [
          [:x402, :mcp, :payment_required],
          [:x402, :mcp, :payment_verified],
          [:x402, :mcp, :payment_rejected]
        ],
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      config = config(start_facilitator())

      Server.call(%{"name" => "premium_search"}, config, refute_handler())

      assert_received {:telemetry, [:x402, :mcp, :payment_required], %{count: 1},
                       %{tool: "premium_search"}}

      Server.call(request(payment()), config, ok_handler())

      assert_received {:telemetry, [:x402, :mcp, :payment_verified], %{count: 1},
                       %{tool: "premium_search"}}

      Server.call(request(payment(%{"x402Version" => 1})), config, refute_handler())

      assert_received {:telemetry, [:x402, :mcp, :payment_rejected], %{count: 1},
                       %{tool: "premium_search", reason: :invalid_x402_version}}
    end
  end
end
