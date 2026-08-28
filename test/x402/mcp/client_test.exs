defmodule X402.MCP.ClientTest do
  use ExUnit.Case, async: true

  doctest X402.MCP.Client

  alias X402.EIP3009
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.MCP
  alias X402.MCP.Client
  alias X402.MCP.Server
  alias X402.Signer.LocalKey

  # A real caller-side X402.Facilitator over a Bypass HTTP stub (the
  # facilitator client executes verify/settle in the calling process).
  defp start_bypass_facilitator(opts) do
    owner = Keyword.fetch!(opts, :owner)
    {:ok, %{status: v_status, body: v_body}} = Keyword.fetch!(opts, :verify)
    {:ok, %{status: s_status, body: s_body}} = Keyword.fetch!(opts, :settle)

    bypass = Bypass.open()

    stub = fn path, tag, status, body ->
      Bypass.stub(bypass, "POST", path, fn conn ->
        {:ok, request_body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(request_body)
        send(owner, {tag, decoded["paymentPayload"], decoded["paymentRequirements"]})
        Plug.Conn.resp(conn, status, Jason.encode!(body))
      end)
    end

    stub.("/verify", :verify_called, v_status, v_body)
    stub.("/settle", :settle_called, s_status, s_body)

    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("mcp_client_finch_#{suffix}")
    name = String.to_atom("mcp_client_facilitator_#{suffix}")

    start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

    start_supervised!(
      {X402.Facilitator,
       name: name,
       finch: finch,
       url: "http://localhost:#{bypass.port}",
       max_retries: 0,
       receive_timeout_ms: 2_000}
    )
  end

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x2222222222222222222222222222222222222222"
  @network "eip155:84532"

  @requirements %{
    "scheme" => "exact",
    "network" => @network,
    "amount" => "10000",
    "asset" => @asset,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  @payment_required %{
    "x402Version" => 2,
    "error" => "Payment required to access this tool",
    "resource" => %{"url" => "mcp://tool/premium_search", "mimeType" => "application/json"},
    "accepts" => [@requirements],
    "extensions" => %{}
  }

  @request %{"name" => "premium_search", "arguments" => %{"query" => "x402"}}

  @ok_result %{"content" => [%{"type" => "text", "text" => "results"}]}

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  defp payment_required_result do
    {:ok, result} = MCP.payment_required_result(@payment_required)
    result
  end

  defp tracking_fun(responses) do
    parent = self()
    {:ok, agent} = Agent.start_link(fn -> responses end)

    fn request ->
      send(parent, {:tool_called, request})
      Agent.get_and_update(agent, fn [head | rest] -> {head, rest} end)
    end
  end

  describe "call/3 without payment required" do
    test "returns the result as-is when the tool is free" do
      call_fun = tracking_fun([@ok_result])

      assert {:ok, %{result: @ok_result, payment_response: nil, paid: false}} =
               Client.call(@request, call_fun, signer: signer())

      assert_received {:tool_called, @request}
      refute_received {:tool_called, _request}
    end

    test "accepts {:ok, result} returns from the tool-call function" do
      call_fun = tracking_fun([{:ok, @ok_result}])

      assert {:ok, %{result: @ok_result, paid: false}} =
               Client.call(@request, call_fun, signer: signer())
    end

    test "propagates transport errors" do
      call_fun = tracking_fun([{:error, :timeout}])

      assert Client.call(@request, call_fun, signer: signer()) ==
               {:error, {:transport_error, :timeout}}
    end

    test "rejects invalid tool results" do
      call_fun = tracking_fun(["nope"])

      assert Client.call(@request, call_fun, signer: signer()) ==
               {:error, :invalid_tool_result}
    end

    test "rejects signers that do not implement X402.Signer" do
      call_fun = tracking_fun([@ok_result])

      assert_raise NimbleOptions.ValidationError, ~r/X402.Signer/, fn ->
        Client.call(@request, call_fun, signer: "not a signer")
      end

      assert_raise NimbleOptions.ValidationError, ~r/X402.Signer/, fn ->
        Client.call(@request, call_fun, signer: %URI{})
      end
    end
  end

  describe "call/3 payment flow" do
    test "signs and retries once with the payment in _meta" do
      paid_result =
        MCP.put_payment_response(@ok_result, %{"success" => true, "network" => @network})

      call_fun = tracking_fun([payment_required_result(), paid_result])
      signer = signer()

      assert {:ok, %{result: result, payment_response: receipt, paid: true}} =
               Client.call(@request, call_fun, signer: signer)

      assert result == paid_result
      assert receipt == %{"success" => true, "network" => @network}

      assert_received {:tool_called, @request}
      assert_received {:tool_called, retried}
      assert retried["name"] == "premium_search"
      assert retried["arguments"] == %{"query" => "x402"}

      assert {:ok, payload} = MCP.fetch_payment(retried)
      assert payload["x402Version"] == 2
      assert payload["accepted"] == @requirements
      assert payload["resource"] == @payment_required["resource"]

      authorization = payload["payload"]["authorization"]
      assert authorization["from"] == signer.address
      assert authorization["to"] == @receiver
      assert authorization["value"] == "10000"

      assert {:ok, domain} = EIP3009.domain(@requirements)
      assert {:ok, digest} = EIP3009.eip712_digest(domain, authorization)

      assert EIP3009.recover_signer(digest, payload["payload"]["signature"]) ==
               {:ok, signer.address}
    end

    test "detects payment-required results carried only in content text" do
      text_only = %{
        "isError" => true,
        "content" => [%{"type" => "text", "text" => Jason.encode!(@payment_required)}]
      }

      call_fun = tracking_fun([text_only, @ok_result])

      assert {:ok, %{result: @ok_result, paid: true}} =
               Client.call(@request, call_fun, signer: signer())
    end

    test "detects payment-required JSON-RPC errors (402 and -32042)" do
      error_402 = {:error, %{"code" => 402, "message" => "pay", "data" => @payment_required}}

      assert {:ok, %{paid: true}} =
               Client.call(@request, tracking_fun([error_402, @ok_result]), signer: signer())

      elicitation =
        {:error,
         %{"code" => -32_042, "message" => "pay", "data" => %{"x402" => @payment_required}}}

      assert {:ok, %{paid: true}} =
               Client.call(@request, tracking_fun([elicitation, @ok_result]), signer: signer())
    end

    test "never pays twice: a second payment-required result is returned as-is" do
      call_fun = tracking_fun([payment_required_result(), payment_required_result()])

      assert {:ok, %{result: second, payment_response: nil, paid: true}} =
               Client.call(@request, call_fun, signer: signer())

      assert second["isError"] == true
      assert_received {:tool_called, _first}
      assert_received {:tool_called, _second}
      refute_received {:tool_called, _third}
    end

    test "refuses to pay for requests that already carry a payment" do
      request = MCP.put_payment(@request, %{"x402Version" => 2, "payload" => %{}})
      call_fun = tracking_fun([payment_required_result()])

      assert Client.call(request, call_fun, signer: signer()) ==
               {:error, :payment_already_attempted}

      assert_received {:tool_called, _first}
      refute_received {:tool_called, _second}
    end

    test "the on_payment_required hook can cancel the payment" do
      parent = self()
      call_fun = tracking_fun([payment_required_result()])

      hook = fn payment_required ->
        send(parent, {:hook_called, payment_required})
        :cancel
      end

      assert Client.call(@request, call_fun, signer: signer(), on_payment_required: hook) ==
               {:error, :payment_cancelled}

      assert_received {:hook_called, @payment_required}
      assert_received {:tool_called, _first}
      refute_received {:tool_called, _second}
    end

    test "any other hook return value continues the payment" do
      call_fun = tracking_fun([payment_required_result(), @ok_result])

      assert {:ok, %{paid: true}} =
               Client.call(@request, call_fun,
                 signer: signer(),
                 on_payment_required: fn _payment_required -> :ok end
               )
    end

    test "selection filters apply to the advertised requirements" do
      call_fun = tracking_fun([payment_required_result()])

      assert Client.call(@request, call_fun, signer: signer(), max_amount: "50") ==
               {:error, :no_acceptable_requirements}
    end

    test "propagates transport errors on the retry" do
      call_fun = tracking_fun([payment_required_result(), {:error, :closed}])

      assert Client.call(@request, call_fun, signer: signer()) ==
               {:error, {:transport_error, :closed}}
    end

    test "normalizes a payment-required JSON-RPC error on the retry to a tool result" do
      rejected_retry =
        {:error, %{"code" => 402, "message" => "still pay", "data" => @payment_required}}

      call_fun = tracking_fun([payment_required_result(), rejected_retry])

      # The rejected paid retry comes back as the payment-required tool
      # result — never re-signed, never surfaced as a transport error.
      assert {:ok, %{result: result, payment_response: nil, paid: true}} =
               Client.call(@request, call_fun, signer: signer())

      assert result["isError"] == true
      assert result["structuredContent"] == @payment_required

      assert_received {:tool_called, _first}
      assert_received {:tool_called, _second}
      refute_received {:tool_called, _third}
    end

    test "rejects invalid tool results on the retry" do
      call_fun = tracking_fun([payment_required_result(), "nope"])

      assert Client.call(@request, call_fun, signer: signer()) ==
               {:error, :invalid_tool_result}
    end
  end

  describe "build_payment_meta/3" do
    test "builds the _meta entries from a PaymentRequired map" do
      signer = signer()

      assert {:ok, meta} = Client.build_payment_meta(@payment_required, signer)
      assert %{"x402/payment" => payload} = meta
      assert payload["accepted"] == @requirements
    end

    test "builds the _meta entries from a payment-required tool result" do
      assert {:ok, %{"x402/payment" => payload}} =
               Client.build_payment_meta(payment_required_result(), signer())

      assert payload["accepted"] == @requirements
    end

    test "propagates selection errors" do
      assert Client.build_payment_meta(@payment_required, signer(), max_amount: "1") ==
               {:error, :no_acceptable_requirements}
    end
  end

  describe "call/3 telemetry" do
    test "emits [:x402, :mcp, :call]" do
      handler_id = "mcp-client-test-#{System.unique_integer([:positive])}"
      parent = self()

      :telemetry.attach(
        handler_id,
        [:x402, :mcp, :call],
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      Client.call(@request, tracking_fun([@ok_result]), signer: signer())

      assert_received {:telemetry, [:x402, :mcp, :call], %{count: 1}, %{status: :ok, paid: false}}

      Client.call(@request, tracking_fun([{:error, :timeout}]), signer: signer())

      assert_received {:telemetry, [:x402, :mcp, :call], %{count: 1},
                       %{status: :error, reason: {:transport_error, :timeout}}}
    end
  end

  # ---------------------------------------------------------------------------
  # Full client ⇄ server loop
  # ---------------------------------------------------------------------------

  describe "client-server loop" do
    setup do
      facilitator =
        start_bypass_facilitator(
          owner: self(),
          verify: {:ok, %{status: 200, body: %{"isValid" => true}}},
          settle:
            {:ok,
             %{
               status: 200,
               body: %{
                 "success" => true,
                 "transaction" => "0x" <> String.duplicate("ab", 32),
                 "network" => @network,
                 "payer" => "0x3333333333333333333333333333333333333333"
               }
             }}
        )

      cache =
        start_supervised!({ETSCache, name: :"mcp_loop_#{System.unique_integer([:positive])}"})

      config =
        Server.init(
          tool: "premium_search",
          accepts: [
            %{
              price: "10000",
              network: @network,
              asset: @asset,
              pay_to: @receiver,
              max_timeout_seconds: 300,
              extra: %{"name" => "USDC", "version" => "2"}
            }
          ],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )

      %{config: config}
    end

    test "the client pays for a wrapped tool end to end", %{config: config} do
      parent = self()
      signer = signer()

      handler = fn request ->
        send(parent, {:handler_called, request})
        @ok_result
      end

      call_fun = fn request ->
        send(parent, {:tool_called, request})
        Server.call(request, config, handler)
      end

      assert {:ok, %{result: result, payment_response: receipt, paid: true}} =
               Client.call(@request, call_fun, signer: signer, max_amount: "10000")

      assert result["content"] == [%{"type" => "text", "text" => "results"}]
      assert receipt["success"] == true
      assert receipt["transaction"] == "0x" <> String.duplicate("ab", 32)

      # Exactly two tool calls: the unpaid probe and the paid retry.
      assert_received {:tool_called, _first}
      assert_received {:tool_called, _second}
      refute_received {:tool_called, _third}

      # The handler ran exactly once, for the paid call.
      assert_received {:handler_called, _request}
      refute_received {:handler_called, _request}

      # The facilitator verified and settled the signed payment once.
      assert_received {:verify_called, payload, requirements}
      assert payload["payload"]["authorization"]["from"] == signer.address
      assert requirements["payTo"] == @receiver
      assert_received {:settle_called, _payload, _requirements}
      refute_received {:verify_called, _payload, _requirements}
    end

    test "a rejected payment is surfaced without paying twice", %{config: config} do
      facilitator =
        start_bypass_facilitator(
          owner: self(),
          verify: {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "bad"}}},
          settle: {:ok, %{status: 200, body: %{}}}
        )

      config = %{config | facilitator: facilitator}
      parent = self()

      call_fun = fn request ->
        send(parent, {:tool_called, request})
        Server.call(request, config, fn _request -> @ok_result end)
      end

      assert {:ok, %{result: result, payment_response: nil, paid: true}} =
               Client.call(@request, call_fun, signer: signer())

      # The retry's payment was rejected: the server re-advertises payment
      # required and the client returns it as-is instead of signing again.
      assert result["isError"] == true
      assert result["structuredContent"]["error"] == "bad"

      assert_received {:tool_called, _first}
      assert_received {:tool_called, _second}
      refute_received {:tool_called, _third}
      assert_received {:verify_called, _payload, _requirements}
      refute_received {:settle_called, _payload, _requirements}
    end
  end
end
