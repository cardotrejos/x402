defmodule X402.Plug.PaymentGateTest do
  @moduledoc """
  Spec-aligned tests for `X402.Plug.PaymentGate` against x402 v2.

  https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

  Sections map to protocol concerns:

  * Route matching (HTTP method/path)
  * PaymentRequired signaling (402 + PAYMENT-REQUIRED header)
  * PaymentPayload validation and accepted matching
  * HTTP status mapping (400 invalid request vs 402 payment required/failed)
  * Facilitator verify/settle + PAYMENT-RESPONSE
  * Multi-accept routes
  * ResourceInfo / extensions
  * Lifecycle hooks and telemetry
  """

  use ExUnit.Case, async: false
  import Plug.Conn
  import Plug.Test

  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.Plug.PaymentGate

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

    def start_link(opts) when is_list(opts) do
      GenServer.start_link(__MODULE__, opts)
    end

    @impl true
    def init(opts) do
      state = %{
        owner: Keyword.fetch!(opts, :owner),
        verify: Keyword.get(opts, :verify, @default_verify),
        settle: Keyword.get(opts, :settle, @default_settle)
      }

      {:ok, state}
    end

    @impl true
    def handle_call({:verify, payment_payload, requirements}, _from, state) do
      handle_verify_call(payment_payload, requirements, nil, state)
    end

    def handle_call({:verify, payment_payload, requirements, hooks_module}, _from, state) do
      handle_verify_call(payment_payload, requirements, hooks_module, state)
    end

    def handle_call({:settle, payment_payload, requirements}, _from, state) do
      handle_settle_call(payment_payload, requirements, nil, state)
    end

    def handle_call({:settle, payment_payload, requirements, hooks_module}, _from, state) do
      handle_settle_call(payment_payload, requirements, hooks_module, state)
    end

    defp resolve_result(result, _payment_payload, _requirements) when is_tuple(result), do: result

    defp resolve_result(result_fun, payment_payload, requirements)
         when is_function(result_fun, 2) do
      result_fun.(payment_payload, requirements)
    end

    defp handle_verify_call(payment_payload, requirements, hooks_module, state) do
      send(state.owner, {:verify_called, payment_payload, requirements, hooks_module})
      {:reply, resolve_result(state.verify, payment_payload, requirements), state}
    end

    defp handle_settle_call(payment_payload, requirements, hooks_module, state) do
      send(state.owner, {:settle_called, payment_payload, requirements, hooks_module})
      {:reply, resolve_result(state.settle, payment_payload, requirements), state}
    end
  end

  defmodule TrackingHooks do
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

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @network "eip155:84532"
  @amount "10000"

  @route %{
    method: :get,
    path: "/api/resource",
    price: @amount,
    network: @network,
    asset: @asset,
    pay_to: @receiver
  }

  @upto_route Map.put(@route, :scheme, "upto")

  # ---------------------------------------------------------------------------
  # Route matching
  # ---------------------------------------------------------------------------

  describe "route matching" do
    test "passes through non-gated routes" do
      conn = run_request(conn(:get, "/public"), routes: [@route], facilitator: self())

      assert conn.status == 200
      assert conn.resp_body == "ok"
      assert get_resp_header(conn, "payment-required") == []
    end

    test "matches exact paths with normalized trailing slash" do
      conn = run_request(conn(:get, "/api/resource/"), routes: [@route], facilitator: self())
      required = decode_payment_required!(conn)

      assert conn.status == 402
      assert required["resource"]["url"] =~ "/api/resource"
    end

    test "matches glob routes" do
      route = Map.put(@route, :path, "/api/*")
      conn = run_request(conn(:get, "/api/v1/items"), routes: [route], facilitator: self())

      assert conn.status == 402
      assert get_resp_header(conn, "payment-required") != []
    end

    test "filters by method and supports :any" do
      post_route = Map.put(@route, :method, :post)
      any_route = %{post_route | method: :any, path: "/any"}

      pass = run_request(conn(:get, "/api/resource"), routes: [post_route], facilitator: self())
      gated = run_request(conn(:put, "/any"), routes: [any_route], facilitator: self())

      assert pass.status == 200
      assert gated.status == 402
    end

    test "first matching route wins" do
      route1 = Map.put(@route, :path, "/api/resource")
      route2 = Map.put(@route, :path, "/api/*")

      conn =
        run_request(conn(:get, "/api/resource"), routes: [route1, route2], facilitator: self())

      required = decode_payment_required!(conn)
      assert required["resource"]["url"] =~ "/api/resource"
    end

    test "normalizes root path and unknown methods via :any" do
      root = Map.put(@route, :path, "/")
      assert run_request(conn(:get, "/"), routes: [root], facilitator: self()).status == 402

      any = Map.put(@route, :method, :any)

      assert run_request(Plug.Test.conn("PURGE", "/api/resource"),
               routes: [any],
               facilitator: self()
             ).status == 402
    end

    test "supports all standard HTTP methods" do
      for {method_string, method_atom} <- [
            {"DELETE", :delete},
            {"HEAD", :head},
            {"OPTIONS", :options},
            {"PATCH", :patch},
            {"POST", :post},
            {"PUT", :put},
            {"TRACE", :trace}
          ] do
        route = Map.put(@route, :method, method_atom)

        conn =
          run_request(Plug.Test.conn(method_string, "/api/resource"),
            routes: [route],
            facilitator: self()
          )

        assert conn.status == 402
      end
    end
  end

  # ---------------------------------------------------------------------------
  # PaymentRequired (402 signaling) — §5.1 + HTTP transport
  # ---------------------------------------------------------------------------

  describe "PaymentRequired response (402)" do
    test "emits PAYMENT-REQUIRED header with full v2 PaymentRequired schema" do
      conn = run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: self())
      required = decode_payment_required!(conn)
      [accept] = required["accepts"]

      assert conn.status == 402
      assert conn.resp_body == "{}"
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]

      assert required["x402Version"] == 2
      assert required["error"] == "PAYMENT-SIGNATURE header is required"
      assert is_map(required["resource"])
      assert required["resource"]["url"] =~ "/api/resource"
      assert required["resource"]["description"] == "Payment required"
      assert required["resource"]["mimeType"] == "application/json"
      assert required["extensions"] == %{}

      assert accept["scheme"] == "exact"
      assert accept["network"] == @network
      assert accept["amount"] == @amount
      assert accept["asset"] == @asset
      assert accept["payTo"] == @receiver
      assert accept["maxTimeoutSeconds"] == 60
      assert accept["extra"] == %{}

      # v2: amount not maxAmountRequired; resource not nested under accepts
      refute Map.has_key?(accept, "maxAmountRequired")
      refute Map.has_key?(accept, "resource")
    end

    test "upto scheme advertises amount as max authorized amount" do
      conn = run_request(conn(:get, "/api/resource"), routes: [@upto_route], facilitator: self())
      [accept] = decode_payment_required!(conn)["accepts"]

      assert accept["scheme"] == "upto"
      assert accept["amount"] == @amount
      refute Map.has_key?(accept, "maxPrice")
      refute Map.has_key?(accept, "maxAmountRequired")
    end

    test "includes optional ResourceInfo fields and extensions" do
      route =
        Map.merge(@route, %{
          description: "Premium market data",
          mime_type: "application/json",
          service_name: "Market Data",
          tags: ["finance", "market-data"],
          icon_url: "https://api.example.com/icon.png",
          extensions: %{"bazaar" => %{"info" => %{}, "schema" => %{}}},
          extra: %{"name" => "USDC", "version" => "2"},
          max_timeout_seconds: 120
        })

      required =
        conn(:get, "/api/resource")
        |> run_request(routes: [route], facilitator: self())
        |> decode_payment_required!()

      assert required["resource"]["description"] == "Premium market data"
      assert required["resource"]["serviceName"] == "Market Data"
      assert required["resource"]["tags"] == ["finance", "market-data"]
      assert required["resource"]["iconUrl"] == "https://api.example.com/icon.png"
      assert required["extensions"]["bazaar"]["info"] == %{}

      [accept] = required["accepts"]
      assert accept["maxTimeoutSeconds"] == 120
      assert accept["extra"] == %{"name" => "USDC", "version" => "2"}
    end
  end

  # ---------------------------------------------------------------------------
  # PaymentPayload structure + accepted matching — §5.2
  # ---------------------------------------------------------------------------

  describe "PaymentPayload structure" do
    test "requires x402Version 2 (missing version is invalid)" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> Map.delete("x402Version")
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      required = decode_payment_required!(conn)

      assert conn.status == 400
      assert required["error"] == "invalid_x402_version"
      refute_received {:verify_called, _, _, _}
    end

    test "rejects x402Version other than 2 with 400" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> Map.put("x402Version", 1)
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_x402_version"
      refute_received {:verify_called, _, _, _}
    end

    test "rejects payload missing accepted or payload with 400" do
      facilitator = start_mock_facilitator()

      header =
        %{"x402Version" => 2, "network" => @network}
        |> Jason.encode!()
        |> Base.encode64()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
      refute_received {:verify_called, _, _, _}
    end

    test "rejects invalid base64 and invalid JSON with 400" do
      facilitator = start_mock_facilitator()

      bad_b64 =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", "not-valid-base64")
        |> run_request(routes: [@route], facilitator: facilitator)

      assert bad_b64.status == 400
      assert decode_payment_required!(bad_b64)["error"] == "invalid payment header"

      bad_json =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", Base.encode64("not json"))
        |> run_request(routes: [@route], facilitator: facilitator)

      assert bad_json.status == 400
      assert decode_payment_required!(bad_json)["error"] == "invalid payment header"
    end

    test "rejects empty PAYMENT-SIGNATURE with 400" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", "")
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid payment header"
    end
  end

  describe "accepted requirements matching" do
    for {field, value} <- [
          {"scheme", "upto"},
          {"network", "eip155:8453"},
          {"asset", "0x0000000000000000000000000000000000000001"},
          {"payTo", "0x2222222222222222222222222222222222222222"},
          {"amount", "99999"}
        ] do
      test "rejects accepted.#{field} mismatch with 402 and no facilitator call" do
        facilitator = start_mock_facilitator()
        field = unquote(field)
        value = unquote(value)

        header =
          valid_payment_payload()
          |> put_in(["accepted", field], value)
          |> encode_header()

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", header)
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 402
        assert decode_payment_required!(conn)["error"] == "No matching payment requirements"
        refute_received {:verify_called, _, _, _}
      end
    end

    test "uses matched requirements for verify and settle" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200

      assert_receive {:verify_called, _payload, requirements, _}
      assert requirements["scheme"] == "exact"
      assert requirements["network"] == @network
      assert requirements["amount"] == @amount
      assert requirements["asset"] == @asset
      assert requirements["payTo"] == @receiver

      assert_receive {:settle_called, _payload, ^requirements, _}
    end
  end

  # ---------------------------------------------------------------------------
  # Multi-accept routes
  # ---------------------------------------------------------------------------

  describe "multi-accept routes" do
    @solana_accept %{
      scheme: "exact",
      price: "5000",
      network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      pay_to: "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"
    }

    @multi_route %{
      method: :get,
      path: "/api/resource",
      accepts: [
        %{
          scheme: "exact",
          price: @amount,
          network: @network,
          asset: @asset,
          pay_to: @receiver
        },
        @solana_accept
      ]
    }

    test "PAYMENT-REQUIRED advertises all accepts" do
      required =
        conn(:get, "/api/resource")
        |> run_request(routes: [@multi_route], facilitator: self())
        |> decode_payment_required!()

      assert length(required["accepts"]) == 2

      assert Enum.any?(
               required["accepts"],
               &(&1["network"] == @network and &1["amount"] == @amount)
             )

      assert Enum.any?(
               required["accepts"],
               &(&1["network"] == @solana_accept.network and &1["amount"] == "5000")
             )
    end

    test "selects the matching accept among multiple options" do
      facilitator = start_mock_facilitator()

      solana_payload =
        valid_payment_payload()
        |> put_in(["accepted", "scheme"], "exact")
        |> put_in(["accepted", "network"], @solana_accept.network)
        |> put_in(["accepted", "amount"], @solana_accept.price)
        |> put_in(["accepted", "asset"], @solana_accept.asset)
        |> put_in(["accepted", "payTo"], @solana_accept.pay_to)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", encode_header(solana_payload))
        |> run_request(routes: [@multi_route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, _payload, requirements, _}
      assert requirements["network"] == @solana_accept.network
      assert requirements["amount"] == @solana_accept.price
      assert requirements["payTo"] == @solana_accept.pay_to
    end

    test "rejects when accepted matches none of the multi-accept options" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(["accepted", "network"], "eip155:1")
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@multi_route], facilitator: facilitator)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "No matching payment requirements"
      refute_received {:verify_called, _, _, _}
    end
  end

  # ---------------------------------------------------------------------------
  # Happy path: verify → settle → PAYMENT-RESPONSE + assigns
  # ---------------------------------------------------------------------------

  describe "successful payment flow" do
    test "verifies, settles, attaches PAYMENT-RESPONSE, and assigns payload" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns[:x402_payment_payload]["x402Version"] == 2
      assert conn.assigns[:x402_payment_requirements]["amount"] == @amount

      settle = decode_payment_response!(conn)
      assert settle["success"] == true
      assert settle["network"] == @network
      assert settle["transaction"] != ""

      assert_receive {:verify_called, payload, requirements, nil}
      assert payload["accepted"]["scheme"] == "exact"
      assert payload["payload"]["authorization"]["from"] == @receiver
      assert requirements["asset"] == @asset

      assert_receive {:settle_called, ^payload, ^requirements, nil}
    end

    test "passes configured hooks module to facilitator calls" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: TrackingHooks)

      assert conn.status == 200
      assert_receive {:verify_called, _, requirements, TrackingHooks}
      assert requirements["amount"] == @amount
      assert_receive {:settle_called, _, ^requirements, TrackingHooks}
    end

    test "verifies and settles valid upto payments under max amount" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header("9000"))
        |> run_request(routes: [@upto_route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, payload, requirements, nil}
      assert payload["accepted"]["scheme"] == "upto"
      assert payload["payload"]["authorization"]["value"] == "9000"
      assert requirements["scheme"] == "upto"
      assert requirements["amount"] == @amount
      assert_receive {:settle_called, _, ^requirements, nil}
    end

    test "rejects upto payments when authorization value exceeds route amount" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header("20000"))
        |> run_request(routes: [@upto_route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
      refute_received {:verify_called, _, _, _}
    end
  end

  # ---------------------------------------------------------------------------
  # Facilitator failure modes + PAYMENT-RESPONSE
  # ---------------------------------------------------------------------------

  describe "facilitator failures" do
    test "returns 402 when verify returns error" do
      facilitator =
        start_mock_facilitator(verify: fn _, _ -> {:error, :verification_failed} end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:settle_called, _, _, _}
    end

    test "returns 402 when verify body has isValid false" do
      facilitator =
        start_mock_facilitator(
          verify:
            {:ok,
             %{
               status: 200,
               body: %{"isValid" => false, "invalidReason" => "insufficient_funds"}
             }}
        )

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"
      refute_received {:settle_called, _, _, _}
    end

    test "returns 402 when settle fails with transport error" do
      facilitator =
        start_mock_facilitator(settle: fn _, _ -> {:error, :settlement_failed} end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "payment verification failed"
    end

    test "returns 402 with PAYMENT-RESPONSE when settle success is false" do
      settle_body = %{
        "success" => false,
        "errorReason" => "insufficient_funds",
        "transaction" => "",
        "network" => @network,
        "payer" => @receiver
      }

      facilitator =
        start_mock_facilitator(settle: {:ok, %{status: 200, body: settle_body}})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"

      response = decode_payment_response!(conn)
      assert response["success"] == false
      assert response["errorReason"] == "insufficient_funds"
    end

    test "returns 402 when verify or settle return non-2xx HTTP status" do
      for {key, result} <- [
            {:verify, {:ok, %{status: 400, body: %{"error" => "invalid"}}}},
            {:settle, {:ok, %{status: 500, body: %{"error" => "failed"}}}}
          ] do
        facilitator = start_mock_facilitator([{key, result}])

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", valid_payment_header())
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 402
        assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"
      end
    end

    test "maps invalid_payload from facilitator using protocol error code" do
      facilitator = start_mock_facilitator(verify: {:error, :invalid_payload})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      # Local and facilitator invalid_payload both surface the protocol code;
      # HTTP transport maps invalid payment to 400.
      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
    end
  end

  # ---------------------------------------------------------------------------
  # Config validation
  # ---------------------------------------------------------------------------

  describe "init/1 validation" do
    test "raises on missing routes and invalid values" do
      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(facilitator: self())
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(routes: :invalid)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(routes: [%{method: :get, path: "/api"}])
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(
          routes: [
            %{method: :foo, path: "/api", price: "1", network: "n", asset: "a", pay_to: "r"}
          ]
        )
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(routes: [@route], hooks: :not_a_hook_module)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(routes: [Map.put(@route, :scheme, "invalid")])
      end
    end

    test "accepts multi-accept routes without top-level price fields" do
      opts =
        PaymentGate.init(
          routes: [
            %{
              method: :get,
              path: "/paid",
              accepts: [
                %{
                  price: "1",
                  network: "eip155:1",
                  asset: "0xabc",
                  pay_to: "0xdef"
                }
              ]
            }
          ],
          facilitator: self()
        )

      assert length(hd(opts.routes).accepts) == 1
    end
  end

  # ---------------------------------------------------------------------------
  # Telemetry
  # ---------------------------------------------------------------------------

  describe "telemetry" do
    test "emits pass_through, payment_required, payment_verified, payment_rejected" do
      ok = start_mock_facilitator()
      reject = start_mock_facilitator(verify: fn _, _ -> {:error, :declined} end)

      handler_id = "payment-gate-#{System.unique_integer([:positive, :monotonic])}"
      parent = self()

      :ok =
        :telemetry.attach_many(
          handler_id,
          [
            [:x402, :plug, :pass_through],
            [:x402, :plug, :payment_required],
            [:x402, :plug, :payment_verified],
            [:x402, :plug, :payment_rejected]
          ],
          fn event, measurements, metadata, _ ->
            send(parent, {:telemetry_event, event, measurements, metadata})
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      run_request(conn(:get, "/public"), routes: [@route], facilitator: ok)
      run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: ok)

      verified =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: ok)

      rejected =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: reject)

      assert verified.status == 200
      assert rejected.status == 402

      assert_receive {:telemetry_event, [:x402, :plug, :pass_through], %{count: 1},
                      %{path: "/public"}}

      assert_receive {:telemetry_event, [:x402, :plug, :payment_required], %{count: 1},
                      %{path: "/api/resource"}}

      assert_receive {:telemetry_event, [:x402, :plug, :payment_verified], %{count: 1},
                      %{path: "/api/resource"}}

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], %{count: 1},
                      %{path: "/api/resource"}}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp run_request(conn, opts) do
    conn
    |> PaymentGate.call(PaymentGate.init(opts))
    |> maybe_send_ok()
  end

  defp maybe_send_ok(%Plug.Conn{halted: true} = conn), do: conn
  defp maybe_send_ok(conn), do: Plug.Conn.send_resp(conn, 200, "ok")

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  defp decode_payment_response!(conn) do
    [header] = get_resp_header(conn, "payment-response")
    assert {:ok, payload} = PaymentResponse.decode(header)
    payload
  end

  defp valid_payment_payload do
    %{
      "x402Version" => 2,
      "resource" => %{
        "url" => "http://www.example.com/api/resource",
        "description" => "Payment required",
        "mimeType" => "application/json"
      },
      "accepted" => %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => @amount,
        "asset" => @asset,
        "payTo" => @receiver,
        "maxTimeoutSeconds" => 60,
        "extra" => %{}
      },
      "payload" => %{
        "signature" =>
          "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
        "authorization" => %{
          "from" => @receiver,
          "to" => @receiver,
          "value" => @amount,
          "validAfter" => "1740672089",
          "validBefore" => "1740672154",
          "nonce" => "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
        }
      },
      "extensions" => %{}
    }
  end

  defp valid_payment_header, do: encode_header(valid_payment_payload())

  defp valid_upto_payment_header(value) do
    valid_payment_payload()
    |> put_in(["accepted", "scheme"], "upto")
    |> put_in(["payload", "authorization", "value"], value)
    |> encode_header()
  end

  defp encode_header(payload) when is_map(payload) do
    payload |> Jason.encode!() |> Base.encode64()
  end

  defp start_mock_facilitator(opts \\ []) do
    id = {:mock_facilitator, System.unique_integer([:positive, :monotonic])}
    start_options = Keyword.put_new(opts, :owner, self())

    start_supervised!(%{
      id: id,
      start: {MockFacilitator, :start_link, [start_options]}
    })
  end
end
