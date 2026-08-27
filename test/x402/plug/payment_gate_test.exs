defmodule X402.Plug.PaymentGateTest do
  @moduledoc """
  Spec-aligned tests for `X402.Plug.PaymentGate` against x402 v2.

  https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

  Sections map to protocol concerns:

  * Route matching (HTTP method/path)
  * PaymentRequired signaling (402 + PAYMENT-REQUIRED header)
  * PaymentPayload validation and accepted matching
  * HTTP status mapping (400 invalid, 402 payment failed, 500 server failure)
  * Facilitator verify/settle + PAYMENT-RESPONSE
  * Multi-accept routes
  * ResourceInfo / extensions
  * Lifecycle hooks and telemetry
  """

  use ExUnit.Case, async: false
  doctest X402.Plug.PaymentGate

  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator
  alias X402.Facilitator.Error
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

    test "preserves the request query in ResourceInfo.url" do
      required =
        conn(:get, "/api/resource?cursor=next&limit=10")
        |> run_request(routes: [@route], facilitator: self())
        |> decode_payment_required!()

      assert required["resource"]["url"] ==
               "http://www.example.com/api/resource?cursor=next&limit=10"
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
  # Route matching against path aliases — regression tests for the
  # GHSA-3j63-5h8p-gf7c bug class (route bypass via alternate spellings of a
  # protected path). Matching runs on decoded conn.path_info segments so the
  # gate agrees with what the downstream router serves.
  # ---------------------------------------------------------------------------

  describe "route matching against encoded path aliases" do
    test "gates routes mounted behind a forwarded prefix (script_name)" do
      # Plug/Phoenix `forward "/api", ...` pops the matched prefix from
      # path_info into script_name before inner plugs run. Routes configured
      # as full paths must still match, or forwarded mounts fail open.
      conn = %{
        conn(:get, "/api/resource")
        | script_name: ["api"],
          path_info: ["resource"]
      }

      assert run_request(conn, routes: [@route], facilitator: self()).status == 402
    end

    test "gates a leading-double-slash alias of a protected path" do
      # Cowboy builds path_info by dropping empty segments, so "//api/resource"
      # reaches the router as the protected resource while request_path keeps
      # the raw spelling. Simulate the adapter output directly — Plug.Test
      # cannot parse a scheme-relative "//" target.
      conn = %{
        conn(:get, "/api/resource")
        | request_path: "//api/resource",
          path_info: ["api", "resource"]
      }

      assert run_request(conn, routes: [@route], facilitator: self()).status == 402
    end

    test "gates a mid-path double-slash alias of a protected path" do
      conn = %{
        conn(:get, "/api/resource")
        | request_path: "/api//resource",
          path_info: ["api", "resource"]
      }

      assert run_request(conn, routes: [@route], facilitator: self()).status == 402
    end

    test "gates a percent-encoded alias of a protected path" do
      conn = run_request(conn(:get, "/api/re%73ource"), routes: [@route], facilitator: self())

      assert conn.status == 402
      assert get_resp_header(conn, "payment-required") != []
    end

    test "gates an encoded-slash alias of a protected path" do
      conn = run_request(conn(:get, "/api%2Fresource"), routes: [@route], facilitator: self())

      assert conn.status == 402
    end

    test "gates percent-encoded aliases under glob routes" do
      route = Map.put(@route, :path, "/api/*")
      conn = run_request(conn(:get, "/api/%76%31/items"), routes: [route], facilitator: self())

      assert conn.status == 402
    end

    test "matches malformed percent sequences verbatim without crashing" do
      passthrough =
        run_request(conn(:get, "/api/re%zzource"), routes: [@route], facilitator: self())

      assert passthrough.status == 200

      gated_route = Map.put(@route, :path, "/api/re%zzource")

      gated =
        run_request(conn(:get, "/api/re%zzource"), routes: [gated_route], facilitator: self())

      assert gated.status == 402
    end

    test "does not gate paths that decode to a different resource" do
      conn = run_request(conn(:get, "/api/re%73ourceX"), routes: [@route], facilitator: self())

      assert conn.status == 200
    end
  end

  # ---------------------------------------------------------------------------
  # Local pre-verification checks — cheap payTo/amount/timing validation on the
  # EIP-3009 authorization object before the facilitator round-trip.
  # ---------------------------------------------------------------------------

  describe "local pre-verification checks" do
    test "rejects a payTo mismatch without calling the facilitator" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(
          ["payload", "authorization", "to"],
          "0x9999999999999999999999999999999999999999"
        )
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:verify_called, _, _, _}
    end

    test "accepts a payTo that differs only in hex casing" do
      facilitator = start_mock_facilitator()

      "0x" <> hex = @receiver

      header =
        valid_payment_payload()
        |> put_in(["payload", "authorization", "to"], "0x" <> String.upcase(hex))
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, _, _, _}
    end

    test "rejects an exact-scheme amount mismatch without calling the facilitator" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(["payload", "authorization", "value"], "9999")
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:verify_called, _, _, _}
    end

    test "rejects an authorization that is not yet valid" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(
          ["payload", "authorization", "validAfter"],
          Integer.to_string(System.system_time(:second) + 3_600)
        )
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:verify_called, _, _, _}
    end

    test "rejects an authorization expiring inside the settlement buffer" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(
          ["payload", "authorization", "validBefore"],
          Integer.to_string(System.system_time(:second) + 3)
        )
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:verify_called, _, _, _}
    end

    test "rejects non-numeric authorization timing" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(["payload", "authorization", "validAfter"], "not-a-timestamp")
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      refute_received {:verify_called, _, _, _}
    end

    test "skips payloads without an EIP-3009 authorization object" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(["payload"], %{"signature" => "0xsignature"})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, _, _, _}
    end

    test "local_prechecks: false defers everything to the facilitator" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> put_in(
          ["payload", "authorization", "to"],
          "0x9999999999999999999999999999999999999999"
        )
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator, local_prechecks: false)

      assert conn.status == 200
      assert_receive {:verify_called, _, _, _}
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

    test "returns 400 for v2 payloads with an incomplete accepted object" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> update_in(["accepted"], &Map.delete(&1, "asset"))
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      required = decode_payment_required!(conn)

      assert conn.status == 400
      assert required["error"] == "invalid_payload"
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
          {"amount", "99999"},
          {"maxTimeoutSeconds", 120}
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

    test "rejects removal or mutation of advertised extra fields" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extra, %{"name" => "USDC", "version" => "2"})

      for extra <- [%{}, %{"name" => "USDT", "version" => "2"}] do
        header =
          valid_payment_payload()
          |> put_in(["accepted", "extra"], extra)
          |> encode_header()

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", header)
          |> run_request(routes: [route], facilitator: facilitator)

        assert conn.status == 402
        assert decode_payment_required!(conn)["error"] == "No matching payment requirements"
      end

      refute_received {:verify_called, _, _, _}
    end

    test "allows additive client metadata under accepted.extra" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extra, %{"name" => "USDC"})

      header =
        valid_payment_payload()
        |> put_in(["accepted", "extra"], %{"name" => "USDC", "version" => "2"})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, _, _, _}
    end

    test "rejects mutated extension echoes before facilitator verification" do
      facilitator = start_mock_facilitator()

      route =
        Map.put(@route, :extensions, %{
          "bazaar" => %{"info" => %{"resource" => "premium"}, "schema" => %{"type" => "object"}}
        })

      header =
        valid_payment_payload()
        |> put_in(["extensions"], %{"bazaar" => %{"info" => %{"resource" => "free"}}})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
      refute_received {:verify_called, _, _, _}
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
        |> put_in(["payload"], %{"transaction" => "base64-encoded-solana-transaction"})

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
    test "verifies before the handler and settles only when its response is sent" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> gate_request(routes: [@route], facilitator: facilitator)

      assert_receive {:verify_called, _, _, _}
      refute_received {:settle_called, _, _, _}

      response_conn = Plug.Conn.send_resp(gated_conn, 201, "created")

      assert response_conn.status == 201
      assert_receive {:settle_called, _, _, _}
      assert decode_payment_response!(response_conn)["success"] == true
    end

    test "does not settle when the protected handler returns an error" do
      facilitator = start_mock_facilitator()

      response_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> gate_request(routes: [@route], facilitator: facilitator)
        |> Plug.Conn.send_resp(500, "handler failed")

      assert response_conn.status == 500
      assert response_conn.resp_body == "handler failed"
      assert_receive {:verify_called, _, _, _}
      refute_received {:settle_called, _, _, _}
      assert get_resp_header(response_conn, "payment-response") == []
    end

    test "releases the idempotency claim when the protected handler fails" do
      facilitator = start_mock_facilitator()
      cache_name = String.to_atom("payment_gate_cache_#{System.unique_integer([:positive])}")
      cache = start_supervised!({ETSCache, name: cache_name})
      header = valid_payment_header()

      first_response =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> gate_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )
        |> Plug.Conn.send_resp(500, "handler failed")

      assert first_response.status == 500
      assert_receive {:verify_called, _, _, _}
      refute_received {:settle_called, _, _, _}

      retry_response =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )

      assert retry_response.status == 200
      assert_receive {:verify_called, _, _, _}
      assert_receive {:settle_called, _, _, _}
    end

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

    test "verifies and settles an upto payment at the advertised maximum by default" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> run_request(routes: [@upto_route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, payload, requirements, nil}
      assert payload["accepted"]["scheme"] == "upto"
      assert payload["payload"]["permit2Authorization"]["permitted"]["amount"] == @amount
      assert requirements["scheme"] == "upto"
      assert requirements["amount"] == @amount
      assert_receive {:settle_called, _, ^requirements, nil}
    end

    test "settles an upto payment using the handler's actual atomic amount" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> gate_request(routes: [@upto_route], facilitator: facilitator)

      assert {:ok, gated_conn} = PaymentGate.put_settlement_amount(gated_conn, "2500")
      response_conn = Plug.Conn.send_resp(gated_conn, 200, "usage complete")

      assert response_conn.status == 200
      assert_receive {:verify_called, _, %{"amount" => @amount}, _}
      assert_receive {:settle_called, _, %{"amount" => "2500"}, _}
    end

    test "fails closed when an upto settlement amount exceeds the authorized maximum" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> gate_request(routes: [@upto_route], facilitator: facilitator)

      assert {:ok, gated_conn} = PaymentGate.put_settlement_amount(gated_conn, "10001")
      response_conn = Plug.Conn.send_resp(gated_conn, 200, "usage complete")

      assert response_conn.status == 500
      assert decode_payment_required!(response_conn)["error"] == "payment processing failed"
      refute_received {:settle_called, _, _, _}
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

  describe "real facilitator client integration" do
    test "sends the upto ceiling to verify and the handler amount to settle" do
      bypass = Bypass.open()
      finch = String.to_atom("payment_gate_finch_#{System.unique_integer([:positive])}")

      facilitator_name =
        String.to_atom("payment_gate_facilitator_#{System.unique_integer([:positive])}")

      start_supervised!({Finch, name: finch})

      Bypass.expect(bypass, "POST", "/verify", fn bypass_conn ->
        assert {:ok, body, bypass_conn} = Plug.Conn.read_body(bypass_conn)
        decoded = Jason.decode!(body)

        assert decoded["x402Version"] == 2
        assert decoded["paymentRequirements"]["amount"] == @amount

        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      Bypass.expect(bypass, "POST", "/settle", fn bypass_conn ->
        assert {:ok, body, bypass_conn} = Plug.Conn.read_body(bypass_conn)
        decoded = Jason.decode!(body)

        assert decoded["paymentRequirements"]["amount"] == "2500"

        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{
            "success" => true,
            "transaction" => "0xsettled",
            "network" => @network,
            "payer" => @receiver
          })
        )
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: facilitator_name,
           finch: finch,
           url: "http://localhost:#{bypass.port}",
           max_retries: 0}
        )

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> gate_request(routes: [@upto_route], facilitator: facilitator)

      assert {:ok, gated_conn} = PaymentGate.put_settlement_amount(gated_conn, "2500")
      response_conn = Plug.Conn.send_resp(gated_conn, 200, "usage complete")

      assert response_conn.status == 200
      assert decode_payment_response!(response_conn)["success"] == true
    end
  end

  # ---------------------------------------------------------------------------
  # Facilitator failure modes + PAYMENT-RESPONSE
  # ---------------------------------------------------------------------------

  describe "facilitator failures" do
    test "returns 500 when verify has a transport failure" do
      error = %Error{type: :transport_error, reason: :closed, retryable: true}
      facilitator = start_mock_facilitator(verify: {:error, error})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
      refute_received {:settle_called, _, _, _}
    end

    test "fails closed when verify omits or mistypes isValid" do
      for body <- [%{}, %{"isValid" => "true"}, []] do
        facilitator = start_mock_facilitator(verify: {:ok, %{status: 200, body: body}})

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", valid_payment_header())
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 500
        assert decode_payment_required!(conn)["error"] == "payment processing failed"
      end

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

    test "returns 500 when settle has a transport failure" do
      error = %Error{type: :timeout, reason: :timeout, retryable: true}
      facilitator = start_mock_facilitator(settle: {:error, error})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end

    test "fails closed when settle omits required success fields" do
      for body <- [%{}, %{"success" => true}, []] do
        facilitator = start_mock_facilitator(settle: {:ok, %{status: 200, body: body}})

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", valid_payment_header())
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 500
        assert decode_payment_required!(conn)["error"] == "payment processing failed"
      end
    end

    test "returns 500 when PAYMENT-REQUIRED cannot be encoded" do
      route = Map.put(@route, :extensions, %{"invalid" => %{"value" => self()}})
      conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: self())

      assert conn.status == 500
      assert conn.resp_body == "{}"
      assert get_resp_header(conn, "payment-required") == []
    end

    test "returns 500 when PAYMENT-RESPONSE cannot be encoded" do
      settle_body = %{
        "success" => true,
        "transaction" => "0xsettled",
        "network" => @network,
        "unencodable" => self()
      }

      facilitator =
        start_mock_facilitator(settle: {:ok, %{status: 200, body: settle_body}})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 500
      assert conn.resp_body == "{}"
      assert get_resp_header(conn, "payment-response") == []
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

    test "returns 500 when the facilitator adapter returns non-2xx responses" do
      for {key, result} <- [
            {:verify, {:ok, %{status: 400, body: %{"error" => "invalid"}}}},
            {:settle, {:ok, %{status: 500, body: %{"error" => "failed"}}}}
          ] do
        facilitator = start_mock_facilitator([{key, result}])

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", valid_payment_header())
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 500
        assert decode_payment_required!(conn)["error"] == "payment processing failed"
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

      assert_raise NimbleOptions.ValidationError, ~r/atomic-unit amount/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :price, "0.01")])
      end

      assert_raise NimbleOptions.ValidationError, ~r/unsupported payment flow/, fn ->
        PaymentGate.init(
          routes: [Map.put(@route, :extra, %{"paymentFlow" => "upfront"})],
          facilitator: self()
        )
      end
    end

    test "rejects unknown string options without creating atoms" do
      unknown_key = "untrusted_route_option_#{System.unique_integer([:positive])}"

      assert_raise ArgumentError, fn -> String.to_existing_atom(unknown_key) end

      assert_raise NimbleOptions.ValidationError, ~r/unknown route option/, fn ->
        PaymentGate.init(
          routes: [Map.put(@route, unknown_key, true)],
          facilitator: self()
        )
      end

      assert_raise ArgumentError, fn -> String.to_existing_atom(unknown_key) end
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

      reject =
        start_mock_facilitator(
          verify:
            {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "declined"}}}
        )

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
    |> gate_request(opts)
    |> maybe_send_ok()
  end

  defp gate_request(conn, opts), do: PaymentGate.call(conn, PaymentGate.init(opts))

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
          "validAfter" => Integer.to_string(System.system_time(:second) - 60),
          "validBefore" => Integer.to_string(System.system_time(:second) + 300),
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
    |> put_in(
      ["payload"],
      %{
        "signature" => "0xpermit2-signature",
        "permit2Authorization" => %{
          "permitted" => %{"token" => @asset, "amount" => value},
          "from" => @receiver,
          "spender" => "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002",
          "nonce" => "1",
          "deadline" => "1740672154",
          "witness" => %{"to" => @receiver, "facilitator" => @receiver, "validAfter" => "0"}
        }
      }
    )
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
