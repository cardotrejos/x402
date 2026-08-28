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

  import Mox
  import Plug.Conn
  import Plug.Test

  alias X402.Client
  alias X402.EIP3009
  alias X402.Extensions.PaymentIdentifier
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator
  alias X402.PaymentIdentifierCacheMock, as: CacheMock
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.Plug.PaymentGate
  alias X402.RPC
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey
  alias X402.TestRPCStub

  setup :verify_on_exit!

  # Facilitator operations execute in the calling process; the gate runs in
  # the test process, so hook callbacks can message `self()` directly.
  defmodule TrackingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: notify(:before_verify, context)
    def after_verify(%Context{} = context, _metadata), do: notify(:after_verify, context)

    def on_verify_failure(%Context{} = context, _metadata),
      do: notify(:on_verify_failure, context)

    def before_settle(%Context{} = context, _metadata), do: notify(:before_settle, context)
    def after_settle(%Context{} = context, _metadata), do: notify(:after_settle, context)

    def on_settle_failure(%Context{} = context, _metadata),
      do: notify(:on_settle_failure, context)

    defp notify(callback, context) do
      send(self(), {:hook_called, callback})
      {:cont, context}
    end
  end

  # Replaces the facilitator error with the protocol error code, emulating a
  # facilitator client that surfaces `:invalid_payload` directly.
  defmodule InvalidPayloadHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}

    def on_verify_failure(%Context{} = context, _metadata),
      do: {:cont, %Context{context | error: :invalid_payload}}

    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  # Injects a value that cannot be JSON-encoded into the settle result body so
  # PAYMENT-RESPONSE encoding fails after a successful settlement.
  defmodule UnencodableSettleHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}

    def after_settle(%Context{} = context, _metadata) do
      body = Map.put(context.result.body, "unencodable", self())
      {:cont, %Context{context | result: %{context.result | body: body}}}
    end

    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  # Replaces facilitator verify/settle results or errors with values the test
  # stages in its process dictionary. Facilitator operations execute in the
  # calling (test) process, so `Process.get/2` reads the staged value; without
  # a staged value every callback passes the context through unchanged.
  defmodule StagedResultHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}

    def after_verify(%Context{} = context, _metadata),
      do: {:cont, %Context{context | result: Process.get(:staged_verify_result, context.result)}}

    def on_verify_failure(%Context{} = context, _metadata),
      do: {:cont, %Context{context | error: Process.get(:staged_verify_error, context.error)}}

    def before_settle(%Context{} = context, _metadata), do: {:cont, context}

    def after_settle(%Context{} = context, _metadata),
      do: {:cont, %Context{context | result: Process.get(:staged_settle_result, context.result)}}

    def on_settle_failure(%Context{} = context, _metadata),
      do: {:cont, %Context{context | error: Process.get(:staged_settle_error, context.error)}}
  end

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @network "eip155:84532"
  @amount "10000"

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
      refute_received {:verify_called, _, _}
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
      assert_receive {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      assert_receive {:verify_called, _, _}
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
      assert_receive {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
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
        refute_received {:verify_called, _, _}
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

      refute_received {:verify_called, _, _}
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
      assert_receive {:verify_called, _, _}
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
      refute_received {:verify_called, _, _}
    end

    test "uses matched requirements for verify and settle" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200

      assert_receive {:verify_called, _payload, requirements}
      assert requirements["scheme"] == "exact"
      assert requirements["network"] == @network
      assert requirements["amount"] == @amount
      assert requirements["asset"] == @asset
      assert requirements["payTo"] == @receiver

      assert_receive {:settle_called, _payload, ^requirements}
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
      pay_to: "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5",
      extra: %{
        "feePayer" => "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu",
        "recentBlockhash" => "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
      }
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

      # Full client flow: the 402's PAYMENT-REQUIRED is decoded, the client
      # selects the SVM entry (the EVM entry lacks its EIP-712 domain and is
      # not signable), builds a real partially signed Solana transaction, and
      # the gate's structural validation and static-path pre-checks let it
      # through to the Bypass-backed facilitator.
      payment_required =
        conn(:get, "/api/resource")
        |> run_request(routes: [@multi_route], facilitator: facilitator)
        |> decode_payment_required!()

      {:ok, solana_signer} = SolanaKey.new(:crypto.strong_rand_bytes(32))
      {:ok, solana_payload} = Client.build_payment(payment_required, solana_signer)

      assert solana_payload["accepted"]["network"] == @solana_accept.network

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", encode_header(solana_payload))
        |> run_request(routes: [@multi_route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, payload, requirements}
      assert requirements["network"] == @solana_accept.network
      assert requirements["amount"] == @solana_accept.price
      assert requirements["payTo"] == @solana_accept.pay_to
      assert requirements["extra"]["feePayer"] == @solana_accept.extra["feePayer"]

      # The facilitator receives the client's partially signed transaction.
      assert payload["payload"]["transaction"] == solana_payload["payload"]["transaction"]
      assert {:ok, _wire} = Base.decode64(payload["payload"]["transaction"])
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
      refute_received {:verify_called, _, _}
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

      assert_receive {:verify_called, _, _}
      refute_received {:settle_called, _, _}

      response_conn = Plug.Conn.send_resp(gated_conn, 201, "created")

      assert response_conn.status == 201
      assert_receive {:settle_called, _, _}
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
      assert_receive {:verify_called, _, _}
      refute_received {:settle_called, _, _}
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
      assert_receive {:verify_called, _, _}
      refute_received {:settle_called, _, _}

      retry_response =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )

      assert retry_response.status == 200
      assert_receive {:verify_called, _, _}
      assert_receive {:settle_called, _, _}
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

      assert_receive {:verify_called, payload, requirements}
      assert payload["accepted"]["scheme"] == "exact"
      assert payload["payload"]["authorization"]["from"] == @receiver
      assert requirements["asset"] == @asset

      assert_receive {:settle_called, ^payload, ^requirements}
    end

    test "passes configured hooks module to facilitator calls" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: TrackingHooks)

      assert conn.status == 200
      assert_receive {:verify_called, _, requirements}
      assert requirements["amount"] == @amount
      assert_receive {:settle_called, _, ^requirements}

      # The configured hooks module ran around both facilitator operations.
      assert_receive {:hook_called, :before_verify}
      assert_receive {:hook_called, :after_verify}
      assert_receive {:hook_called, :before_settle}
      assert_receive {:hook_called, :after_settle}
    end

    test "verifies and settles an upto payment at the advertised maximum by default" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> run_request(routes: [@upto_route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, payload, requirements}
      assert payload["accepted"]["scheme"] == "upto"
      assert payload["payload"]["permit2Authorization"]["permitted"]["amount"] == @amount
      assert requirements["scheme"] == "upto"
      assert requirements["amount"] == @amount
      assert_receive {:settle_called, _, ^requirements}
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
      assert_receive {:verify_called, _, %{"amount" => @amount}}
      assert_receive {:settle_called, _, %{"amount" => "2500"}}
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
      refute_received {:settle_called, _, _}
    end

    test "rejects upto payments when authorization value exceeds route amount" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header("20000"))
        |> run_request(routes: [@upto_route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
      refute_received {:verify_called, _, _}
    end
  end

  # ---------------------------------------------------------------------------
  # Claim ordering relative to facilitator verification
  # ---------------------------------------------------------------------------

  describe "claim_order" do
    test "defaults to :after_verify" do
      assert %{claim_order: :after_verify} = PaymentGate.init(routes: [@route])
    end

    test "init/1 rejects invalid claim_order values" do
      assert_raise NimbleOptions.ValidationError, ~r/claim_order/, fn ->
        PaymentGate.init(routes: [@route], claim_order: :sometimes)
      end
    end

    test ":after_verify claims only after the facilitator verified" do
      facilitator = start_mock_facilitator()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified ->
        # The verify round-trip must already have completed when the claim runs.
        assert_received {:verify_called, _, _}
        :ok
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref},
          claim_order: :after_verify
        )

      assert conn.status == 200
    end

    test ":after_verify never touches the cache when verification fails" do
      facilitator =
        start_mock_facilitator(
          verify:
            {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "declined"}}}
        )

      # No CacheMock expectations: any adapter call would raise UnexpectedCallError.
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref}
        )

      assert conn.status == 402
    end

    test ":before_verify claims before contacting the facilitator" do
      facilitator = start_mock_facilitator()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified ->
        # The claim must run before any facilitator verify round-trip.
        refute_received {:verify_called, _, _}
        :ok
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref},
          claim_order: :before_verify
        )

      assert conn.status == 200
      assert_receive {:verify_called, _, _}
      assert_receive {:settle_called, _, _}
    end

    test ":before_verify releases the claim when verification is rejected" do
      facilitator =
        start_mock_facilitator(
          verify:
            {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "declined"}}}
        )

      parent = self()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified -> :ok end)

      expect(CacheMock, :delete, fn :mock_ref, payment_id ->
        send(parent, {:adapter_delete, payment_id})
        :ok
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref},
          claim_order: :before_verify
        )

      assert conn.status == 402
      assert_receive {:adapter_delete, _payment_id}
      refute_received {:settle_called, _, _}
    end

    test ":before_verify releases the claim on facilitator transport errors" do
      bypass = Bypass.open()
      Bypass.down(bypass)
      facilitator = start_facilitator(url: "http://localhost:#{bypass.port}")
      parent = self()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified -> :ok end)

      expect(CacheMock, :delete, fn :mock_ref, payment_id ->
        send(parent, {:adapter_delete, payment_id})
        :ok
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref},
          claim_order: :before_verify
        )

      assert conn.status == 500
      assert_receive {:adapter_delete, _payment_id}
    end

    test ":before_verify releases the claim when the facilitator call exits" do
      # A dead facilitator pid makes Facilitator.verify exit with :noproc —
      # the caller-side client still fetches its configuration through a
      # GenServer.call to the facilitator process before running the HTTP
      # request — instead of returning an error tuple. The claim must still be
      # released
      # before the exit propagates, or the payer's retry is rejected as a
      # duplicate until the cache TTL expires.
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      assert_receive {:DOWN, ^ref, :process, ^dead, _reason}

      parent = self()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified -> :ok end)

      expect(CacheMock, :delete, fn :mock_ref, payment_id ->
        send(parent, {:adapter_delete, payment_id})
        :ok
      end)

      opts =
        PaymentGate.init(
          routes: [@route],
          facilitator: dead,
          payment_identifier_cache: {CacheMock, :mock_ref},
          claim_order: :before_verify
        )

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())

      assert catch_exit(PaymentGate.call(conn, opts))
      assert_receive {:adapter_delete, _payment_id}
    end

    test ":before_verify allows a retry after a failed verification" do
      reject =
        start_mock_facilitator(
          verify:
            {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "declined"}}}
        )

      accept = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      header = valid_payment_header()

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: reject,
          payment_identifier_cache: cache,
          claim_order: :before_verify
        )

      assert first.status == 402

      retry =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: accept,
          payment_identifier_cache: cache,
          claim_order: :before_verify
        )

      assert retry.status == 200
      assert_receive {:settle_called, _, _}
    end

    test ":before_verify rejects a duplicate without any facilitator call" do
      bypass = Bypass.open()
      finch = String.to_atom("payment_gate_finch_#{System.unique_integer([:positive])}")

      facilitator_name =
        String.to_atom("payment_gate_facilitator_#{System.unique_integer([:positive])}")

      start_supervised!({Finch, name: finch})

      # expect_once fails the test if either endpoint is hit more than once,
      # proving the duplicate request below causes zero facilitator calls.
      Bypass.expect_once(bypass, "POST", "/verify", fn bypass_conn ->
        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      Bypass.expect_once(bypass, "POST", "/settle", fn bypass_conn ->
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

      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      header = valid_payment_header()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert first.status == 200
      assert decode_payment_response!(first)["success"] == true

      duplicate =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
    end
  end

  # ---------------------------------------------------------------------------
  # Replay protection through the Cache behaviour
  # ---------------------------------------------------------------------------

  describe "payment identifier cache adapters" do
    test "init/1 wraps a pid or name in the default ETSCache adapter" do
      pid = self()
      name = :payment_gate_cache_compat

      assert %{payment_identifier_cache: {ETSCache, ^pid}} =
               PaymentGate.init(routes: [@route], payment_identifier_cache: pid)

      assert %{payment_identifier_cache: {ETSCache, ^name}} =
               PaymentGate.init(routes: [@route], payment_identifier_cache: name)

      assert %{payment_identifier_cache: nil} = PaymentGate.init(routes: [@route])
    end

    test "init/1 accepts a {module, cache} adapter tuple as-is" do
      assert %{payment_identifier_cache: {CacheMock, :mock_ref}} =
               PaymentGate.init(
                 routes: [@route],
                 payment_identifier_cache: {CacheMock, :mock_ref}
               )
    end

    test "init/1 rejects adapter tuples whose module misses callbacks" do
      assert_raise NimbleOptions.ValidationError, ~r/put_new\/3/, fn ->
        PaymentGate.init(
          routes: [@route],
          payment_identifier_cache: {X402.Extensions.PaymentIdentifier, :ref}
        )
      end
    end

    test "claims through a custom adapter and releases when the handler fails" do
      facilitator = start_mock_facilitator()
      parent = self()

      expect(CacheMock, :put_new, fn :mock_ref, payment_id, :verified ->
        send(parent, {:adapter_put_new, payment_id})
        :ok
      end)

      expect(CacheMock, :delete, fn :mock_ref, payment_id ->
        send(parent, {:adapter_delete, payment_id})
        :ok
      end)

      response_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> gate_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref}
        )
        |> Plug.Conn.send_resp(500, "handler failed")

      assert response_conn.status == 500
      assert_receive {:adapter_put_new, payment_id}
      assert_receive {:adapter_delete, ^payment_id}
      refute_received {:settle_called, _, _}
    end

    test "releases the claim through the adapter when settlement fails" do
      settle_body = %{
        "success" => false,
        "errorReason" => "insufficient_funds",
        "transaction" => "",
        "network" => @network
      }

      facilitator = start_mock_facilitator(settle: {:ok, %{status: 200, body: settle_body}})
      parent = self()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified -> :ok end)

      expect(CacheMock, :delete, fn :mock_ref, payment_id ->
        send(parent, {:adapter_delete, payment_id})
        :ok
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref}
        )

      assert conn.status == 402
      assert_receive {:adapter_delete, _payment_id}
    end

    test "rejects a duplicate claim from a custom adapter with 402" do
      facilitator = start_mock_facilitator()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified ->
        {:error, :already_exists}
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref}
        )

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "payment already processed"
      refute_received {:settle_called, _, _}
    end

    test "fails closed with 500 when the adapter claim errors" do
      facilitator = start_mock_facilitator()

      expect(CacheMock, :put_new, fn :mock_ref, _payment_id, :verified ->
        {:error, :backend_unavailable}
      end)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: {CacheMock, :mock_ref}
        )

      assert conn.status == 500
      refute_received {:settle_called, _, _}
    end

    test "rejects duplicate payment proofs with the default ETS adapter" do
      facilitator = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      header = valid_payment_header()

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )

      assert first.status == 200
      assert_receive {:settle_called, _, _}

      duplicate =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          payment_identifier_cache: cache
        )

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
      refute_received {:settle_called, _, _}
    end

    test "exactly one of two concurrent identical requests wins the claim" do
      facilitator = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      header = valid_payment_header()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        payment_identifier_cache: cache
      ]

      statuses =
        1..2
        |> Enum.map(fn _index ->
          Task.async(fn ->
            conn(:get, "/api/resource")
            |> put_req_header("payment-signature", header)
            |> gate_request(opts)
            |> maybe_send_ok()
            |> Map.fetch!(:status)
          end)
        end)
        |> Task.await_many()

      assert Enum.sort(statuses) == [200, 402]
      assert_receive {:settle_called, _, _}
      refute_received {:settle_called, _, _}
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
      bypass = Bypass.open()
      Bypass.down(bypass)
      facilitator = start_facilitator(url: "http://localhost:#{bypass.port}")

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
      refute_received {:settle_called, _, _}
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

      refute_received {:settle_called, _, _}
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
      refute_received {:settle_called, _, _}
    end

    test "returns 500 when settle times out" do
      owner = self()
      bypass = Bypass.open()
      stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, @default_verify)

      Bypass.stub(bypass, "POST", "/settle", fn conn ->
        # The client hangs up at its receive timeout, which kills this handler
        # mid-sleep; mark the expectation as passed so Bypass does not report
        # the intentional timeout as a failure.
        Bypass.pass(bypass)
        Process.sleep(150)
        Plug.Conn.resp(conn, 200, Jason.encode!(%{}))
      end)

      facilitator =
        start_facilitator(url: "http://localhost:#{bypass.port}", receive_timeout_ms: 50)

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
        "network" => @network
      }

      facilitator =
        start_mock_facilitator(settle: {:ok, %{status: 200, body: settle_body}})

      # UnencodableSettleHooks injects a pid into the settle result body, so
      # the settlement succeeds but the PAYMENT-RESPONSE header cannot be
      # JSON-encoded.
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: UnencodableSettleHooks)

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
      facilitator =
        start_mock_facilitator(verify: {:ok, %{status: 400, body: %{"error" => "invalid"}}})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: InvalidPayloadHooks)

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
    test "normalizes :global and :via names to the default ETSCache adapter" do
      global = PaymentGate.init(routes: [@route], payment_identifier_cache: {:global, :my_cache})

      assert global.payment_identifier_cache == {ETSCache, {:global, :my_cache}}

      via_name = {:via, Registry, {MyRegistry, :cache}}
      via = PaymentGate.init(routes: [@route], payment_identifier_cache: via_name)

      assert via.payment_identifier_cache == {ETSCache, via_name}
    end

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
  # Browser paywall (:paywall option)
  # ---------------------------------------------------------------------------

  defmodule CustomPaywall do
    @moduledoc false
    @behaviour X402.Paywall

    @impl X402.Paywall
    def render(payment_required, conn_info) do
      {:ok,
       "custom-paywall:#{conn_info.method}:#{conn_info.request_path}:" <>
         "#{conn_info.status}:#{payment_required["error"]}"}
    end
  end

  defmodule FailingPaywall do
    @moduledoc false
    @behaviour X402.Paywall

    @impl X402.Paywall
    def render(_payment_required, _conn_info), do: {:error, :boom}
  end

  @browser_accept "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  @browser_user_agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

  defp browser_conn(conn) do
    conn
    |> put_req_header("accept", @browser_accept)
    |> put_req_header("user-agent", @browser_user_agent)
  end

  defp maybe_put_req_header(conn, _name, nil), do: conn
  defp maybe_put_req_header(conn, name, value), do: put_req_header(conn, name, value)

  describe "browser paywall" do
    test "serves HTML to browser page loads when :paywall is set" do
      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [@route], facilitator: self(), paywall: X402.Paywall.Default)

      assert conn.status == 402
      assert conn.halted
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ "<!DOCTYPE html>"
      assert conn.resp_body =~ @amount
      assert conn.resp_body =~ @network
      assert conn.resp_body =~ @asset
    end

    test "denies framing on the HTML paywall (clickjacking defense)" do
      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [@route], facilitator: self(), paywall: X402.Paywall.Default)

      assert get_resp_header(conn, "x-frame-options") == ["DENY"]
      assert get_resp_header(conn, "content-security-policy") == ["frame-ancestors 'none'"]

      # JSON 402s keep their existing header surface.
      json = run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: self())
      assert get_resp_header(json, "x-frame-options") == []
      assert get_resp_header(json, "content-security-policy") == []
    end

    test "keeps JSON for non-GET browser requests (paywall retry is a GET)" do
      route = Map.put(@route, :method, :post)

      conn =
        conn(:post, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [route], facilitator: self(), paywall: X402.Paywall.Default)

      assert conn.status == 402
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
      refute conn.resp_body =~ "<!DOCTYPE html>"
    end

    test "serves HTML for a bare text/html Accept with a Mozilla User-Agent" do
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("accept", "text/html")
        |> put_req_header("user-agent", @browser_user_agent)
        |> run_request(routes: [@route], facilitator: self(), paywall: X402.Paywall.Default)

      assert conn.status == 402
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
    end

    test "keeps JSON across the API-client Accept/User-Agent matrix" do
      matrix = [
        {nil, nil},
        {@browser_accept, nil},
        {"text/html", nil},
        {nil, @browser_user_agent},
        {"application/json", @browser_user_agent},
        {"*/*", @browser_user_agent},
        {"application/json, text/plain", @browser_user_agent}
      ]

      for {accept, user_agent} <- matrix do
        conn =
          conn(:get, "/api/resource")
          |> maybe_put_req_header("accept", accept)
          |> maybe_put_req_header("user-agent", user_agent)
          |> run_request(routes: [@route], facilitator: self(), paywall: X402.Paywall.Default)

        assert conn.status == 402
        assert conn.resp_body == "{}"
        assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
        assert get_resp_header(conn, "payment-required") != []
      end
    end

    test "sends the identical PAYMENT-REQUIRED header on HTML and JSON forms" do
      opts = [routes: [@route], facilitator: self(), paywall: X402.Paywall.Default]

      html_conn = conn(:get, "/api/resource") |> browser_conn() |> run_request(opts)
      json_conn = run_request(conn(:get, "/api/resource"), opts)

      bare_conn =
        run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: self())

      [header] = get_resp_header(html_conn, "payment-required")
      assert get_resp_header(json_conn, "payment-required") == [header]
      assert get_resp_header(bare_conn, "payment-required") == [header]

      # The page embeds the exact header value for tooling.
      assert html_conn.resp_body =~ header
    end

    test "the :paywall default leaves browser 402 responses byte-identical" do
      default_conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [@route], facilitator: self())

      explicit_nil_conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [@route], facilitator: self(), paywall: nil)

      assert default_conn.status == 402
      assert default_conn.resp_body == "{}"
      assert get_resp_header(default_conn, "content-type") == ["application/json; charset=utf-8"]

      assert explicit_nil_conn.status == default_conn.status
      assert explicit_nil_conn.resp_body == default_conn.resp_body
      assert Enum.sort(explicit_nil_conn.resp_headers) == Enum.sort(default_conn.resp_headers)
    end

    test "escapes hostile route descriptions and service names" do
      route =
        @route
        |> Map.put(:description, "<script>alert('pwn')</script>")
        |> Map.put(:service_name, "\"><img src=x onerror=alert(1)>")

      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [route], facilitator: self(), paywall: X402.Paywall.Default)

      assert conn.status == 402
      refute conn.resp_body =~ "<script>alert"
      refute conn.resp_body =~ "<img src=x"
      assert conn.resp_body =~ "&lt;script&gt;alert(&#39;pwn&#39;)&lt;/script&gt;"
      assert conn.resp_body =~ "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"
    end

    test "dispatches to a custom X402.Paywall module" do
      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> run_request(routes: [@route], facilitator: self(), paywall: CustomPaywall)

      assert conn.status == 402
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]

      assert conn.resp_body ==
               "custom-paywall:GET:/api/resource:402:PAYMENT-SIGNATURE header is required"
    end

    test "falls back to JSON when the paywall renderer fails" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn =
            conn(:get, "/api/resource")
            |> browser_conn()
            |> run_request(routes: [@route], facilitator: self(), paywall: FailingPaywall)

          assert conn.status == 402
          assert conn.resp_body == "{}"
          assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
          assert get_resp_header(conn, "payment-required") != []
        end)

      assert log =~ "paywall renderer"
      assert log =~ ":boom"
    end

    test "keeps 400 invalid-payload responses JSON even for browsers" do
      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> put_req_header("payment-signature", "%%% not base64 %%%")
        |> run_request(routes: [@route], facilitator: self(), paywall: X402.Paywall.Default)

      assert conn.status == 400
      assert conn.resp_body == "{}"
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
    end

    test "serves the paywall on browser 402s for rejected payments" do
      reject =
        start_mock_facilitator(
          verify:
            {:ok, %{status: 200, body: %{"isValid" => false, "invalidReason" => "declined"}}}
        )

      conn =
        conn(:get, "/api/resource")
        |> browser_conn()
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: reject, paywall: X402.Paywall.Default)

      assert conn.status == 402
      assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
      assert conn.resp_body =~ "<!DOCTYPE html>"
    end

    test "init rejects modules that do not implement X402.Paywall" do
      assert_raise NimbleOptions.ValidationError, ~r/X402\.Paywall/, fn ->
        PaymentGate.init(routes: [@route], paywall: __MODULE__)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Inline local verification (:local_verification option)
  # ---------------------------------------------------------------------------

  @eip712_extra %{"name" => "USDC", "version" => "2"}

  describe "local verification" do
    test "init/1 normalizes a bare level atom into a keyword list" do
      opts = PaymentGate.init(routes: [@route], local_verification: :structural)

      assert opts.local_verification[:level] == :structural
      assert opts.local_verification[:simulate] == true

      assert %{local_verification: nil} = PaymentGate.init(routes: [@route])
    end

    test "init/1 requires :rpc for level :full" do
      assert_raise NimbleOptions.ValidationError, ~r/requires :rpc/, fn ->
        PaymentGate.init(routes: [@route], local_verification: :full)
      end

      assert_raise NimbleOptions.ValidationError, ~r/requires :rpc/, fn ->
        PaymentGate.init(routes: [@route], local_verification: [level: :full])
      end
    end

    test "init/1 rejects unknown local_verification shapes" do
      assert_raise NimbleOptions.ValidationError, ~r/verification level/, fn ->
        PaymentGate.init(routes: [@route], local_verification: :bogus)
      end

      assert_raise NimbleOptions.ValidationError, ~r/:level/, fn ->
        PaymentGate.init(routes: [@route], local_verification: [simulate: false])
      end
    end

    test "init/1 accepts simulate: :counterfactual_only" do
      opts =
        PaymentGate.init(
          routes: [@route],
          local_verification: [level: :structural, simulate: :counterfactual_only]
        )

      assert opts.local_verification[:simulate] == :counterfactual_only
    end

    test ":full passes simulate: :counterfactual_only through to Verify.EVM" do
      facilitator = start_mock_facilitator()

      rpc_bypass = Bypass.open()
      finch = String.to_atom("gate_rpc_finch_#{System.unique_integer([:positive, :monotonic])}")
      start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))
      rpc = TestRPCStub.stub_rpc(rpc_bypass, finch)

      stub = TestRPCStub.defaults()

      requirements = %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => @amount,
        "asset" => stub.asset,
        "payTo" => stub.pay_to,
        "maxTimeoutSeconds" => 60,
        "extra" => @eip712_extra
      }

      # The stub's configured payer is the address of this well-known key.
      {:ok, signer} = LocalKey.new("0x" <> String.duplicate("11", 32))
      {:ok, scheme_payload} = EIP3009.sign(requirements, signer, valid_after_buffer: 60)

      header =
        encode_header(%{
          "x402Version" => 2,
          "accepted" => requirements,
          "payload" => scheme_payload
        })

      route = %{
        method: :get,
        path: "/api/resource",
        price: @amount,
        network: @network,
        asset: stub.asset,
        pay_to: stub.pay_to,
        extra: @eip712_extra
      }

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [route],
          facilitator: facilitator,
          local_verification: [level: :full, rpc: rpc, simulate: :counterfactual_only]
        )

      assert conn.status == 200
      assert_receive {:verify_called, _payload, _requirements}

      # Local verification ran at :full against the RPC...
      assert_received {:rpc, "eth_getCode", _params}

      # ...and :counterfactual_only skipped the EOA transfer simulation —
      # simulate: true (the default) would eth_call transferWithAuthorization.
      refute_received {:rpc, "eth_call", [%{"data" => "0xe3ee160e" <> _}, _block]}
      refute_received {:rpc, "eth_call", [%{"data" => "0xcf092995" <> _}, _block]}
    end

    test ":structural passes a well-formed payment through to the facilitator" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extra, @eip712_extra)

      header =
        valid_payment_payload()
        |> put_in(["accepted", "extra"], @eip712_extra)
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator, local_verification: :structural)

      assert conn.status == 200
      assert_receive {:verify_called, _payload, _requirements}
      assert_receive {:settle_called, _payload, _requirements}
    end

    test ":structural rejection answers 402 like a facilitator rejection, without calling it" do
      facilitator = start_mock_facilitator()

      # @route advertises no EIP-712 domain (empty extra), which structural
      # verification requires — a mismatch the cheap prechecks do not catch.
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(
          routes: [@route],
          facilitator: facilitator,
          local_verification: :structural
        )

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"
      refute_received {:verify_called, _, _}
    end

    test ":signature rejects a signature that does not recover the payer" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extra, @eip712_extra)

      header =
        valid_payment_payload()
        |> put_in(["accepted", "extra"], @eip712_extra)
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator, local_verification: :signature)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"
      refute_received {:verify_called, _, _}
    end

    test ":full fails closed with 500 when the RPC endpoint is unreachable" do
      facilitator = start_mock_facilitator()
      rpc_bypass = Bypass.open()
      Bypass.down(rpc_bypass)

      finch = String.to_atom("gate_rpc_finch_#{System.unique_integer([:positive, :monotonic])}")
      start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))
      {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{rpc_bypass.port}", finch: finch)

      route = Map.put(@route, :extra, @eip712_extra)

      header =
        valid_payment_payload()
        |> put_in(["accepted", "extra"], @eip712_extra)
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(
          routes: [route],
          facilitator: facilitator,
          local_verification: [level: :full, rpc: rpc]
        )

      assert conn.status == 500
      assert conn.resp_body == "{}"
      refute_received {:verify_called, _, _}
    end

    test "skips local verification for non exact-EVM payments" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> run_request(
          routes: [@upto_route],
          facilitator: facilitator,
          local_verification: :structural
        )

      assert conn.status == 200
      assert_receive {:verify_called, _payload, _requirements}
    end
  end

  # ---------------------------------------------------------------------------
  # Canonical replay keys
  # ---------------------------------------------------------------------------

  defmodule NoteScheme do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "note"

    @impl X402.Scheme
    def networks, do: ["local:*"]
  end

  @note_route %{
    method: :get,
    path: "/note/resource",
    scheme: "note",
    price: "5000",
    network: "local:test",
    asset: "note",
    pay_to: "till"
  }

  describe "canonical replay keys" do
    test "rejects a re-encoded duplicate of the same authorization without a facilitator call" do
      bypass = Bypass.open()
      finch = String.to_atom("payment_gate_finch_#{System.unique_integer([:positive])}")

      facilitator_name =
        String.to_atom("payment_gate_facilitator_#{System.unique_integer([:positive])}")

      start_supervised!({Finch, name: finch})

      # expect_once fails the test if either endpoint is hit more than once,
      # proving the re-encoded duplicate below causes zero facilitator calls.
      Bypass.expect_once(bypass, "POST", "/verify", fn bypass_conn ->
        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      Bypass.expect_once(bypass, "POST", "/settle", fn bypass_conn ->
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

      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      payload = valid_payment_payload()
      header = encode_header(payload)
      reencoded = payload |> Jason.encode!(pretty: true) |> Base.encode64()
      assert reencoded != header

      opts = [
        routes: [@route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert first.status == 200

      duplicate =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", reencoded)
        |> run_request(opts)

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
    end

    test "distinct authorization nonces settle independently" do
      facilitator = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})

      opts = [
        routes: [@route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      second_header =
        valid_payment_payload()
        |> put_in(["payload", "authorization", "nonce"], "0x" <> String.duplicate("ab", 32))
        |> encode_header()

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      second =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", second_header)
        |> run_request(opts)

      assert first.status == 200
      assert second.status == 200
      assert_receive {:settle_called, _, _}
      assert_receive {:settle_called, _, _}
    end

    test "upto replay keys derive from the signed permit nonce" do
      facilitator = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})

      opts = [
        routes: [@upto_route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      payload = valid_upto_payment_payload(@amount)
      header = encode_header(payload)
      reencoded = payload |> Jason.encode!(pretty: true) |> Base.encode64()
      assert reencoded != header

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert first.status == 200
      assert_receive {:verify_called, _, _}

      duplicate =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", reencoded)
        |> run_request(opts)

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
      refute_received {:verify_called, _, _}
    end

    test "svm replay keys derive from the signed message bytes" do
      facilitator = start_mock_facilitator()
      cache = start_supervised!({ETSCache, name: unique_cache_name()})
      solana_route = %{method: :get, path: "/api/resource", accepts: [@solana_accept]}

      payment_required =
        conn(:get, "/api/resource")
        |> run_request(routes: [solana_route], facilitator: facilitator)
        |> decode_payment_required!()

      {:ok, solana_signer} = SolanaKey.new(:crypto.strong_rand_bytes(32))
      {:ok, solana_payload} = Client.build_payment(payment_required, solana_signer)

      header = encode_header(solana_payload)
      reencoded = solana_payload |> Jason.encode!(pretty: true) |> Base.encode64()
      assert reencoded != header

      opts = [
        routes: [solana_route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      first =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert first.status == 200
      assert_receive {:verify_called, _, _}

      duplicate =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", reencoded)
        |> run_request(opts)

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
      refute_received {:verify_called, _, _}
    end

    test "unknown schemes fall back to header-hash keying" do
      facilitator =
        start_mock_facilitator(
          settle:
            {:ok,
             %{
               status: 200,
               body: %{
                 "success" => true,
                 "transaction" => "note-receipt-1",
                 "network" => "local:test",
                 "payer" => "payer-1"
               }
             }}
        )

      cache = start_supervised!({ETSCache, name: unique_cache_name()})

      opts = [
        routes: [@note_route],
        schemes: [NoteScheme],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        claim_order: :before_verify
      ]

      payload = %{
        "x402Version" => 2,
        "resource" => %{
          "url" => "http://www.example.com/note/resource",
          "description" => "Payment required",
          "mimeType" => "application/json"
        },
        "accepted" => %{
          "scheme" => "note",
          "network" => "local:test",
          "amount" => "5000",
          "asset" => "note",
          "payTo" => "till",
          "maxTimeoutSeconds" => 60,
          "extra" => %{}
        },
        "payload" => %{"note" => "IOU 5000"},
        "extensions" => %{}
      }

      header = encode_header(payload)
      reencoded = payload |> Jason.encode!(pretty: true) |> Base.encode64()
      assert reencoded != header

      first =
        conn(:get, "/note/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert first.status == 200

      # Without a signed per-family identity the key is the raw-header
      # hash, so a re-encoding of the same proof is NOT caught — pinned
      # here as the documented fallback behavior.
      resubmitted =
        conn(:get, "/note/resource")
        |> put_req_header("payment-signature", reencoded)
        |> run_request(opts)

      assert resubmitted.status == 200

      # A byte-identical replay still is.
      duplicate =
        conn(:get, "/note/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(opts)

      assert duplicate.status == 402
      assert decode_payment_required!(duplicate)["error"] == "payment already processed"
    end
  end

  # ---------------------------------------------------------------------------
  # Payment identifier extension surfacing
  # ---------------------------------------------------------------------------

  describe "payment identifier extension" do
    test "assigns x402_payment_id and tags telemetry for a well-formed extension" do
      facilitator = start_mock_facilitator()
      handler_id = "payment-id-#{System.unique_integer([:positive, :monotonic])}"
      parent = self()

      :ok =
        :telemetry.attach(
          handler_id,
          [:x402, :plug, :payment_verified],
          fn _event, _measurements, metadata, _config ->
            send(parent, {:verified_metadata, metadata})
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      {:ok, encoded} = PaymentIdentifier.encode("pay-123")

      header =
        valid_payment_payload()
        |> Map.put("extensions", %{"paymentIdentifier" => encoded})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns[:x402_payment_id] == "pay-123"
      assert_receive {:verified_metadata, %{payment_id: "pay-123"}}
    end

    test "accepts the decoded map form of the extension" do
      facilitator = start_mock_facilitator()

      header =
        valid_payment_payload()
        |> Map.put("extensions", %{"paymentIdentifier" => %{"paymentId" => "pay-9"}})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns[:x402_payment_id] == "pay-9"
    end

    test "accepts the info-wrapped envelope map form the echo matcher honors" do
      facilitator = start_mock_facilitator()

      # The route advertises the generic %{"info" => ..., "schema" => ...}
      # envelope; the client's echo passes validate_extensions (the matcher
      # unwraps "info" on both sides), so extraction must honor the same
      # envelope instead of rejecting the payment as malformed.
      route =
        Map.put(@route, :extensions, %{
          "paymentIdentifier" => %{"schema" => "https://x402.org/ext", "info" => %{}}
        })

      header =
        valid_payment_payload()
        |> Map.put("extensions", %{
          "paymentIdentifier" => %{
            "schema" => "https://x402.org/ext",
            "info" => %{"paymentId" => "pay-env-1"}
          }
        })
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns[:x402_payment_id] == "pay-env-1"
    end

    test "accepts the info-wrapped Base64 string form of the extension" do
      facilitator = start_mock_facilitator()
      {:ok, encoded} = PaymentIdentifier.encode("pay-env-2")

      header =
        valid_payment_payload()
        |> Map.put("extensions", %{"paymentIdentifier" => %{"info" => encoded}})
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns[:x402_payment_id] == "pay-env-2"
    end

    test "rejects info-wrapped garbage with 400 before any facilitator call" do
      facilitator = start_mock_facilitator()

      malformed_envelopes = [
        %{"info" => "%%% not base64 %%%"},
        %{"info" => %{}},
        %{"info" => %{"paymentId" => ""}},
        %{"info" => 42}
      ]

      for malformed <- malformed_envelopes do
        conn =
          conn(:get, "/api/resource")
          |> put_req_header(
            "payment-signature",
            valid_payment_payload()
            |> Map.put("extensions", %{"paymentIdentifier" => malformed})
            |> encode_header()
          )
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 400

        assert decode_payment_required!(conn)["error"] ==
                 "invalid payment identifier extension"
      end

      refute_received {:verify_called, _, _}
    end

    test "rejects a malformed extension with 400 before any facilitator call" do
      facilitator = start_mock_facilitator()

      for malformed <- ["%%% not base64 %%%", %{}, %{"paymentId" => ""}, 42] do
        conn =
          conn(:get, "/api/resource")
          |> put_req_header(
            "payment-signature",
            valid_payment_payload()
            |> Map.put("extensions", %{"paymentIdentifier" => malformed})
            |> encode_header()
          )
          |> run_request(routes: [@route], facilitator: facilitator)

        assert conn.status == 400

        assert decode_payment_required!(conn)["error"] ==
                 "invalid payment identifier extension"
      end

      refute_received {:verify_called, _, _}
    end

    test "absent extension leaves the assign unset" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      refute Map.has_key?(conn.assigns, :x402_payment_id)
    end
  end

  # ---------------------------------------------------------------------------
  # settlement_pending settle retry
  # ---------------------------------------------------------------------------

  describe "settlement_pending settle retry" do
    test "retries the settle once when settlement_pending carries a transaction hash" do
      bypass = Bypass.open()

      Bypass.stub(bypass, "POST", "/verify", fn bypass_conn ->
        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      {:ok, counter} = Agent.start_link(fn -> 0 end)

      Bypass.expect(bypass, "POST", "/settle", fn bypass_conn ->
        body =
          case Agent.get_and_update(counter, fn count -> {count + 1, count + 1} end) do
            1 ->
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => "0xpending",
                "network" => @network
              }

            _later ->
              %{
                "success" => true,
                "transaction" => "0xsettled",
                "network" => @network,
                "payer" => @receiver
              }
          end

        Plug.Conn.resp(bypass_conn, 200, Jason.encode!(body))
      end)

      facilitator = start_facilitator(url: "http://localhost:#{bypass.port}")

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
      assert decode_payment_response!(conn)["success"] == true
      assert decode_payment_response!(conn)["transaction"] == "0xsettled"
      assert Agent.get(counter, & &1) == 2
    end

    test "a second settlement_pending follows the normal failure path" do
      bypass = Bypass.open()

      Bypass.stub(bypass, "POST", "/verify", fn bypass_conn ->
        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      {:ok, counter} = Agent.start_link(fn -> 0 end)

      Bypass.expect(bypass, "POST", "/settle", fn bypass_conn ->
        Agent.update(counter, &(&1 + 1))

        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{
            "success" => false,
            "errorReason" => "settlement_pending",
            "transaction" => "0xpending",
            "network" => @network
          })
        )
      end)

      facilitator = start_facilitator(url: "http://localhost:#{bypass.port}")

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      response = decode_payment_response!(conn)
      assert response["success"] == false
      assert response["errorReason"] == "settlement_pending"
      assert Agent.get(counter, & &1) == 2
    end

    test "settlement_pending without a transaction hash is not retried" do
      bypass = Bypass.open()

      Bypass.stub(bypass, "POST", "/verify", fn bypass_conn ->
        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{"isValid" => true, "payer" => @receiver})
        )
      end)

      {:ok, counter} = Agent.start_link(fn -> 0 end)

      Bypass.expect(bypass, "POST", "/settle", fn bypass_conn ->
        Agent.update(counter, &(&1 + 1))

        Plug.Conn.resp(
          bypass_conn,
          200,
          Jason.encode!(%{
            "success" => false,
            "errorReason" => "settlement_pending",
            "transaction" => "",
            "network" => @network
          })
        )
      end)

      facilitator = start_facilitator(url: "http://localhost:#{bypass.port}")

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 402
      assert Agent.get(counter, & &1) == 1
    end
  end

  # ---------------------------------------------------------------------------
  # Route and option validation edge cases
  # ---------------------------------------------------------------------------

  describe "route and option validation edge cases" do
    test "validate_route/1 validates a route map against the built-in schemes" do
      assert {:ok, %{path: "/api/resource"}} = PaymentGate.validate_route(@route)
    end

    test "validate_route/1 rejects non-map routes" do
      assert PaymentGate.validate_route(path: "/api/resource") ==
               {:error, "expected a route map"}
    end

    test "validate_route/1 rejects non-atom route option keys" do
      assert PaymentGate.validate_route(%{1 => "/api/resource"}) ==
               {:error, "invalid route option key: 1"}
    end

    test "init/1 rejects non-map extra values" do
      assert_raise NimbleOptions.ValidationError, ~r/expected a map/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :extra, "not-a-map")])
      end
    end

    test "init/1 rejects non-binary prices" do
      assert_raise NimbleOptions.ValidationError, ~r/digit-only/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :price, 10_000)])
      end
    end

    test "accepts entries advertise only the supported payment flow" do
      accept = %{
        price: @amount,
        network: @network,
        asset: @asset,
        pay_to: @receiver,
        extra: %{"paymentFlow" => "authorization"}
      }

      route = %{method: :get, path: "/flow", accepts: [accept]}

      assert {:ok, _validated} = PaymentGate.validate_route(route)

      streaming = %{route | accepts: [put_in(accept, [:extra, "paymentFlow"], "streaming")]}

      assert PaymentGate.validate_route(streaming) ==
               {:error, ~s(unsupported payment flow: "streaming")}
    end
  end

  # ---------------------------------------------------------------------------
  # Advertised requirements normalization
  # ---------------------------------------------------------------------------

  describe "advertised requirements normalization" do
    test "omits empty serviceName and iconUrl from ResourceInfo" do
      route = @route |> Map.put(:service_name, "") |> Map.put(:icon_url, "")

      required =
        conn(:get, "/api/resource")
        |> run_request(routes: [route], facilitator: self())
        |> decode_payment_required!()

      refute Map.has_key?(required["resource"], "serviceName")
      refute Map.has_key?(required["resource"], "iconUrl")
    end

    test "stringifies atom keys in advertised extra and extensions" do
      route =
        @route
        |> Map.put(:extra, %{name: "USDC"})
        |> Map.put(:extensions, %{payment_identifier: %{"info" => %{}}})

      required =
        conn(:get, "/api/resource")
        |> run_request(routes: [route], facilitator: self())
        |> decode_payment_required!()

      assert [accept] = required["accepts"]
      assert accept["extra"] == %{"name" => "USDC"}
      assert required["extensions"] == %{"payment_identifier" => %{"info" => %{}}}
    end
  end

  # ---------------------------------------------------------------------------
  # Payment payload rejection edge cases
  # ---------------------------------------------------------------------------

  describe "payment payload rejection edge cases" do
    test "rejects payloads whose accepted object has invalid field types" do
      header =
        valid_payment_payload()
        |> put_in(["accepted", "amount"], 10_000)
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [@route], facilitator: self())

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"
    end

    test "rejects oversized payment headers" do
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", String.duplicate("A", 8_193))
        |> run_request(routes: [@route], facilitator: self())

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid payment header"
    end

    test "skips local prechecks for kinds with no registered scheme module" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :network, "othernet:1")

      header =
        valid_payment_payload()
        |> put_in(["accepted", "network"], "othernet:1")
        |> encode_header()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", header)
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 200
      assert_receive {:verify_called, _payload, %{"network" => "othernet:1"}}
      assert_receive {:settle_called, _payload, _requirements}
    end
  end

  # ---------------------------------------------------------------------------
  # Settlement amount edge cases
  # ---------------------------------------------------------------------------

  describe "settlement amount edge cases" do
    test "put_settlement_amount/2 normalizes integer amounts" do
      assert {:ok, conn} = PaymentGate.put_settlement_amount(conn(:get, "/paid"), 7_500)
      assert conn.private[:x402_settlement_amount] == "7500"
    end

    test "put_settlement_amount/2 rejects non-amount values" do
      assert PaymentGate.put_settlement_amount(conn(:get, "/paid"), :free) ==
               {:error, :invalid_settlement_amount}
    end

    test "settles an upto payment for a zero atomic amount" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> gate_request(routes: [@upto_route], facilitator: facilitator)

      assert {:ok, gated_conn} = PaymentGate.put_settlement_amount(gated_conn, "0")
      response_conn = Plug.Conn.send_resp(gated_conn, 200, "free this time")

      assert response_conn.status == 200
      assert_receive {:settle_called, _payload, %{"amount" => "0"}}
    end

    test "fails closed when the settlement amount private is not an atomic amount" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_upto_payment_header(@amount))
        |> gate_request(routes: [@upto_route], facilitator: facilitator)

      tampered_conn = Plug.Conn.put_private(gated_conn, :x402_settlement_amount, :free)
      response_conn = Plug.Conn.send_resp(tampered_conn, 200, "usage complete")

      assert response_conn.status == 500
      assert decode_payment_required!(response_conn)["error"] == "payment processing failed"
      refute_received {:settle_called, _payload, _requirements}
    end

    test "does not settle when a before_send callback runs without a response status" do
      facilitator = start_mock_facilitator()

      gated_conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> gate_request(routes: [@route], facilitator: facilitator)

      assert_receive {:verify_called, _payload, _requirements}
      [settle_callback] = gated_conn.private[:before_send]

      returned_conn = settle_callback.(gated_conn)

      assert returned_conn.status == nil
      assert get_resp_header(returned_conn, "payment-response") == []
      refute_received {:settle_called, _payload, _requirements}
    end
  end

  # ---------------------------------------------------------------------------
  # Facilitator response shape validation — hook-replaced results exercise the
  # defensive clauses for responses the HTTP transport itself never produces.
  # ---------------------------------------------------------------------------

  describe "facilitator response shape validation" do
    test "rejects verify results without a map body" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_verify_result, %{status: 200, body: []})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end

    test "rejects verify results with an unexpected HTTP status" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_verify_result, %{status: 503})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end

    test "rejects verify results without a status" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_verify_result, %{})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end

    test "rejects settle results without a map body" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_settle_result, %{status: 200, body: []})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
      assert get_resp_header(conn, "payment-response") == []
    end

    test "rejects settle results with an unexpected HTTP status" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_settle_result, %{status: 502})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end

    test "rejects settle results without a status" do
      facilitator = start_mock_facilitator()
      Process.put(:staged_settle_result, %{})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 500
      assert decode_payment_required!(conn)["error"] == "payment processing failed"
    end
  end

  # ---------------------------------------------------------------------------
  # Facilitator failure reason mapping
  # ---------------------------------------------------------------------------

  describe "facilitator failure reason mapping" do
    test "surfaces a binary settlement failure reason as a PAYMENT-RESPONSE" do
      facilitator = start_mock_facilitator(settle: {:ok, %{status: 500, body: %{}}})
      Process.put(:staged_settle_error, {:settlement_failed, "facilitator exploded"})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 402

      assert decode_payment_response!(conn) == %{
               "success" => false,
               "errorReason" => "facilitator exploded",
               "transaction" => "",
               "network" => ""
             }
    end

    test "stringifies non-binary settlement failure reasons" do
      facilitator = start_mock_facilitator(settle: {:ok, %{status: 500, body: %{}}})
      Process.put(:staged_settle_error, {:settlement_failed, :insufficient_funds})

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

      assert conn.status == 402
      assert decode_payment_response!(conn)["errorReason"] == "insufficient_funds"
    end

    test "maps hook-normalized verify failure reasons onto transport statuses" do
      for {reason, status, error} <- [
            {{:unsupported_x402_version, 1}, 400, "unsupported x402 version"},
            {:invalid_payment_requirements, 400, "invalid_payload"},
            {{:payment_response_encoding_failed, :boom}, 500, "payment processing failed"}
          ] do
        facilitator = start_mock_facilitator(verify: {:ok, %{status: 500, body: %{}}})
        Process.put(:staged_verify_error, reason)

        conn =
          conn(:get, "/api/resource")
          |> put_req_header("payment-signature", valid_payment_header())
          |> run_request(routes: [@route], facilitator: facilitator, hooks: StagedResultHooks)

        assert conn.status == status
        assert decode_payment_required!(conn)["error"] == error
      end
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

  defp unique_cache_name do
    String.to_atom("payment_gate_cache_#{System.unique_integer([:positive, :monotonic])}")
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

  defp valid_upto_payment_header(value), do: encode_header(valid_upto_payment_payload(value))

  defp valid_upto_payment_payload(value) do
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
  end

  defp encode_header(payload) when is_map(payload) do
    payload |> Jason.encode!() |> Base.encode64()
  end

  # Starts a real `X402.Facilitator` (operations execute in the calling
  # process) backed by a Bypass HTTP stub that serves canned verify/settle
  # results and notifies the test process of every facilitator call.
  defp start_mock_facilitator(opts \\ []) do
    owner = self()
    verify = Keyword.get(opts, :verify, @default_verify)
    settle = Keyword.get(opts, :settle, @default_settle)

    bypass = Bypass.open()
    stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, verify)
    stub_facilitator_endpoint(bypass, owner, "/settle", :settle_called, settle)

    start_facilitator(url: "http://localhost:#{bypass.port}")
  end

  defp stub_facilitator_endpoint(bypass, owner, path, tag, {:ok, %{status: status, body: body}}) do
    Bypass.stub(bypass, "POST", path, fn conn ->
      {:ok, request_body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(request_body)
      send(owner, {tag, decoded["paymentPayload"], decoded["paymentRequirements"]})
      Plug.Conn.resp(conn, status, Jason.encode!(body))
    end)
  end

  defp start_facilitator(opts) do
    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("payment_gate_finch_#{suffix}")
    name = String.to_atom("payment_gate_facilitator_#{suffix}")

    start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

    start_supervised!(
      {Facilitator,
       Keyword.merge([name: name, finch: finch, max_retries: 0, receive_timeout_ms: 1_000], opts)}
    )
  end
end
