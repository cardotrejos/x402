defmodule X402.Plug.PaymentGateLifecycleTest do
  @moduledoc """
  Tests for the resource-server parity features of `X402.Plug.PaymentGate`:

  * `:param` route templates and the `:x402_path_params` assign
  * dynamic pricing (function-valued route fields)
  * bazaar `routeTemplate` / `pathParams` advertisement
  * `on_protected_request` / `on_verified_payment_canceled` hooks
  * `X402.Extension` adapters and the `builder-code` echo rules
  """

  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.BuilderCode
  alias X402.Extensions.PaymentIdentifier
  alias X402.Facilitator
  alias X402.Hooks.RequestContext
  alias X402.PaymentRequired
  alias X402.Plug.PaymentGate

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @other_receiver "0x2222222222222222222222222222222222222222"
  @network "eip155:84532"
  @amount "10000"
  @premium_amount "20000"

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

  @failed_settle {
    :ok,
    %{
      status: 200,
      body: %{
        "success" => false,
        "errorReason" => "insufficient_funds",
        "transaction" => "",
        "network" => "eip155:84532"
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

  @param_route %{@route | path: "/api/users/:id/reports/:report_id"}

  # ---------------------------------------------------------------------------
  # Hook modules
  # ---------------------------------------------------------------------------

  # Forwards every resource-server callback to the test process, and lets
  # the test pick the on_protected_request result through the process
  # dictionary-free route: the result is stored in the conn's private map.
  defmodule RecordingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    alias X402.Hooks.RequestContext

    def on_protected_request(%RequestContext{} = context, metadata) do
      send(self(), {:on_protected_request, context, metadata})
      protected_request_result(context)
    end

    def on_verified_payment_canceled(%RequestContext{} = context, metadata) do
      send(self(), {:on_verified_payment_canceled, context, metadata})
      :ok
    end

    defp protected_request_result(%RequestContext{conn: %Plug.Conn{} = conn} = context) do
      case conn.private[:hook_result] do
        nil -> {:cont, context}
        :discount -> {:cont, %{context | requirements: discounted(context.requirements)}}
        :extensions -> {:cont, %{context | extensions: %{"custom" => %{"info" => %{}}}}}
        result -> result
      end
    end

    defp protected_request_result(context), do: {:cont, context}

    defp discounted(requirements) do
      Enum.map(requirements, &Map.put(&1, "amount", "5000"))
    end
  end

  defmodule BrokenHooks do
    @moduledoc false
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def on_protected_request(_context, _metadata), do: :whatever

    def on_verified_payment_canceled(_context, _metadata), do: raise("cancel boom")
  end

  defmodule RaisingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def on_protected_request(_context, _metadata), do: raise("protected boom")
  end

  defmodule CancelRaisingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def on_verified_payment_canceled(_context, _metadata), do: raise("cancel boom")
  end

  # ---------------------------------------------------------------------------
  # Extension adapters
  # ---------------------------------------------------------------------------

  defmodule RecordingAdapter do
    @moduledoc false
    @behaviour X402.Extension

    def key, do: "recording"

    def init(opts), do: {:ok, Keyword.put_new(opts, :reject, false)}

    def advertise(opts, %X402.Hooks.RequestContext{} = context) do
      send(self(), {:adapter_advertise, context.path})
      %{"info" => %{"path" => context.path, "reject" => opts[:reject]}}
    end

    def validate(echoed, advertised, opts) do
      send(self(), {:adapter_validate, echoed, advertised})

      case opts[:reject] do
        true -> {:error, :rejected_by_adapter}
        false -> :ok
      end
    end

    def after_verify(_payload, _requirements, response, _opts),
      do: send(self(), {:adapter_after_verify, response.status})

    def after_settle(_payload, _requirements, response, _opts),
      do: send(self(), {:adapter_after_settle, response.body["transaction"]})
  end

  # ---------------------------------------------------------------------------
  # Route templates and path params
  # ---------------------------------------------------------------------------

  describe ":param route templates" do
    test "match one non-empty segment per parameter and assign the captures" do
      facilitator = start_mock_facilitator()

      conn =
        run_request(conn(:get, "/api/users/42/reports/q3"),
          routes: [@param_route],
          facilitator: facilitator
        )

      assert conn.status == 402
      assert conn.assigns.x402_path_params == %{"id" => "42", "report_id" => "q3"}

      payload = decode_payment_required!(conn)
      assert payload["resource"]["url"] == "http://www.example.com/api/users/42/reports/q3"
    end

    test "do not match missing, empty, or extra segments" do
      facilitator = start_mock_facilitator()

      for path <- [
            "/api/users/42/reports",
            "/api/users//reports/q3",
            "/api/users/42/reports/q3/extra",
            "/api/users/42/other/q3"
          ] do
        conn = run_request(conn(:get, path), routes: [@param_route], facilitator: facilitator)
        assert conn.status == 200, "expected #{path} to pass through"
        refute Map.has_key?(conn.assigns, :x402_path_params)
      end
    end

    test "decode percent-encoded captures" do
      facilitator = start_mock_facilitator()

      conn =
        run_request(conn(:get, "/api/users/a%20b/reports/r%3A1"),
          routes: [@param_route],
          facilitator: facilitator
        )

      assert conn.status == 402
      assert conn.assigns.x402_path_params == %{"id" => "a b", "report_id" => "r:1"}

      # An encoded slash decodes to a segment separator before matching, so
      # it can never smuggle a slash into a single parameter.
      slash =
        run_request(conn(:get, "/api/users/42/reports/r%2F1"),
          routes: [@param_route],
          facilitator: facilitator
        )

      assert slash.status == 200
    end

    test "exact and glob routes never assign path params" do
      facilitator = start_mock_facilitator()

      exact = run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: facilitator)
      refute Map.has_key?(exact.assigns, :x402_path_params)

      glob =
        run_request(conn(:get, "/api/anything"),
          routes: [%{@route | path: "/api/*"}],
          facilitator: facilitator
        )

      assert glob.status == 402
      refute Map.has_key?(glob.assigns, :x402_path_params)
    end

    test "paid requests on a template route settle with the concrete requirements" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/users/42/reports/q3")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@param_route], facilitator: facilitator)

      assert conn.status == 200
      assert conn.assigns.x402_path_params == %{"id" => "42", "report_id" => "q3"}
      assert_receive {:verify_called, _payload, %{"amount" => @amount}}
      assert_receive {:settle_called, _payload, _requirements}
    end

    test "init rejects malformed, duplicate, and glob-mixed parameters" do
      for path <- ["/api/:", "/api/:1bad", "/api/:id/:id", "/api/:id/*"] do
        assert_raise NimbleOptions.ValidationError, fn ->
          PaymentGate.init(routes: [%{@route | path: path}], facilitator: Facilitator)
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Dynamic pricing
  # ---------------------------------------------------------------------------

  describe "dynamic route fields" do
    test "price functions resolve per request, before the 402 and the match" do
      facilitator = start_mock_facilitator()

      route =
        Map.put(@route, :price, fn conn ->
          case get_req_header(conn, "x-tier") do
            ["premium"] -> @premium_amount
            _other -> @amount
          end
        end)

      standard =
        run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)

      assert [%{"amount" => @amount}] = decode_payment_required!(standard)["accepts"]

      premium =
        conn(:get, "/api/resource")
        |> put_req_header("x-tier", "premium")
        |> run_request(routes: [route], facilitator: facilitator)

      assert [%{"amount" => @premium_amount}] = decode_payment_required!(premium)["accepts"]

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("x-tier", "premium")
        |> put_req_header("payment-signature", payment_header(amount: @premium_amount))
        |> run_request(routes: [route], facilitator: facilitator)

      assert paid.status == 200
      assert_receive {:verify_called, _payload, %{"amount" => @premium_amount}}

      mismatched =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", payment_header(amount: @premium_amount))
        |> run_request(routes: [route], facilitator: facilitator)

      assert mismatched.status == 402
      assert decode_payment_required!(mismatched)["error"] == "No matching payment requirements"
    end

    test "price functions see the path params assign" do
      facilitator = start_mock_facilitator()

      route =
        Map.put(@param_route, :price, fn conn ->
          if conn.assigns.x402_path_params["report_id"] == "premium",
            do: {:ok, @premium_amount},
            else: {:ok, @amount}
        end)

      conn =
        run_request(conn(:get, "/api/users/1/reports/premium"),
          routes: [route],
          facilitator: facilitator
        )

      assert [%{"amount" => @premium_amount}] = decode_payment_required!(conn)["accepts"]
    end

    test "pay_to, description, and accepts may be functions" do
      facilitator = start_mock_facilitator()

      route = %{
        method: :get,
        path: "/api/resource",
        description: fn _conn -> "Dynamic description" end,
        accepts: fn conn ->
          receiver =
            case get_req_header(conn, "x-receiver") do
              [receiver] -> receiver
              [] -> @receiver
            end

          [%{price: @amount, network: @network, asset: @asset, pay_to: fn _conn -> receiver end}]
        end
      }

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("x-receiver", @other_receiver)
        |> run_request(routes: [route], facilitator: facilitator)

      payload = decode_payment_required!(conn)
      assert payload["resource"]["description"] == "Dynamic description"
      assert [%{"payTo" => @other_receiver, "amount" => @amount}] = payload["accepts"]
    end

    test "accept entries with function fields are resolved" do
      facilitator = start_mock_facilitator()

      route = %{
        method: :get,
        path: "/api/resource",
        accepts: [
          %{
            price: fn _conn -> @premium_amount end,
            network: @network,
            asset: @asset,
            pay_to: @receiver
          }
        ]
      }

      conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)
      assert [%{"amount" => @premium_amount}] = decode_payment_required!(conn)["accepts"]
    end

    test "an {:error, reason} answers 500 without a PAYMENT-REQUIRED header and emits telemetry" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      route = Map.put(@route, :price, fn _conn -> {:error, :pricing_unavailable} end)

      conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)

      assert conn.status == 500
      assert conn.halted
      assert get_resp_header(conn, "payment-required") == []
      refute conn.resp_body =~ "pricing_unavailable"

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:dynamic_route_error, {:price, :pricing_unavailable}}}}
    end

    test "invalid dynamic values fail closed with 500" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      invalid_routes = [
        {Map.put(@route, :price, fn _conn -> "1.5" end), :price},
        {Map.put(@route, :pay_to, fn _conn -> "" end), :pay_to},
        {Map.put(@route, :description, fn _conn -> 42 end), :description},
        {%{method: :get, path: "/api/resource", accepts: fn _conn -> [] end}, :accepts},
        {%{method: :get, path: "/api/resource", accepts: fn _conn -> :nope end}, :accepts},
        {%{
           method: :get,
           path: "/api/resource",
           accepts: fn _conn ->
             [%{price: @amount, network: @network, asset: @asset, pay_to: @receiver, scheme: "x"}]
           end
         }, :accepts},
        {%{
           method: :get,
           path: "/api/resource",
           accepts: fn _conn ->
             [
               %{
                 price: @amount,
                 network: @network,
                 asset: @asset,
                 pay_to: @receiver,
                 extra: %{"paymentFlow" => "escrow"}
               }
             ]
           end
         }, :accepts}
      ]

      for {route, field} <- invalid_routes do
        conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)
        assert conn.status == 500, "expected a 500 for an invalid dynamic #{field}"

        assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                        %{reason: {:dynamic_route_error, {^field, _detail}}}}
      end
    end

    test "init still validates static values and rejects non-function, non-string ones" do
      assert_raise NimbleOptions.ValidationError, ~r/1-arity function/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :price, 100)], facilitator: Facilitator)
      end

      assert_raise NimbleOptions.ValidationError, ~r/pay_to/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :pay_to, 100)], facilitator: Facilitator)
      end

      assert_raise NimbleOptions.ValidationError, ~r/description/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :description, 100)], facilitator: Facilitator)
      end

      assert_raise NimbleOptions.ValidationError, ~r/payment option maps/, fn ->
        PaymentGate.init(
          routes: [%{method: :get, path: "/api/resource", accepts: :nope}],
          facilitator: Facilitator
        )
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Bazaar advertisement
  # ---------------------------------------------------------------------------

  describe ":bazaar route option" do
    test "advertises routeTemplate and pathParams for template routes" do
      facilitator = start_mock_facilitator()
      route = Map.put(@param_route, :bazaar, method: :get, output: [type: "json"])

      conn =
        run_request(conn(:get, "/api/users/42/reports/q3"),
          routes: [route],
          facilitator: facilitator
        )

      bazaar = decode_payment_required!(conn)["extensions"]["bazaar"]
      assert bazaar["routeTemplate"] == "/api/users/:id/reports/:report_id"
      assert bazaar["info"]["input"]["method"] == "GET"
      assert bazaar["info"]["input"]["pathParams"] == %{"id" => "42", "report_id" => "q3"}
      assert bazaar["info"]["input"]["type"] == "http"
      assert bazaar["schema"]["properties"]["input"]["properties"]["pathParams"]
    end

    test "advertises neither for exact routes" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :bazaar, method: :get)

      conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)

      bazaar = decode_payment_required!(conn)["extensions"]["bazaar"]
      refute Map.has_key?(bazaar, "routeTemplate")
      refute Map.has_key?(bazaar["info"]["input"], "pathParams")
    end

    test "composes with static extensions and passes the echo check" do
      facilitator = start_mock_facilitator()

      route =
        @route
        |> Map.put(:bazaar, method: :get)
        |> Map.put(:extensions, %{"payment-identifier" => PaymentIdentifier.extension()})

      conn = run_request(conn(:get, "/api/resource"), routes: [route], facilitator: facilitator)
      extensions = decode_payment_required!(conn)["extensions"]
      assert Enum.sort(Map.keys(extensions)) == ["bazaar", "payment-identifier"]

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", payment_header(extensions: extensions))
        |> run_request(routes: [route], facilitator: facilitator)

      assert paid.status == 200
    end

    test "init rejects globs, invalid templates, and invalid bazaar options" do
      assert_raise NimbleOptions.ValidationError, ~r/glob/, fn ->
        PaymentGate.init(
          routes: [%{@route | path: "/api/*"} |> Map.put(:bazaar, method: :get)],
          facilitator: Facilitator
        )
      end

      assert_raise NimbleOptions.ValidationError, ~r/keyword list/, fn ->
        PaymentGate.init(routes: [Map.put(@route, :bazaar, %{})], facilitator: Facilitator)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(
          routes: [Map.put(@route, :bazaar, output: :nope)],
          facilitator: Facilitator
        )
      end
    end
  end

  # ---------------------------------------------------------------------------
  # on_protected_request
  # ---------------------------------------------------------------------------

  describe "on_protected_request" do
    test "runs before payment processing with the request context" do
      facilitator = start_mock_facilitator()

      conn =
        run_request(conn(:get, "/api/users/42/reports/q3"),
          routes: [@param_route],
          facilitator: facilitator,
          hooks: RecordingHooks
        )

      assert conn.status == 402

      assert_receive {:on_protected_request, %RequestContext{} = context,
                      %{method: :get, path: "/api/users/42/reports/q3"}}

      assert context.transport == :http
      assert %Plug.Conn{} = context.conn
      assert context.route.path == "/api/users/:id/reports/:report_id"
      assert context.method == :get
      assert context.path_params == %{"id" => "42", "report_id" => "q3"}
      assert [%{"amount" => @amount}] = context.requirements
      assert context.extensions == %{}
      assert is_nil(context.payload)
    end

    test "{:cont, context} with replaced requirements advertises and matches them" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, :discount)
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert [%{"amount" => "5000"}] = decode_payment_required!(conn)["accepts"]

      paid =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, :discount)
        |> put_req_header("payment-signature", payment_header(amount: "5000"))
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert paid.status == 200
      assert_receive {:verify_called, _payload, %{"amount" => "5000"}}
    end

    test "{:cont, context} with replaced extensions advertises them" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, :extensions)
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert decode_payment_required!(conn)["extensions"] == %{"custom" => %{"info" => %{}}}
    end

    test "{:halt, :skip_payment} lets the handler run unpaid and emits pass_through" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      conn =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, {:halt, :skip_payment})
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert conn.status == 200
      refute conn.halted
      assert get_resp_header(conn, "payment-required") == []

      assert_receive {:telemetry_event, [:x402, :plug, :pass_through], _measurements,
                      %{reason: :hook_skipped, route: "/api/resource", path: "/api/resource"}}

      refute_received {:verify_called, _payload, _requirements}
    end

    test "{:halt, {status, body}} sends the JSON body and halts" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      conn =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, {:halt, {403, %{"error" => "blocked", "code" => 7}}})
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert conn.status == 403
      assert conn.halted
      assert Jason.decode!(conn.resp_body) == %{"error" => "blocked", "code" => 7}
      assert get_resp_header(conn, "content-type") |> hd() =~ "application/json"
      assert get_resp_header(conn, "payment-required") == []

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:hook_halted, 403}}}
    end

    test "an unencodable halt body fails closed with 500" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_private(:hook_result, {:halt, {403, %{"error" => {:not, :json}}}})
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert conn.status == 500
      assert conn.halted
    end

    test "an invalid return or a raise fails closed with 500" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      invalid =
        run_request(conn(:get, "/api/resource"),
          routes: [@route],
          facilitator: facilitator,
          hooks: BrokenHooks
        )

      assert invalid.status == 500
      assert invalid.halted

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:hook_invalid_return, :on_protected_request, :whatever}}}

      raised =
        run_request(conn(:get, "/api/resource"),
          routes: [@route],
          facilitator: facilitator,
          hooks: RaisingHooks
        )

      assert raised.status == 500

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:hook_callback_failed, :on_protected_request, _error}}}
    end

    test "hook modules without the callback are unaffected" do
      facilitator = start_mock_facilitator()

      conn =
        run_request(conn(:get, "/api/resource"),
          routes: [@route],
          facilitator: facilitator,
          hooks: X402.Hooks.Default
        )

      assert conn.status == 402
    end
  end

  # ---------------------------------------------------------------------------
  # on_verified_payment_canceled
  # ---------------------------------------------------------------------------

  describe "on_verified_payment_canceled" do
    test "runs with :handler_failed when the handler answers 400 or above" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> gate_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)
        |> send_resp(503, "down")

      assert conn.status == 503
      assert_receive {:verify_called, _payload, _requirements}
      refute_received {:settle_called, _payload, _requirements}

      assert_receive {:on_verified_payment_canceled, %RequestContext{} = context,
                      %{reason: :handler_failed, response_status: 503, path: "/api/resource"}}

      assert context.payload["x402Version"] == 2
      assert context.matched_requirements["amount"] == @amount
    end

    test "runs with :settlement_failed when the facilitator declines settlement" do
      facilitator = start_mock_facilitator(settle: @failed_settle)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert conn.status == 402

      assert_receive {:on_verified_payment_canceled, %RequestContext{},
                      %{reason: :settlement_failed, error: {:settlement_failed, _reason}}}
    end

    test "does not run when a settlement failure carries a broadcast transaction" do
      broadcast =
        {:ok,
         %{
           status: 200,
           body: %{
             "success" => false,
             "errorReason" => "reverted",
             "transaction" => "0xabc",
             "network" => @network
           }
         }}

      facilitator = start_mock_facilitator(settle: broadcast)

      conn(:get, "/api/resource")
      |> put_req_header("payment-signature", valid_payment_header())
      |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert_receive {:settle_called, _payload, _requirements}
      refute_received {:on_verified_payment_canceled, _context, _metadata}
    end

    test "does not run on success" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(routes: [@route], facilitator: facilitator, hooks: RecordingHooks)

      assert conn.status == 200
      refute_received {:on_verified_payment_canceled, _context, _metadata}
    end

    test "a raising callback is logged and never changes the response" do
      facilitator = start_mock_facilitator()

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn =
            conn(:get, "/api/resource")
            |> put_req_header("payment-signature", valid_payment_header())
            |> gate_request(routes: [@route], facilitator: facilitator, hooks: CancelRaisingHooks)
            |> send_resp(503, "down")

          assert conn.status == 503
          assert conn.resp_body == "down"
        end)

      assert log =~ "on_verified_payment_canceled"
      assert log =~ "cancel boom"
    end
  end

  # ---------------------------------------------------------------------------
  # Extension adapters
  # ---------------------------------------------------------------------------

  describe ":extensions adapters" do
    test "advertise on every 402 and are merged over static route extensions" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extensions, %{"static" => %{"info" => %{}}})

      conn =
        run_request(conn(:get, "/api/resource"),
          routes: [route],
          facilitator: facilitator,
          extensions: [
            RecordingAdapter,
            {X402.Extensions.PaymentIdentifier.Adapter, required: false},
            {X402.Extensions.BuilderCode.Adapter, app_code: "my_app", service_codes: "sdk"}
          ]
        )

      extensions = decode_payment_required!(conn)["extensions"]

      assert extensions["static"] == %{"info" => %{}}

      assert extensions["recording"] == %{
               "info" => %{"path" => "/api/resource", "reject" => false}
             }

      assert extensions["payment-identifier"]["info"] == %{"required" => false}
      assert extensions["builder-code"]["info"] == %{"a" => "my_app", "s" => ["sdk"]}
      assert_receive {:adapter_advertise, "/api/resource"}
    end

    test "validate the echo and observe verify and settle" do
      facilitator = start_mock_facilitator()

      opts = [routes: [@route], facilitator: facilitator, extensions: [RecordingAdapter]]
      advertised = decode_payment_required!(run_request(conn(:get, "/api/resource"), opts))

      conn =
        conn(:get, "/api/resource")
        |> put_req_header(
          "payment-signature",
          payment_header(extensions: advertised["extensions"])
        )
        |> run_request(opts)

      assert conn.status == 200

      assert_receive {:adapter_validate, %{"info" => %{"path" => "/api/resource"}},
                      %{"info" => %{"path" => "/api/resource"}}}

      assert_receive {:adapter_after_verify, 200}
      assert_receive {:adapter_after_settle, "0x1234567890abcdef" <> _rest}
    end

    test "a validate failure answers 400 invalid_payload" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        extensions: [{RecordingAdapter, reject: true}]
      ]

      advertised = decode_payment_required!(run_request(conn(:get, "/api/resource"), opts))

      conn =
        conn(:get, "/api/resource")
        |> put_req_header(
          "payment-signature",
          payment_header(extensions: advertised["extensions"])
        )
        |> run_request(opts)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:extension_invalid, "recording", :rejected_by_adapter}}}

      refute_received {:verify_called, _payload, _requirements}
    end

    test "init rejects invalid adapter specs" do
      assert_raise NimbleOptions.ValidationError, ~r/X402.Extension/, fn ->
        PaymentGate.init(routes: [@route], facilitator: Facilitator, extensions: [Enum])
      end

      assert_raise NimbleOptions.ValidationError, ~r/invalid builder code/, fn ->
        PaymentGate.init(
          routes: [@route],
          facilitator: Facilitator,
          extensions: [{X402.Extensions.BuilderCode.Adapter, app_code: "Bad Code"}]
        )
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Builder code
  # ---------------------------------------------------------------------------

  describe "builder-code echo" do
    test "a well-formed echo of the advertised code is forwarded to the facilitator" do
      facilitator = start_mock_facilitator()
      route = Map.put(@route, :extensions, %{"builder-code" => BuilderCode.extension("my_app")})

      echo = %{
        "builder-code" => %{
          "info" => %{"a" => "my_app", "s" => ["my_client"]},
          "schema" => BuilderCode.schema()
        }
      }

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", payment_header(extensions: echo))
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 200

      assert_receive {:verify_called,
                      %{"extensions" => %{"builder-code" => %{"info" => %{"a" => "my_app"}}}},
                      _requirements}
    end

    test "a volunteered echo without an advertisement is accepted when it carries no app code" do
      facilitator = start_mock_facilitator()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header(
          "payment-signature",
          payment_header(extensions: %{"builder-code" => %{"info" => %{"s" => "my_client"}}})
        )
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 200
    end

    test "an app code the server never declared is an echo mismatch" do
      facilitator = start_mock_facilitator()
      attach_telemetry()

      conn =
        conn(:get, "/api/resource")
        |> put_req_header(
          "payment-signature",
          payment_header(extensions: %{"builder-code" => %{"a" => "other_app"}})
        )
        |> run_request(routes: [@route], facilitator: facilitator)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_payload"

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: :extension_echo_mismatch}}
    end

    test "malformed codes and too many service codes answer 400" do
      facilitator = start_mock_facilitator()
      attach_telemetry()
      route = Map.put(@route, :extensions, %{"builder-code" => BuilderCode.extension("my_app")})

      malformed = %{
        "builder-code" => %{
          "info" => %{"a" => "my_app", "s" => ["Bad Code"]},
          "schema" => BuilderCode.schema()
        }
      }

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", payment_header(extensions: malformed))
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 400

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:invalid_builder_code, {:invalid_builder_code, "s"}}}}

      too_many = %{
        "builder-code" => %{
          "info" => %{"a" => "my_app", "s" => Enum.map(1..11, &"code_#{&1}")},
          "schema" => BuilderCode.schema()
        }
      }

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", payment_header(extensions: too_many))
        |> run_request(routes: [route], facilitator: facilitator)

      assert conn.status == 400

      assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], _measurements,
                      %{reason: {:invalid_builder_code, :too_many_service_codes}}}
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
  defp maybe_send_ok(conn), do: send_resp(conn, 200, "ok")

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  defp attach_telemetry do
    handler_id = "payment-gate-lifecycle-#{System.unique_integer([:positive, :monotonic])}"
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
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry_event, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp valid_payment_header, do: payment_header([])

  defp payment_header(opts) do
    amount = Keyword.get(opts, :amount, @amount)
    extensions = Keyword.get(opts, :extensions, %{})

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
        "amount" => amount,
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
          "value" => amount,
          "validAfter" => Integer.to_string(System.system_time(:second) - 60),
          "validBefore" => Integer.to_string(System.system_time(:second) + 300),
          "nonce" => "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
        }
      },
      "extensions" => extensions
    }
    |> Jason.encode!()
    |> Base.encode64()
  end

  defp start_mock_facilitator(opts \\ []) do
    owner = self()
    verify = Keyword.get(opts, :verify, @default_verify)
    settle = Keyword.get(opts, :settle, @default_settle)

    bypass = Bypass.open()
    stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, verify)
    stub_facilitator_endpoint(bypass, owner, "/settle", :settle_called, settle)

    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("payment_gate_lifecycle_finch_#{suffix}")
    name = String.to_atom("payment_gate_lifecycle_facilitator_#{suffix}")

    start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

    start_supervised!(
      {Facilitator,
       [
         name: name,
         finch: finch,
         max_retries: 0,
         receive_timeout_ms: 1_000,
         url: "http://localhost:#{bypass.port}"
       ]}
    )
  end

  defp stub_facilitator_endpoint(bypass, owner, path, tag, {:ok, %{status: status, body: body}}) do
    Bypass.stub(bypass, "POST", path, fn conn ->
      {:ok, request_body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(request_body)
      send(owner, {tag, decoded["paymentPayload"], decoded["paymentRequirements"]})
      Plug.Conn.resp(conn, status, Jason.encode!(body))
    end)
  end
end
