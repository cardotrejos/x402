defmodule X402.Plug.PaymentGateTest do
  use ExUnit.Case, async: false
  import Plug.Conn
  import Plug.Test

  alias X402.Plug.PaymentGate

  defmodule MockFacilitator do
    @moduledoc false
    use GenServer

    @default_verify {:ok, %{status: 200, body: %{"verified" => true}}}
    @default_settle {:ok, %{status: 200, body: %{"settled" => true}}}

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
      send(state.owner, {:verify_called, payment_payload, requirements})
      {:reply, resolve_result(state.verify, payment_payload, requirements), state}
    end

    @impl true
    def handle_call({:settle, payment_payload, requirements}, _from, state) do
      send(state.owner, {:settle_called, payment_payload, requirements})
      {:reply, resolve_result(state.settle, payment_payload, requirements), state}
    end

    defp resolve_result(result, _payment_payload, _requirements) when is_tuple(result), do: result

    defp resolve_result(result_fun, payment_payload, requirements)
         when is_function(result_fun, 2) do
      result_fun.(payment_payload, requirements)
    end
  end

  @route %{
    method: :get,
    path: "/api/resource",
    price: "0.01",
    network: "base-sepolia",
    asset: "USDC",
    receiver: "0x1111111111111111111111111111111111111111"
  }

  test "passes through non-gated routes" do
    conn = conn(:get, "/public")
    result_conn = run_request(conn, routes: [@route], facilitator: self())

    assert result_conn.status == 200
    assert result_conn.resp_body == "ok"
  end

  test "matches exact paths with normalized trailing slash" do
    conn = conn(:get, "/api/resource/")
    result_conn = run_request(conn, routes: [@route], facilitator: self())
    body = Jason.decode!(result_conn.resp_body)

    assert result_conn.status == 402
    assert body["accepts"] |> List.first() |> Map.fetch!("resource") == "/api/resource"
  end

  test "matches glob routes" do
    route = Map.put(@route, :path, "/api/*")
    conn = conn(:get, "/api/v1/items")
    result_conn = run_request(conn, routes: [route], facilitator: self())

    assert result_conn.status == 402
  end

  test "filters by method and supports :any" do
    post_route = Map.put(@route, :method, :post)
    any_route = %{post_route | method: :any, path: "/any"}

    pass_through_conn =
      run_request(conn(:get, "/api/resource"), routes: [post_route], facilitator: self())

    gated_conn = run_request(conn(:put, "/any"), routes: [any_route], facilitator: self())

    assert pass_through_conn.status == 200
    assert gated_conn.status == 402
  end

  test "matches HEAD requests for root path routes" do
    head_root_route = %{Map.put(@route, :method, :head) | path: "/"}

    result_conn = run_request(conn(:head, "/"), routes: [head_root_route], facilitator: self())

    assert result_conn.status == 402
    assert result_conn.halted
  end

  test "normalizes additional HTTP methods including fallback to :any" do
    methods = ["DELETE", "OPTIONS", "PATCH", "POST", "TRACE", "CUSTOM"]

    for method <- methods do
      result_conn = run_request(conn(method, "/public"), routes: [@route], facilitator: self())
      assert result_conn.status == 200
      assert result_conn.resp_body == "ok"
    end
  end

  test "returns 402 response body in required x402 format" do
    conn = conn(:get, "/api/resource")
    result_conn = run_request(conn, routes: [@route], facilitator: self())
    body = Jason.decode!(result_conn.resp_body)
    [accept] = body["accepts"]

    assert result_conn.status == 402
    assert get_resp_header(result_conn, "content-type") == ["application/json; charset=utf-8"]
    assert body["x402Version"] == 1
    assert body["error"] == ""
    assert accept["scheme"] == "exact"
    assert accept["network"] == "base-sepolia"
    assert accept["maxAmountRequired"] == "0.01"
    assert accept["resource"] == "/api/resource"
    assert accept["description"] == "Payment required"
    assert accept["mimeType"] == "application/json"
    assert accept["payTo"] == "0x1111111111111111111111111111111111111111"
    assert accept["maxTimeoutSeconds"] == 60
    assert accept["extra"] == %{}
  end

  test "verifies and settles valid payments before pass-through" do
    facilitator = start_mock_facilitator()

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())

    result_conn = run_request(conn, routes: [@route], facilitator: facilitator)

    assert result_conn.status == 200

    assert_receive {:verify_called, payload, requirements}
    assert payload["transactionHash"] == "0xabc"
    assert requirements["network"] == "base-sepolia"
    assert requirements["asset"] == "USDC"
    assert requirements["resource"] == "/api/resource"

    assert_receive {:settle_called, payload, ^requirements}
    assert payload["payerWallet"] == "0x1111111111111111111111111111111111111111"
  end

  test "rejects invalid x-payment header values" do
    facilitator = start_mock_facilitator()

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", "not-valid-base64")

    result_conn = run_request(conn, routes: [@route], facilitator: facilitator)
    body = Jason.decode!(result_conn.resp_body)

    assert result_conn.status == 402
    assert body["error"] == "invalid payment header"
    refute_received {:verify_called, _payload, _requirements}
  end

  test "rejects when facilitator verification fails" do
    verify_failure = fn _payment_payload, _requirements -> {:error, :verification_failed} end
    facilitator = start_mock_facilitator(verify: verify_failure)

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())

    result_conn = run_request(conn, routes: [@route], facilitator: facilitator)

    assert result_conn.status == 402
    refute_received {:settle_called, _payload, _requirements}
  end

  test "rejects when facilitator verification returns non-success status" do
    facilitator =
      start_mock_facilitator(verify: {:ok, %{status: 409, body: %{"error" => "conflict"}}})

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())

    result_conn = run_request(conn, routes: [@route], facilitator: facilitator)
    body = Jason.decode!(result_conn.resp_body)

    assert result_conn.status == 402
    assert body["error"] == "facilitator rejected payment"
    refute_received {:settle_called, _payload, _requirements}
  end

  test "rejects when facilitator settlement fails" do
    facilitator = start_mock_facilitator(settle: {:error, :settlement_failed})

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())

    result_conn = run_request(conn, routes: [@route], facilitator: facilitator)
    body = Jason.decode!(result_conn.resp_body)

    assert result_conn.status == 402
    assert body["error"] == "payment verification failed"
    assert_receive {:verify_called, _payload, _requirements}
    assert_receive {:settle_called, _payload, _requirements}
  end

  test "rejects malformed x-payment header and emits telemetry reason metadata" do
    handler_id = "payment-gate-malformed-#{System.unique_integer([:positive, :monotonic])}"
    parent = self()

    :ok =
      :telemetry.attach(
        handler_id,
        [:x402, :plug, :payment_rejected],
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry_event, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", "")

    result_conn = run_request(conn, routes: [@route], facilitator: self())
    body = Jason.decode!(result_conn.resp_body)

    assert result_conn.status == 402
    assert body["error"] == "invalid payment header"

    assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], %{count: 1},
                    %{path: "/api/resource", reason: :invalid_payment_header}}
  end

  test "maps invalid_json, invalid_payload, and missing_fields reasons to payment payload errors" do
    invalid_json_header = Base.encode64("{")

    invalid_json_conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", invalid_json_header)
      |> run_request(routes: [@route], facilitator: self())

    assert invalid_json_conn.status == 402
    assert Jason.decode!(invalid_json_conn.resp_body)["error"] == "invalid payment header"

    invalid_payload_facilitator = start_mock_facilitator(verify: {:error, :invalid_payload})

    invalid_payload_conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())
      |> run_request(routes: [@route], facilitator: invalid_payload_facilitator)

    assert invalid_payload_conn.status == 402
    assert Jason.decode!(invalid_payload_conn.resp_body)["error"] == "invalid payment payload"

    missing_fields_facilitator =
      start_mock_facilitator(verify: {:error, {:missing_fields, ["network"]}})

    missing_fields_conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())
      |> run_request(routes: [@route], facilitator: missing_fields_facilitator)

    assert missing_fields_conn.status == 402
    assert Jason.decode!(missing_fields_conn.resp_body)["error"] == "invalid payment payload"
  end

  test "emits pass_through, payment_required, payment_verified, and payment_rejected telemetry events" do
    ok_facilitator = start_mock_facilitator()

    reject_verify = fn _payment_payload, _requirements -> {:error, :declined} end
    reject_facilitator = start_mock_facilitator(verify: reject_verify)

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
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry_event, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    run_request(conn(:get, "/public"), routes: [@route], facilitator: ok_facilitator)
    run_request(conn(:get, "/api/resource"), routes: [@route], facilitator: ok_facilitator)

    verified_conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())
      |> run_request(routes: [@route], facilitator: ok_facilitator)

    rejected_conn =
      conn(:get, "/api/resource")
      |> put_req_header("x-payment", valid_payment_header())
      |> run_request(routes: [@route], facilitator: reject_facilitator)

    assert verified_conn.status == 200
    assert rejected_conn.status == 402

    assert_receive {:telemetry_event, [:x402, :plug, :pass_through], %{count: 1},
                    %{path: "/public"}}

    assert_receive {:telemetry_event, [:x402, :plug, :payment_required], %{count: 1},
                    %{path: "/api/resource"}}

    assert_receive {:telemetry_event, [:x402, :plug, :payment_verified], %{count: 1},
                    %{path: "/api/resource"}}

    assert_receive {:telemetry_event, [:x402, :plug, :payment_rejected], %{count: 1},
                    %{path: "/api/resource"}}
  end

  test "init/1 raises NimbleOptions validation errors for invalid config" do
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
          %{method: :foo, path: "/api", price: "1", network: "n", asset: "a", receiver: "r"}
        ]
      )
    end
  end

  defp run_request(conn, opts) do
    conn
    |> PaymentGate.call(PaymentGate.init(opts))
    |> maybe_send_ok()
  end

  defp maybe_send_ok(%Plug.Conn{halted: true} = conn), do: conn
  defp maybe_send_ok(conn), do: Plug.Conn.send_resp(conn, 200, "ok")

  defp valid_payment_header do
    %{
      "transactionHash" => "0xabc",
      "network" => "base-sepolia",
      "scheme" => "exact",
      "payerWallet" => "0x1111111111111111111111111111111111111111"
    }
    |> Jason.encode!()
    |> Base.encode64()
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
