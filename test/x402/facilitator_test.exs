defmodule X402.FacilitatorTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias X402.Facilitator
  alias X402.Facilitator.Error
  alias X402.Hooks.Context

  import X402.TestHelpers

  defmodule MutatingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata) do
      {:cont,
       %Context{
         context
         | payload: Map.put(context.payload, "beforeVerify", true),
           requirements: Map.put(context.requirements, "beforeVerify", true)
       }}
    end

    def after_verify(%Context{} = context, _metadata) do
      body = Map.fetch!(context.result, :body)
      result = Map.put(context.result, :body, Map.put(body, "afterVerify", true))
      {:cont, %Context{context | result: result}}
    end

    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}

    def before_settle(%Context{} = context, _metadata) do
      {:cont,
       %Context{
         context
         | payload: Map.put(context.payload, "beforeSettle", true),
           requirements: Map.put(context.requirements, "beforeSettle", true)
       }}
    end

    def after_settle(%Context{} = context, _metadata) do
      body = Map.fetch!(context.result, :body)
      result = Map.put(context.result, :body, Map.put(body, "afterSettle", true))
      {:cont, %Context{context | result: result}}
    end

    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule VerifyHaltHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = _context, _metadata), do: {:halt, :verify_halted}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule VerifyRecoverHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}

    def on_verify_failure(%Context{} = _context, _metadata) do
      {:recover, %{status: 200, body: %{"recovered" => true}}}
    end

    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule SettleRecoverHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}

    def on_settle_failure(%Context{} = _context, _metadata) do
      {:recover, %{status: 200, body: %{"settled" => "recovered"}}}
    end
  end

  defmodule InvalidAfterVerifyHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = _context, _metadata), do: :invalid_return
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule UptoAdjustingHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata) do
      {:cont, %Context{context | payload: Map.put(context.payload, "value", "9")}}
    end

    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}

    def before_settle(%Context{} = context, _metadata) do
      {:cont, %Context{context | payload: Map.put(context.payload, "value", "9")}}
    end

    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule FailingAuth do
    @moduledoc false
    @behaviour X402.Facilitator.Auth

    defstruct [:ref]

    @impl true
    def new(_opts), do: {:ok, %__MODULE__{}}

    @impl true
    def headers(_auth, _request_info), do: {:error, :no_headers_available}
  end

  defmodule RecordingAuth do
    @moduledoc false
    @behaviour X402.Facilitator.Auth

    defstruct []

    @impl true
    def new(_opts), do: {:ok, %__MODULE__{}}

    # Operations run in the calling process, so self() is the test process.
    @impl true
    def headers(_auth, request_info) do
      send(self(), {:auth_request_info, request_info})
      {:error, :recorded}
    end
  end

  defmodule InvalidBeforeVerifyHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = _context, _metadata), do: :garbage
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule RaisingAfterVerifyHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = _context, _metadata), do: raise("after boom")
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule NilResultAfterVerifyHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}

    def after_verify(%Context{} = context, _metadata),
      do: {:cont, %Context{context | result: nil}}

    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule BadResultAfterVerifyHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}

    def after_verify(%Context{} = context, _metadata),
      do: {:cont, %Context{context | result: :nope}}

    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule BadRecoverHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = _context, _metadata), do: {:recover, :not_a_map}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule InvalidFailureReturnHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = _context, _metadata), do: :bogus
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule RaisingFailureHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = _context, _metadata), do: raise("failure hook boom")
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule NilErrorFailureHooks do
    @moduledoc false
    @behaviour X402.Hooks

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}

    def on_verify_failure(%Context{} = context, _metadata),
      do: {:cont, %Context{context | error: nil}}

    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  setup :setup_bypass
  setup :setup_finch

  test "verify/3 posts payload and requirements to /verify", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"signature" => "abc"}
    requirements = %{"scheme" => "exact"}

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{
               "x402Version" => 2,
               "paymentPayload" => ^payment_payload,
               "paymentRequirements" => ^requirements
             } = Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, payment_payload, requirements)
  end

  test "settle/3 posts payload and requirements to /settle", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"tx" => "0xdeadbeef"}
    requirements = %{"network" => "eip155:8453"}

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{
               "x402Version" => 2,
               "paymentPayload" => ^payment_payload,
               "paymentRequirements" => ^requirements
             } = Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(facilitator, payment_payload, requirements)
  end

  test "before_verify and after_verify hooks can mutate verify flow", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{
               "x402Version" => 2,
               "paymentPayload" => %{"beforeVerify" => true},
               "paymentRequirements" => %{"beforeVerify" => true}
             } = Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: MutatingHooks}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true, "afterVerify" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "before_settle and after_settle hooks can mutate settle flow", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{
               "x402Version" => 2,
               "paymentPayload" => %{"beforeSettle" => true},
               "paymentRequirements" => %{"beforeSettle" => true}
             } = Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: MutatingHooks}
      )

    assert {:ok, %{status: 200, body: %{"settled" => true, "afterSettle" => true}}} =
             Facilitator.settle(facilitator, %{}, %{})
  end

  test "before_verify can halt the operation", %{
    finch: finch,
    facilitator_url: facilitator_url
  } do
    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: VerifyHaltHooks}
      )

    assert {:error, {:hook_halted, :before_verify, :verify_halted}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "on_verify_failure can recover failed verification", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 500, Jason.encode!(%{"error" => "retry me"}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: VerifyRecoverHooks}
      )

    assert {:ok, %{status: 200, body: %{"recovered" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "on_settle_failure can recover failed settlement", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      Plug.Conn.resp(conn, 500, Jason.encode!(%{"error" => "retry me"}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: SettleRecoverHooks}
      )

    assert {:ok, %{status: 200, body: %{"settled" => "recovered"}}} =
             Facilitator.settle(facilitator, %{}, %{})
  end

  test "verify/4 and settle/4 override the configured hook module", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert %{"paymentPayload" => %{"beforeVerify" => true}} = Jason.decode!(body)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert %{"paymentPayload" => %{"beforeSettle" => true}} = Jason.decode!(body)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: X402.Hooks.Default}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true, "afterVerify" => true}}} =
             Facilitator.verify(facilitator, %{}, %{}, MutatingHooks)

    assert {:ok, %{status: 200, body: %{"settled" => true, "afterSettle" => true}}} =
             Facilitator.settle(facilitator, %{}, %{}, MutatingHooks)
  end

  test "returns hook_invalid_return when hook callback returns invalid tuple", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: InvalidAfterVerifyHooks}
      )

    assert {:error, {:hook_invalid_return, :after_verify, :invalid_return}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "verify/2 and settle/2 use default registered name", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    start_supervised!({Facilitator, finch: finch, url: facilitator_url})

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(%{"p" => 1}, %{"r" => 1})

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(%{"p" => 2}, %{"r" => 2})
  end

  test "returns structured errors from transport", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 400, Jason.encode!(%{"error" => "bad request"}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:error, %Error{type: :http_error, status: 400, retryable: false}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "logs a warning when the facilitator declines verification", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 400, Jason.encode!(%{"error" => "bad request"}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    log =
      capture_log(fn ->
        assert {:error, %Error{type: :http_error, status: 400}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)

    assert log =~ "[X402.Facilitator] verify failed at /verify"
    assert log =~ "type=http_error"
    assert log =~ "status=400"
  end

  test "logs a warning for non-HTTP processing failures", %{
    finch: finch,
    facilitator_url: facilitator_url
  } do
    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    log =
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "11"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)

    assert log =~ "[X402.Facilitator] verify failed at /verify"
    assert log =~ "payment_value_exceeds_max_price"
  end

  test "does not log a warning on success", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    log =
      capture_log(fn ->
        assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, %{}, %{})
      end)

    refute log =~ "[X402.Facilitator]"
  end

  test "verify/3 rejects upto payments above maxPrice before HTTP request", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    parent = self()

    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      send(parent, :verify_http_called)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}} =
             Facilitator.verify(
               facilitator,
               %{"value" => "11"},
               %{"scheme" => "upto", "maxPrice" => "10"}
             )

    refute_receive :verify_http_called
  end

  test "settle/3 rejects upto payments above maxPrice before HTTP request", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    parent = self()

    Bypass.stub(bypass, "POST", "/settle", fn conn ->
      send(parent, :settle_http_called)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}} =
             Facilitator.settle(
               facilitator,
               %{"value" => "11"},
               %{"scheme" => "upto", "maxPrice" => "10"}
             )

    refute_receive :settle_http_called
  end

  test "upto validation respects before hooks for verify and settle", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert %{"paymentPayload" => %{"value" => "9"}} = Jason.decode!(body)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert %{"paymentPayload" => %{"value" => "9"}} = Jason.decode!(body)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         hooks: UptoAdjustingHooks}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(
               facilitator,
               %{"value" => "11"},
               %{"scheme" => "upto", "maxPrice" => "10"}
             )

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(
               facilitator,
               %{"value" => "11"},
               %{"scheme" => "upto", "maxPrice" => "10"}
             )
  end

  test "concurrent verify calls do not serialize behind the facilitator process", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    delay_ms = 500

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Process.sleep(delay_ms)
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    {elapsed_us, results} =
      :timer.tc(fn ->
        1..2
        |> Enum.map(fn _index ->
          Task.async(fn -> Facilitator.verify(facilitator, %{}, %{}) end)
        end)
        |> Task.await_many(5_000)
      end)

    for result <- results do
      assert {:ok, %{status: 200, body: %{"verified" => true}}} = result
    end

    elapsed_ms = div(elapsed_us, 1000)

    assert elapsed_ms < 2 * delay_ms,
           "expected concurrent verifies to overlap, but 2 calls took #{elapsed_ms}ms " <>
             "(serialized execution would take >= #{2 * delay_ms}ms)"
  end

  test "emits telemetry span events", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    parent = self()
    handler_id = "facilitator-span-#{System.unique_integer([:positive, :monotonic])}"

    :ok =
      :telemetry.attach_many(
        handler_id,
        [[:x402, :facilitator, :verify, :start], [:x402, :facilitator, :verify, :stop]],
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})

    assert_receive {:telemetry, [:x402, :facilitator, :verify, :start], _measurements,
                    %{operation: :verify, endpoint: "/verify"}}

    assert_receive {:telemetry, [:x402, :facilitator, :verify, :stop], measurements,
                    %{success: true, status: 200}}

    assert %{duration: duration} = measurements
    assert is_integer(duration)
  end

  test "start_link validates required options" do
    assert {:error, %NimbleOptions.ValidationError{}} = Facilitator.start_link([])

    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, max_retries: -1)

    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, hooks: :not_a_hook_module)
  end

  test "start_link validates the auth option shape" do
    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, auth: {NotAnAuthModule, []})

    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, auth: :not_a_module)
  end

  test "start_link fails fast on invalid auth credentials" do
    assert {:error, {:invalid_auth, :invalid_secret_format}} =
             Facilitator.start_link(
               finch: :finch,
               auth: {X402.Facilitator.Auth.CDP, api_key_id: "key", api_key_secret: "not-base64"}
             )
  end

  test "verify/3 uses the configuration from the otp_app", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    {secret, _public_key} = X402.TestAuthKeys.ed25519()
    name = unique_name("config_facilitator")

    set_facilitator_config(:x402, name,
      finch: finch,
      url: facilitator_url,
      auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}
    )

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      [authorization] = Plug.Conn.get_req_header(conn, "authorization")
      assert String.starts_with?(authorization, "Bearer ")
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator = start_supervised!({Facilitator, otp_app: :x402, name: name})

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "explicit options take precedence over the otp_app's configuration", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    {secret, _public_key} = X402.TestAuthKeys.ed25519()
    name = unique_name("config_override_facilitator")

    set_facilitator_config(:x402, name,
      finch: finch,
      url: "https://wrong.example",
      auth: {X402.Facilitator.Auth.CDP, api_key_id: "wrong-key", api_key_secret: secret}
    )

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         otp_app: :x402,
         name: name,
         url: facilitator_url,
         auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "verify/3 sends a CDP JWT Authorization header", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    {secret, public_key} = X402.TestAuthKeys.ed25519()

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      [authorization] = Plug.Conn.get_req_header(conn, "authorization")
      assert String.starts_with?(authorization, "Bearer ")

      token = String.replace_prefix(authorization, "Bearer ", "")
      assert verify_jwt(token, public_key)

      assert jwt_payload(token)["uris"] ==
               ["POST localhost:#{bypass.port}/verify"]

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "settle/3 sends a CDP JWT Authorization header", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    {secret, public_key} = X402.TestAuthKeys.ed25519()

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      [authorization] = Plug.Conn.get_req_header(conn, "authorization")
      token = String.replace_prefix(authorization, "Bearer ", "")
      assert verify_jwt(token, public_key)
      assert jwt_payload(token)["uris"] == ["POST localhost:#{bypass.port}/settle"]
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: facilitator_url,
         auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
      )

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(facilitator, %{}, %{})
  end

  test "verify/3 binds the CDP JWT to the base URL path plus the endpoint", %{
    bypass: bypass,
    finch: finch
  } do
    {secret, public_key} = X402.TestAuthKeys.ed25519()
    base_url = "http://localhost:#{bypass.port}/platform/v2/x402"

    Bypass.expect(bypass, "POST", "/platform/v2/x402/verify", fn conn ->
      [authorization] = Plug.Conn.get_req_header(conn, "authorization")
      token = String.replace_prefix(authorization, "Bearer ", "")
      assert verify_jwt(token, public_key)

      assert jwt_payload(token)["uris"] ==
               ["POST localhost:#{bypass.port}/platform/v2/x402/verify"]

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"),
         finch: finch,
         url: base_url,
         auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "verify/3 sends no Authorization header without auth config", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    parent = self()

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      send(parent, {:auth_headers, Plug.Conn.get_req_header(conn, "authorization")})
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, %{}, %{})
    assert_receive {:auth_headers, []}
  end

  test "returns auth_failed error when auth headers cannot be built", %{
    finch: finch,
    facilitator_url: facilitator_url
  } do
    facilitator =
      start_supervised!(
        {Facilitator,
         name: unique_name("facilitator"), finch: finch, url: facilitator_url, auth: FailingAuth}
      )

    assert {:error, %Error{type: :auth_failed, reason: :no_headers_available, retryable: false}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  describe "supported/1" do
    test "fetches and validates the supported payment kinds", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "kinds" => [
              %{"x402Version" => 2, "scheme" => "exact", "network" => "eip155:8453"},
              %{
                "x402Version" => 2,
                "scheme" => "exact",
                "network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "extra" => %{"feePayer" => "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"}
              }
            ],
            "extensions" => ["bazaar"],
            "signers" => %{"eip155:*" => ["0x1234567890abcdef1234567890abcdef12345678"]}
          })
        )
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:ok, %{kinds: kinds, extensions: ["bazaar"], signers: signers}} =
               Facilitator.supported(facilitator)

      assert [
               %{x402_version: 2, scheme: "exact", network: "eip155:8453", extra: nil},
               %{scheme: "exact", extra: %{"feePayer" => fee_payer}}
             ] = kinds

      assert fee_payer == "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"
      assert signers == %{"eip155:*" => ["0x1234567890abcdef1234567890abcdef12345678"]}
    end

    test "defaults missing extensions and signers", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kinds" => []}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:ok, %{kinds: [], extensions: [], signers: %{}}} =
               Facilitator.supported(facilitator)
    end

    test "supported/0 and list_resources/1 use the default registered name", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kinds" => []}))
      end)

      Bypass.expect(bypass, "GET", "/discovery/resources", fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        assert conn.query_params == %{"limit" => "5"}
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"items" => []}))
      end)

      start_supervised!({Facilitator, finch: finch, url: facilitator_url})

      assert {:ok, %{kinds: []}} = Facilitator.supported()
      assert {:ok, %{items: []}} = Facilitator.list_resources(limit: 5)
    end

    test "fails closed on malformed responses", %{finch: finch} do
      malformed_bodies = [
        %{},
        %{"kinds" => "exact"},
        %{"kinds" => [%{"x402Version" => "2", "scheme" => "exact", "network" => "eip155:1"}]},
        %{"kinds" => [%{"scheme" => "exact", "network" => "eip155:1"}]},
        %{"kinds" => [], "extensions" => "bazaar"},
        %{"kinds" => [], "signers" => %{"eip155:*" => "0xabc"}},
        %{"kinds" => [], "signers" => ["0xabc"]}
      ]

      for body <- malformed_bodies do
        bypass = Bypass.open()

        Bypass.expect(bypass, "GET", "/supported", fn conn ->
          Plug.Conn.resp(conn, 200, Jason.encode!(body))
        end)

        facilitator =
          start_supervised!(
            {Facilitator,
             name: unique_name("facilitator"),
             finch: finch,
             url: "http://localhost:#{bypass.port}"}
          )

        assert {:error, %Error{type: :malformed_facilitator_response, status: 200}} =
                 Facilitator.supported(facilitator)
      end
    end

    test "propagates HTTP errors", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 404, Jason.encode!(%{"error" => "not found"}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:error, %Error{type: :http_error, status: 404, retryable: false}} =
               Facilitator.supported(facilitator)
    end

    test "sends a CDP JWT bound to the GET method and path", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      {secret, public_key} = X402.TestAuthKeys.ed25519()

      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        [authorization] = Plug.Conn.get_req_header(conn, "authorization")
        token = String.replace_prefix(authorization, "Bearer ", "")
        assert verify_jwt(token, public_key)
        assert jwt_payload(token)["uris"] == ["GET localhost:#{bypass.port}/supported"]
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kinds" => []}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
        )

      assert {:ok, %{kinds: []}} = Facilitator.supported(facilitator)
    end

    test "emits telemetry span events", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      parent = self()
      handler_id = "facilitator-supported-span-#{System.unique_integer([:positive, :monotonic])}"

      :ok =
        :telemetry.attach_many(
          handler_id,
          [[:x402, :facilitator, :supported, :start], [:x402, :facilitator, :supported, :stop]],
          fn event, measurements, metadata, _config ->
            send(parent, {:telemetry, event, measurements, metadata})
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      Bypass.expect(bypass, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kinds" => []}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:ok, %{kinds: []}} = Facilitator.supported(facilitator)

      assert_receive {:telemetry, [:x402, :facilitator, :supported, :start], _measurements,
                      %{operation: :supported, endpoint: "/supported"}}

      assert_receive {:telemetry, [:x402, :facilitator, :supported, :stop], _measurements,
                      %{success: true}}
    end
  end

  describe "list_resources/2" do
    test "fetches discovery resources with encoded query parameters", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      item = %{
        "resource" => "https://api.example.com/premium-data",
        "type" => "http",
        "x402Version" => 2,
        "accepts" => [%{"scheme" => "exact", "network" => "eip155:8453"}],
        "lastUpdated" => 1_703_123_456
      }

      Bypass.expect(bypass, "GET", "/discovery/resources", fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)

        assert conn.query_params == %{
                 "type" => "http",
                 "payTo" => "0x1111111111111111111111111111111111111111",
                 "scheme" => "exact",
                 "network" => "eip155:8453",
                 "limit" => "10",
                 "offset" => "20"
               }

        Plug.Conn.resp(
          conn,
          200,
          Jason.encode!(%{
            "x402Version" => 2,
            "items" => [item],
            "pagination" => %{"limit" => 10, "offset" => 20, "total" => 1}
          })
        )
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:ok,
              %{
                x402_version: 2,
                items: [returned_item],
                pagination: %{limit: 10, offset: 20, total: 1}
              }} =
               Facilitator.list_resources(facilitator,
                 type: "http",
                 pay_to: "0x1111111111111111111111111111111111111111",
                 scheme: "exact",
                 network: "eip155:8453",
                 limit: 10,
                 offset: 20
               )

      assert returned_item == item
    end

    test "omits query string without parameters and defaults pagination to nil", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "GET", "/discovery/resources", fn conn ->
        assert conn.query_string == ""
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"items" => []}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:ok, %{x402_version: nil, items: [], pagination: nil}} =
               Facilitator.list_resources(facilitator)
    end

    test "rejects invalid parameters before any HTTP request", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      assert {:error, %NimbleOptions.ValidationError{}} =
               Facilitator.list_resources(facilitator, limit: 0)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Facilitator.list_resources(facilitator, limit: 101)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Facilitator.list_resources(facilitator, network: :base)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Facilitator.list_resources(facilitator, unknown: "option")
    end

    test "fails closed on malformed responses", %{finch: finch} do
      malformed_bodies = [
        %{},
        %{"items" => %{}},
        %{"items" => ["not-a-map"]},
        %{"items" => [], "pagination" => %{"limit" => "10"}},
        %{"items" => [], "x402Version" => "2"}
      ]

      for body <- malformed_bodies do
        bypass = Bypass.open()

        Bypass.expect(bypass, "GET", "/discovery/resources", fn conn ->
          Plug.Conn.resp(conn, 200, Jason.encode!(body))
        end)

        facilitator =
          start_supervised!(
            {Facilitator,
             name: unique_name("facilitator"),
             finch: finch,
             url: "http://localhost:#{bypass.port}"}
          )

        assert {:error, %Error{type: :malformed_facilitator_response, status: 200}} =
                 Facilitator.list_resources(facilitator)
      end
    end

    test "sends a CDP JWT bound to the GET method and discovery path", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      {secret, public_key} = X402.TestAuthKeys.ed25519()

      Bypass.expect(bypass, "GET", "/discovery/resources", fn conn ->
        [authorization] = Plug.Conn.get_req_header(conn, "authorization")
        token = String.replace_prefix(authorization, "Bearer ", "")
        assert verify_jwt(token, public_key)

        assert jwt_payload(token)["uris"] ==
                 ["GET localhost:#{bypass.port}/discovery/resources"]

        Plug.Conn.resp(conn, 200, Jason.encode!(%{"items" => []}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           auth: {X402.Facilitator.Auth.CDP, api_key_id: "key-123", api_key_secret: secret}}
        )

      assert {:ok, %{items: []}} = Facilitator.list_resources(facilitator, limit: 5)
    end
  end

  describe "hook edge cases" do
    test "an invalid before_verify return halts without an HTTP request", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: InvalidBeforeVerifyHooks}
        )

      capture_log(fn ->
        assert {:error, {:hook_invalid_return, :before_verify, :garbage}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)
    end

    test "a raising after_verify on a successful response is an infrastructure error", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: RaisingAfterVerifyHooks}
        )

      capture_log(fn ->
        assert {:error,
                {:hook_callback_failed, :after_verify,
                 {:exception, %RuntimeError{message: "after boom"}}}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)
    end

    test "an after_verify that clears the result keeps the original response", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: NilResultAfterVerifyHooks}
        )

      assert {:ok, %{status: 200, body: %{"verified" => true}}} =
               Facilitator.verify(facilitator, %{}, %{})
    end

    test "an after_verify that replaces the result with a non-map is an error", %{
      bypass: bypass,
      finch: finch,
      facilitator_url: facilitator_url
    } do
      Bypass.expect(bypass, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
      end)

      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: BadResultAfterVerifyHooks}
        )

      capture_log(fn ->
        assert {:error, {:hook_invalid_return, :after_verify, {:invalid_result, :nope}}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)
    end

    test "a non-map recovery from on_verify_failure is an error", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: BadRecoverHooks}
        )

      capture_log(fn ->
        assert {:error,
                {:hook_invalid_return, :on_verify_failure, {:invalid_recovery_result, :not_a_map}}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "11"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)
    end

    test "an invalid on_verify_failure return is an error", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: InvalidFailureReturnHooks}
        )

      capture_log(fn ->
        assert {:error, {:hook_invalid_return, :on_verify_failure, :bogus}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "11"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)
    end

    test "a raising on_verify_failure is an error", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: RaisingFailureHooks}
        )

      capture_log(fn ->
        assert {:error,
                {:hook_callback_failed, :on_verify_failure,
                 {:exception, %RuntimeError{message: "failure hook boom"}}}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "11"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)
    end

    test "an on_verify_failure that clears the error falls back to the original", %{
      finch: finch,
      facilitator_url: facilitator_url
    } do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: facilitator_url,
           hooks: NilErrorFailureHooks}
        )

      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "11"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)
    end
  end

  describe "upto validation edge cases" do
    setup %{finch: finch, facilitator_url: facilitator_url} do
      facilitator =
        start_supervised!(
          {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
        )

      {:ok, facilitator: facilitator}
    end

    test "verify requires a max price", %{facilitator: facilitator} do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :missing_max_price}} =
                 Facilitator.verify(facilitator, %{"value" => "5"}, %{"scheme" => "upto"})
      end)
    end

    test "verify rejects an unparseable max price", %{facilitator: facilitator} do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :invalid_max_price}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "5"},
                   %{"scheme" => "upto", "maxPrice" => "abc"}
                 )
      end)
    end

    test "verify requires a payment value", %{facilitator: facilitator} do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :missing_payment_value}} =
                 Facilitator.verify(facilitator, %{}, %{"scheme" => "upto", "maxPrice" => "10"})
      end)
    end

    test "verify rejects an unparseable payment value", %{facilitator: facilitator} do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :invalid_payment_value}} =
                 Facilitator.verify(
                   facilitator,
                   %{"value" => "abc"},
                   %{"scheme" => "upto", "maxPrice" => "10"}
                 )
      end)
    end

    test "settle rejects an unparseable settlement amount", %{facilitator: facilitator} do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :invalid_settlement_amount}} =
                 Facilitator.settle(
                   facilitator,
                   %{"value" => "5"},
                   %{"scheme" => "upto", "amount" => "abc"}
                 )
      end)
    end

    test "settle rejects a settlement amount above the authorized amount", %{
      facilitator: facilitator
    } do
      capture_log(fn ->
        assert {:error, {:invalid_upto_payment, :settlement_amount_exceeds_authorized_amount}} =
                 Facilitator.settle(
                   facilitator,
                   %{"value" => "10"},
                   %{"scheme" => "upto", "amount" => "20"}
                 )
      end)
    end
  end

  describe "auth request info derivation" do
    test "a URL without a host binds auth to an empty host", %{finch: finch} do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"), finch: finch, url: "not-a-url", auth: RecordingAuth}
        )

      capture_log(fn ->
        assert {:error, %Error{type: :auth_failed, reason: :recorded}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)

      assert_received {:auth_request_info, %{method: :post, host: ""}}
    end

    test "a URL without a scheme keeps the explicit port in the host", %{finch: finch} do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: "//localhost:9080",
           auth: RecordingAuth}
        )

      capture_log(fn ->
        assert {:error, %Error{type: :auth_failed, reason: :recorded}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)

      assert_received {:auth_request_info, %{host: "localhost:9080"}}
    end

    test "a scheme without a known port binds auth to the bare host", %{finch: finch} do
      facilitator =
        start_supervised!(
          {Facilitator,
           name: unique_name("facilitator"),
           finch: finch,
           url: "zzz://localhost",
           auth: RecordingAuth}
        )

      capture_log(fn ->
        assert {:error, %Error{type: :auth_failed, reason: :recorded}} =
                 Facilitator.verify(facilitator, %{}, %{})
      end)

      assert_received {:auth_request_info, %{host: "localhost"}}
    end
  end

  test "start_link rejects auth values that are neither modules nor tuples" do
    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, auth: "not-an-auth")
  end

  test "init/1 stops on auth options that fail to build" do
    assert {:stop, {:invalid_auth, :invalid_secret_format}} =
             Facilitator.init(
               auth: {X402.Facilitator.Auth.CDP, api_key_id: "key", api_key_secret: "not-base64"}
             )
  end

  test "supported/1 fails closed on a kind with a non-map extra", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "GET", "/supported", fn conn ->
      Plug.Conn.resp(
        conn,
        200,
        Jason.encode!(%{
          "kinds" => [
            %{"x402Version" => 2, "scheme" => "exact", "network" => "eip155:1", "extra" => "bad"}
          ]
        })
      )
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    capture_log(fn ->
      assert {:error,
              %Error{type: :malformed_facilitator_response, reason: {:invalid_kind, _kind}}} =
               Facilitator.supported(facilitator)
    end)
  end

  test "hook context struct includes payload and requirements" do
    assert %Context{payload: %{a: 1}, requirements: %{b: 2}, result: nil, error: nil} =
             Context.new(%{a: 1}, %{b: 2})
  end

  defp unique_name(prefix) do
    String.to_atom("#{prefix}_#{System.unique_integer([:positive, :monotonic])}")
  end

  defp set_facilitator_config(app, name, opts) do
    previous = Application.get_env(app, name)
    Application.put_env(app, name, opts)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(app, name)
        value -> Application.put_env(app, name, value)
      end
    end)
  end

  defp verify_jwt(token, public_key) do
    [header_part, payload_part, signature_part] = String.split(token, ".")
    signing_input = header_part <> "." <> payload_part
    signature = Base.url_decode64!(signature_part, padding: false)
    :crypto.verify(:eddsa, :none, signing_input, signature, [public_key, :ed25519])
  end

  defp jwt_payload(token) do
    [_header_part, payload_part, _signature_part] = String.split(token, ".")
    payload_part |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end
end
