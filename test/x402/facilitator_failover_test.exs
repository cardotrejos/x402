defmodule X402.FacilitatorFailoverTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import X402.TestHelpers

  alias X402.Facilitator
  alias X402.Facilitator.Error

  defmodule HeaderAuth do
    @moduledoc false
    @behaviour X402.Facilitator.Auth

    defstruct [:value]

    @impl true
    def new(opts), do: {:ok, %__MODULE__{value: Keyword.fetch!(opts, :value)}}

    @impl true
    def headers(%__MODULE__{value: value}, _request_info), do: {:ok, [{"x-endpoint", value}]}
  end

  @payload %{"signature" => "abc"}
  @requirements %{"scheme" => "exact"}

  setup :setup_finch

  setup do
    primary = Bypass.open()
    fallback = Bypass.open()

    {:ok,
     primary: primary,
     fallback: fallback,
     primary_url: "http://localhost:#{primary.port}",
     fallback_url: "http://localhost:#{fallback.port}"}
  end

  describe "option validation" do
    test "rejects a fallback without a url", %{finch: finch, primary_url: primary_url} do
      assert {:error, %NimbleOptions.ValidationError{key: :fallbacks}} =
               Facilitator.start_link(
                 name: unique_name("facilitator"),
                 finch: finch,
                 url: primary_url,
                 fallbacks: [[auth: nil]]
               )
    end

    test "rejects an invalid failover policy", %{finch: finch, primary_url: primary_url} do
      assert {:error, %NimbleOptions.ValidationError{key: :failover}} =
               Facilitator.start_link(
                 name: unique_name("facilitator"),
                 finch: finch,
                 url: primary_url,
                 failover: [cooldown_ms: -1]
               )
    end

    test "rejects a fallback auth that cannot be built", ctx do
      defmodule BrokenAuth do
        @moduledoc false
        @behaviour X402.Facilitator.Auth
        def new(_opts), do: {:error, :no_credentials}
        def headers(_auth, _info), do: {:ok, []}
      end

      assert {:error, {:invalid_auth, :no_credentials}} =
               Facilitator.start_link(
                 name: unique_name("facilitator"),
                 finch: ctx.finch,
                 url: ctx.primary_url,
                 fallbacks: [[url: ctx.fallback_url, auth: BrokenAuth]]
               )
    end

    test "child_spec/1 carries the failover options", ctx do
      spec =
        Facilitator.child_spec(
          name: unique_name("facilitator"),
          finch: ctx.finch,
          url: ctx.primary_url,
          fallbacks: [[url: ctx.fallback_url]],
          failover: [cooldown_ms: 5]
        )

      {Facilitator, :start_link, [opts]} = spec.start
      assert [fallback] = Keyword.fetch!(opts, :fallbacks)
      assert Keyword.fetch!(fallback, :url) == ctx.fallback_url
      assert Keyword.fetch!(fallback, :auth) == nil
      assert Keyword.fetch!(opts, :failover) == %{max_attempts: nil, cooldown_ms: 5}
    end

    test "fallbacks inherit the primary's transport settings", ctx do
      facilitator =
        start_facilitator(ctx,
          receive_timeout_ms: 321,
          max_retries: 1,
          fallbacks: [[url: ctx.fallback_url, receive_timeout_ms: 5]]
        )

      state = :sys.get_state(facilitator)

      assert [
               %{
                 url: url,
                 finch: finch,
                 auth: nil,
                 max_retries: 1,
                 retry_backoff_ms: 100,
                 receive_timeout_ms: 5
               }
             ] = state.fallbacks

      assert url == ctx.fallback_url
      assert finch == ctx.finch
      assert state.breaker == %{}
    end
  end

  describe "verify/3" do
    test "fails over to the fallback on a 5xx and emits telemetry", ctx do
      handler = attach_failover_handler()

      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 503, "unavailable")
      end)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{status: 200, body: %{"isValid" => true}}} =
               Facilitator.verify(facilitator, @payload, @requirements)

      assert_receive {:failover, metadata}
      assert metadata.operation == :verify
      assert metadata.from == ctx.primary_url
      assert metadata.to == ctx.fallback_url
      assert metadata.reason == :http_error
      assert metadata.status == 503

      :telemetry.detach(handler)
    end

    test "fails over when the primary refuses connections", ctx do
      Bypass.down(ctx.primary)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
    end

    test "fails over when the primary times out", ctx do
      primary = ctx.primary

      Bypass.stub(ctx.primary, "POST", "/verify", fn conn ->
        Bypass.pass(primary)
        Process.sleep(200)
        Plug.Conn.resp(conn, 200, "{}")
      end)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
      end)

      facilitator =
        start_facilitator(ctx, receive_timeout_ms: 50, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{status: 200, body: %{"isValid" => true}}} =
               Facilitator.verify(facilitator, @payload, @requirements)
    end

    test "does not fail over on a 4xx", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 400, Jason.encode!(%{"error" => "bad"}))
      end)

      stub_never_called(ctx.fallback, "POST", "/verify")

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{type: :http_error, status: 400}} =
                 Facilitator.verify(facilitator, @payload, @requirements)
      end)

      refute_receive {:fallback_called, _path}
    end

    test "does not fail over on a verification failure answered with 200", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => false, "invalidReason" => "x"}))
      end)

      stub_never_called(ctx.fallback, "POST", "/verify")

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{body: %{"isValid" => false}}} =
               Facilitator.verify(facilitator, @payload, @requirements)

      refute_receive {:fallback_called, _path}
    end

    test "returns the last error when every endpoint fails", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 500, "a")
      end)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 502, "b")
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{type: :http_error, status: 502}} =
                 Facilitator.verify(facilitator, @payload, @requirements)
      end)
    end

    test "max_attempts: 1 disables failover", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 503, "a")
      end)

      stub_never_called(ctx.fallback, "POST", "/verify")

      facilitator =
        start_facilitator(ctx,
          fallbacks: [[url: ctx.fallback_url]],
          failover: [max_attempts: 1]
        )

      capture_log(fn ->
        assert {:error, %Error{status: 503}} =
                 Facilitator.verify(facilitator, @payload, @requirements)
      end)

      refute_receive {:fallback_called, _path}
    end

    test "uses the fallback's own auth", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/verify", fn conn ->
        assert Plug.Conn.get_req_header(conn, "x-endpoint") == ["primary"]
        Plug.Conn.resp(conn, 503, "a")
      end)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        assert Plug.Conn.get_req_header(conn, "x-endpoint") == ["fallback"]
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
      end)

      facilitator =
        start_facilitator(ctx,
          auth: {HeaderAuth, value: "primary"},
          fallbacks: [[url: ctx.fallback_url, auth: {HeaderAuth, value: "fallback"}]]
        )

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
    end

    test "hooks see the failed-over result", ctx do
      defmodule RecordingHooks do
        @moduledoc false
        @behaviour X402.Hooks
        alias X402.Hooks.Context

        def before_verify(%Context{} = context, _metadata), do: {:cont, context}

        def after_verify(%Context{} = context, _metadata) do
          send(self(), {:after_verify, context.result.body})
          {:cont, context}
        end

        def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
        def before_settle(%Context{} = context, _metadata), do: {:cont, context}
        def after_settle(%Context{} = context, _metadata), do: {:cont, context}
        def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
      end

      Bypass.down(ctx.primary)

      Bypass.expect_once(ctx.fallback, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true, "via" => "fallback"}))
      end)

      facilitator =
        start_facilitator(ctx, hooks: RecordingHooks, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{body: %{"via" => "fallback"}}} =
               Facilitator.verify(facilitator, @payload, @requirements)

      assert_received {:after_verify, %{"via" => "fallback"}}
    end
  end

  describe "settle/3" do
    test "does not fail over on a 5xx", ctx do
      Bypass.expect_once(ctx.primary, "POST", "/settle", fn conn ->
        Plug.Conn.resp(conn, 502, "gateway")
      end)

      stub_never_called(ctx.fallback, "POST", "/settle")

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{type: :http_error, status: 502}} =
                 Facilitator.settle(facilitator, @payload, @requirements)
      end)

      refute_receive {:fallback_called, _path}
      assert :sys.get_state(facilitator).breaker == %{}
    end

    test "does not fail over on a timeout", ctx do
      primary = ctx.primary

      Bypass.stub(ctx.primary, "POST", "/settle", fn conn ->
        Bypass.pass(primary)
        Process.sleep(200)
        Plug.Conn.resp(conn, 200, "{}")
      end)

      stub_never_called(ctx.fallback, "POST", "/settle")

      facilitator =
        start_facilitator(ctx, receive_timeout_ms: 50, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{type: :timeout}} =
                 Facilitator.settle(facilitator, @payload, @requirements)
      end)

      refute_receive {:fallback_called, _path}
    end

    test "fails over when the primary refuses connections", ctx do
      handler = attach_failover_handler()
      Bypass.down(ctx.primary)

      Bypass.expect_once(ctx.fallback, "POST", "/settle", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"success" => true}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{status: 200, body: %{"success" => true}}} =
               Facilitator.settle(facilitator, @payload, @requirements)

      assert_receive {:failover, %{operation: :settle, reason: :transport_error}}

      :telemetry.detach(handler)
    end
  end

  describe "read operations" do
    test "supported/1 fails over on a 5xx", ctx do
      Bypass.expect_once(ctx.primary, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 500, "a")
      end)

      Bypass.expect_once(ctx.fallback, "GET", "/supported", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"kinds" => []}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{kinds: []}} = Facilitator.supported(facilitator)
    end

    test "list_resources/2 fails over when the primary is down", ctx do
      Bypass.down(ctx.primary)

      Bypass.expect_once(ctx.fallback, "GET", "/discovery/resources", fn conn ->
        assert conn.query_string == "limit=5"
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"items" => []}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      assert {:ok, %{items: []}} = Facilitator.list_resources(facilitator, limit: 5)
    end

    test "search_resources/2 fails over on a 5xx but not a malformed body", ctx do
      Bypass.expect_once(ctx.primary, "GET", "/discovery/search", fn conn ->
        Plug.Conn.resp(conn, 503, "a")
      end)

      Bypass.expect_once(ctx.fallback, "GET", "/discovery/search", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"nope" => true}))
      end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{type: :malformed_facilitator_response}} =
                 Facilitator.search_resources(facilitator, query: "weather")
      end)
    end
  end

  describe "circuit breaker" do
    test "skips a tripped primary until the cooldown elapses", ctx do
      owner = self()

      Bypass.stub(ctx.primary, "POST", "/verify", fn conn ->
        send(owner, :primary_called)
        Plug.Conn.resp(conn, 503, "a")
      end)

      Bypass.stub(ctx.fallback, "POST", "/verify", fn conn ->
        send(owner, :fallback_called)
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
      end)

      facilitator =
        start_facilitator(ctx,
          fallbacks: [[url: ctx.fallback_url]],
          failover: [cooldown_ms: 150]
        )

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
      assert_receive :primary_called
      assert_receive :fallback_called

      assert Map.has_key?(:sys.get_state(facilitator).breaker, ctx.primary_url)

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
      refute_receive :primary_called
      assert_receive :fallback_called

      Process.sleep(160)

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
      assert_receive :primary_called
      assert_receive :fallback_called
    end

    test "a success on a tripped endpoint closes its circuit", ctx do
      owner = self()
      {:ok, primary_calls} = Agent.start_link(fn -> 0 end)

      Bypass.stub(ctx.primary, "POST", "/verify", fn conn ->
        send(owner, :primary_called)

        case Agent.get_and_update(primary_calls, &{&1, &1 + 1}) do
          0 -> Plug.Conn.resp(conn, 503, "a")
          _later -> Plug.Conn.resp(conn, 200, Jason.encode!(%{"isValid" => true}))
        end
      end)

      Bypass.stub(ctx.fallback, "POST", "/verify", fn conn ->
        send(owner, :fallback_called)
        Plug.Conn.resp(conn, 503, "b")
      end)

      facilitator =
        start_facilitator(ctx,
          fallbacks: [[url: ctx.fallback_url]],
          failover: [cooldown_ms: 60_000]
        )

      capture_log(fn ->
        assert {:error, %Error{status: 503}} =
                 Facilitator.verify(facilitator, @payload, @requirements)
      end)

      breaker = :sys.get_state(facilitator).breaker
      assert Map.has_key?(breaker, ctx.primary_url)
      assert Map.has_key?(breaker, ctx.fallback_url)

      assert {:ok, %{status: 200}} = Facilitator.verify(facilitator, @payload, @requirements)
      assert_receive :primary_called

      breaker = :sys.get_state(facilitator).breaker
      refute Map.has_key?(breaker, ctx.primary_url)
      assert Map.has_key?(breaker, ctx.fallback_url)
    end

    test "settle never trips the breaker on a 5xx", ctx do
      Bypass.stub(ctx.primary, "POST", "/settle", fn conn -> Plug.Conn.resp(conn, 503, "a") end)

      facilitator = start_facilitator(ctx, fallbacks: [[url: ctx.fallback_url]])

      capture_log(fn ->
        assert {:error, %Error{status: 503}} =
                 Facilitator.settle(facilitator, @payload, @requirements)
      end)

      assert :sys.get_state(facilitator).breaker == %{}
    end
  end

  test "without fallbacks the breaker is never consulted", ctx do
    Bypass.stub(ctx.primary, "POST", "/verify", fn conn -> Plug.Conn.resp(conn, 503, "a") end)

    facilitator = start_facilitator(ctx, [])

    capture_log(fn ->
      assert {:error, %Error{status: 503}} =
               Facilitator.verify(facilitator, @payload, @requirements)
    end)

    assert :sys.get_state(facilitator).breaker == %{}
    assert :sys.get_state(facilitator).fallbacks == []
  end

  defp unique_name(prefix),
    do: String.to_atom("#{prefix}_failover_#{System.unique_integer([:positive, :monotonic])}")

  defp start_facilitator(ctx, opts) do
    start_supervised!(
      {Facilitator,
       Keyword.merge(
         [
           name: unique_name("facilitator"),
           finch: ctx.finch,
           url: ctx.primary_url,
           max_retries: 0
         ],
         opts
       )}
    )
  end

  defp stub_never_called(bypass, method, path) do
    owner = self()

    Bypass.stub(bypass, method, path, fn conn ->
      send(owner, {:fallback_called, path})
      Plug.Conn.resp(conn, 200, "{}")
    end)
  end

  defp attach_failover_handler do
    owner = self()
    handler = "facilitator-failover-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        [:x402, :facilitator, :failover],
        fn _event, _measurements, metadata, _config -> send(owner, {:failover, metadata}) end,
        nil
      )

    handler
  end
end
