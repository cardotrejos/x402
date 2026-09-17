defmodule X402.Telemetry.StatsTest do
  # The aggregator subscribes to global telemetry events, so this module
  # must not run alongside other tests that emit x402 events.
  use ExUnit.Case, async: false

  alias X402.Telemetry
  alias X402.Telemetry.Stats

  setup do
    name = :"x402_stats_test_#{System.unique_integer([:positive, :monotonic])}"
    :ok = Stats.attach(name: name)
    on_exit(fn -> Stats.detach(name) end)
    {:ok, name: name}
  end

  test "attach/1 subscribes to every documented event", %{name: name} do
    handlers = :telemetry.list_handlers([:x402])
    assert Enum.any?(handlers, &(&1.id == {Stats, name}))

    ids = for handler <- handlers, handler.id == {Stats, name}, do: handler.event_name
    assert Enum.sort(ids) == Enum.sort(Telemetry.events())
  end

  test "attach/1 refuses to attach twice", %{name: name} do
    assert Stats.attach(name: name) == {:error, :already_attached}
  end

  test "attach/1 validates options" do
    assert_raise NimbleOptions.ValidationError, fn -> Stats.attach(name: "nope") end
  end

  test "snapshot/1 is empty before any event", %{name: name} do
    assert Stats.snapshot(name) == %{}
  end

  test "counts emit-style events by status", %{name: name} do
    Telemetry.emit(:payment_required, :encode, :ok)
    Telemetry.emit(:payment_required, :encode, :ok)
    Telemetry.emit(:payment_required, :encode, :error, %{reason: :invalid_json})

    assert %{
             [:x402, :payment_required, :encode] => %{
               count: 3,
               by_status: %{ok: 2, error: 1},
               latency: nil
             }
           } = Stats.snapshot(name)
  end

  test "counts gate events without a status", %{name: name} do
    :telemetry.execute([:x402, :plug, :rate_limited], %{count: 1}, %{route: "/api"})
    :telemetry.execute([:x402, :plug, :rate_limited], %{count: 1}, %{route: "/api"})

    assert Stats.snapshot(name)[[:x402, :plug, :rate_limited]] ==
             %{count: 2, by_status: %{}, latency: nil}
  end

  test "records latency and outcome for facilitator spans", %{name: name} do
    :telemetry.span([:x402, :facilitator, :verify], %{}, fn ->
      Process.sleep(2)
      {:ok, %{success: true}}
    end)

    :telemetry.span([:x402, :facilitator, :verify], %{}, fn ->
      {:error, %{success: false}}
    end)

    snapshot = Stats.snapshot(name)

    assert %{count: 2, by_status: %{}} = snapshot[[:x402, :facilitator, :verify, :start]]

    assert %{
             count: 2,
             by_status: %{ok: 1, error: 1},
             latency: %{
               count: 2,
               min_us: min_us,
               max_us: max_us,
               mean_us: mean_us,
               sum_us: sum_us
             }
           } = snapshot[[:x402, :facilitator, :verify, :stop]]

    assert min_us >= 0
    assert max_us >= 2_000
    assert min_us <= mean_us and mean_us <= max_us
    assert sum_us == mean_us * 2 or sum_us == mean_us * 2 + 1
  end

  test "counts span exceptions", %{name: name} do
    assert_raise RuntimeError, fn ->
      :telemetry.span([:x402, :facilitator, :settle], %{}, fn -> raise "boom" end)
    end

    assert %{count: 1, latency: %{count: 1}} =
             Stats.snapshot(name)[[:x402, :facilitator, :settle, :exception]]
  end

  test "latency extremes are tracked under concurrency", %{name: name} do
    event = [:x402, :facilitator, :supported, :stop]

    1..100
    |> Task.async_stream(
      fn index ->
        duration = System.convert_time_unit(index * 10, :microsecond, :native)
        :telemetry.execute(event, %{duration: duration}, %{success: true})
      end,
      max_concurrency: 32
    )
    |> Stream.run()

    assert %{count: 100, latency: %{count: 100, min_us: 10, max_us: 1_000}} =
             Stats.snapshot(name)[event]
  end

  test "ignores non-integer durations", %{name: name} do
    :telemetry.execute([:x402, :facilitator, :verify, :stop], %{duration: :oops}, %{})

    assert Stats.snapshot(name)[[:x402, :facilitator, :verify, :stop]] ==
             %{count: 1, by_status: %{}, latency: nil}
  end

  test "reset/1 zeroes counters while staying attached", %{name: name} do
    Telemetry.emit(:client, :request, :ok)
    assert Stats.snapshot(name) != %{}

    assert Stats.reset(name) == :ok
    assert Stats.snapshot(name) == %{}

    Telemetry.emit(:client, :request, :ok)
    assert %{count: 1} = Stats.snapshot(name)[[:x402, :client, :request]]
  end

  test "detach/1 removes the handler and the table", %{name: name} do
    assert Stats.detach(name) == :ok

    refute Enum.any?(:telemetry.list_handlers([:x402]), &(&1.id == {Stats, name}))
    assert :ets.whereis(name) == :undefined

    assert Stats.detach(name) == :ok
  end

  test "a custom event list narrows aggregation" do
    name = :"x402_stats_custom_#{System.unique_integer([:positive])}"
    :ok = Stats.attach(name: name, events: [[:x402, :client, :sign]])
    on_exit(fn -> Stats.detach(name) end)

    Telemetry.emit(:client, :sign, :ok)
    Telemetry.emit(:client, :build, :ok)

    assert Map.keys(Stats.snapshot(name)) == [[:x402, :client, :sign]]
  end

  test "the default name works with no arguments" do
    Stats.detach()
    assert Stats.attach() == :ok
    on_exit(fn -> Stats.detach() end)

    Telemetry.emit(:client, :build, :ok)
    assert %{count: count} = Stats.snapshot()[[:x402, :client, :build]]
    assert count >= 1
    assert Stats.reset() == :ok
  end
end
