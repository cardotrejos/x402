defmodule X402.Telemetry.Stats do
  @moduledoc """
  Dependency-free in-memory aggregator for x402 telemetry events.

  For deployments without LiveDashboard or a `Telemetry.Metrics` reporter:
  `attach/1` subscribes to every event in `X402.Telemetry.events/0` and
  keeps per-event counters (total and per status) plus simple latency
  statistics for span events that carry a `:duration` measurement, in a
  lazily created ETS table. `snapshot/1` reads them back:

      :ok = X402.Telemetry.Stats.attach()
      # ... traffic ...
      X402.Telemetry.Stats.snapshot()
      #=> %{
      #     [:x402, :plug, :payment_verified] => %{count: 42, by_status: %{}, latency: nil},
      #     [:x402, :facilitator, :verify, :stop] => %{
      #       count: 42,
      #       by_status: %{ok: 40, error: 2},
      #       latency: %{count: 42, min_us: 812, max_us: 9_120, mean_us: 2_310, sum_us: 97_020}
      #     },
      #     ...
      #   }

  Status is read from the `:status` metadata (`:ok` / `:error` events) or
  derived from `:success` (facilitator spans). Counters are ETS atomics;
  latency minima and maxima are compare-and-swap updates, so concurrent
  events never lose samples.

  The table needs no supervision. Call `detach/1` to stop aggregating and
  drop it, or `reset/1` to zero the counters while attached.
  """

  alias X402.ETSTable
  alias X402.Telemetry

  @default_name __MODULE__

  @attach_schema [
    name: [
      type: :atom,
      default: @default_name,
      doc: "ETS table name (also used to derive the telemetry handler id)."
    ],
    events: [
      type: {:list, {:list, :atom}},
      doc: "Events to aggregate. Defaults to `X402.Telemetry.events/0`."
    ]
  ]

  @typedoc "Latency statistics in microseconds for span events."
  @type latency :: %{
          count: pos_integer(),
          min_us: non_neg_integer(),
          max_us: non_neg_integer(),
          mean_us: non_neg_integer(),
          sum_us: non_neg_integer()
        }

  @typedoc "Aggregated statistics for one event."
  @type event_stats :: %{
          count: non_neg_integer(),
          by_status: %{optional(atom()) => non_neg_integer()},
          latency: latency() | nil
        }

  @typedoc "Snapshot of every event seen since attaching (or the last reset)."
  @type snapshot :: %{optional(Telemetry.event()) => event_stats()}

  @doc since: "0.9.0"
  @doc """
  Attaches the aggregator to the x402 telemetry events.

  Returns `{:error, :already_attached}` when a handler for `:name` exists.

  ## Options

  #{NimbleOptions.docs(@attach_schema)}
  """
  @spec attach(keyword()) :: :ok | {:error, :already_attached}
  def attach(opts \\ []) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @attach_schema)
    name = Keyword.fetch!(opts, :name)
    events = Keyword.get(opts, :events, Telemetry.events())
    table = ensure_table(name)

    case :telemetry.attach_many(handler_id(name), events, &__MODULE__.handle_event/4, %{
           table: table
         }) do
      :ok -> :ok
      {:error, :already_exists} -> {:error, :already_attached}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Detaches the aggregator and drops its table.
  """
  @spec detach(atom()) :: :ok
  def detach(name \\ @default_name) when is_atom(name) do
    _ = :telemetry.detach(handler_id(name))
    ETSTable.delete(name)
  end

  @doc since: "0.9.0"
  @doc """
  Zeroes every counter while staying attached.
  """
  @spec reset(atom()) :: :ok
  def reset(name \\ @default_name) when is_atom(name) do
    table = ensure_table(name)
    :ets.match_delete(table, {{:_, :_}, :_})
    :ok
  end

  @doc since: "0.9.0"
  @doc """
  Returns the aggregated statistics per event.

  Events that were never observed are absent from the map.
  """
  @spec snapshot(atom()) :: snapshot()
  def snapshot(name \\ @default_name) when is_atom(name) do
    table = ensure_table(name)

    table
    |> :ets.match_object({{:_, :_}, :_})
    |> Enum.group_by(fn {{event, _field}, _value} -> event end)
    |> Map.new(fn {event, rows} -> {event, event_stats(rows)} end)
  end

  @doc false
  @spec handle_event(Telemetry.event(), map(), map(), %{table: atom()}) :: :ok
  def handle_event(event, measurements, metadata, %{table: table}) do
    :ets.update_counter(table, {event, :count}, 1, {{event, :count}, 0})

    case status_of(metadata) do
      nil ->
        :ok

      status ->
        :ets.update_counter(table, {event, {:status, status}}, 1, {{event, {:status, status}}, 0})
    end

    case measurements do
      %{duration: duration} when is_integer(duration) and duration >= 0 ->
        record_latency(table, event, System.convert_time_unit(duration, :native, :microsecond))

      _no_duration ->
        :ok
    end
  end

  defp status_of(%{status: status}) when is_atom(status) and not is_nil(status), do: status
  defp status_of(%{success: true}), do: :ok
  defp status_of(%{success: false}), do: :error
  defp status_of(_metadata), do: nil

  defp record_latency(table, event, micros) do
    :ets.update_counter(table, {event, :latency_count}, 1, {{event, :latency_count}, 0})
    :ets.update_counter(table, {event, :latency_sum_us}, micros, {{event, :latency_sum_us}, 0})
    cas_extreme(table, {event, :latency_min_us}, micros, &Kernel.</2)
    cas_extreme(table, {event, :latency_max_us}, micros, &Kernel.>/2)
  end

  defp cas_extreme(table, key, value, better?) do
    case :ets.lookup(table, key) do
      [] ->
        :ets.insert_new(table, {key, value}) or cas_extreme(table, key, value, better?)

      [{^key, current}] ->
        if better?.(value, current) do
          replaced =
            :ets.select_replace(table, [
              {{:"$1", :"$2"}, [{:"=:=", :"$1", {:const, key}}, {:"=:=", :"$2", current}],
               [{{:"$1", value}}]}
            ])

          replaced == 1 or cas_extreme(table, key, value, better?)
        else
          true
        end
    end

    :ok
  end

  defp event_stats(rows) do
    fields = Map.new(rows, fn {{_event, field}, value} -> {field, value} end)

    by_status =
      for {{:status, status}, count} <- fields, into: %{}, do: {status, count}

    %{
      count: Map.get(fields, :count, 0),
      by_status: by_status,
      latency: latency(fields)
    }
  end

  defp latency(%{latency_count: count, latency_sum_us: sum} = fields) when count > 0 do
    %{
      count: count,
      min_us: Map.get(fields, :latency_min_us, 0),
      max_us: Map.get(fields, :latency_max_us, 0),
      mean_us: div(sum, count),
      sum_us: sum
    }
  end

  defp latency(_fields), do: nil

  defp handler_id(name), do: {__MODULE__, name}

  defp ensure_table(name),
    do: ETSTable.ensure(name, [:set, read_concurrency: true, write_concurrency: true])
end
