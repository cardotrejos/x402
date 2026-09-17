if Code.ensure_loaded?(Telemetry.Metrics) do
  defmodule X402.Telemetry.Metrics do
    @moduledoc """
    `Telemetry.Metrics` definitions for every x402 telemetry event.

    Ready to hand to Phoenix LiveDashboard or any `Telemetry.Metrics`
    reporter, without this library depending on Phoenix:

        # router.ex
        live_dashboard "/dashboard", metrics: X402.Telemetry.Metrics

        # or a reporter
        {TelemetryMetricsPrometheus, metrics: X402.Telemetry.Metrics.metrics()}

    Requires the optional `:telemetry_metrics` dependency
    (`{:telemetry_metrics, "~> 1.0"}`). `X402.Telemetry.Stats` provides a
    dependency-free aggregator for deployments without a reporter.

    ## Definitions

    Every event listed by `X402.Telemetry.events/0` is covered:

    * emit-style events (`%{count: 1}` measurements) become counters
      tagged by `:status`, plus a `:reason` tag on the client, RPC, local
      verification, and engine events;
    * `[:x402, :plug, ...]` and `[:x402, :mcp, ...]` events become counters
      tagged by route/tool and, for rejections, by `:reason`;
    * `[:x402, :facilitator, operation, :stop]` spans become a counter, a
      summary, and a distribution of `:duration` in milliseconds tagged by
      `:success`, and `:exception` events a counter tagged by `:kind`;
    * `[:x402, :facilitator, :failover]` becomes a counter tagged by
      operation and reason.

    Tag values that are error terms (tuples, structs) are reduced to an
    atom with `reason_tag/1` so that a malformed payload cannot explode the
    tag cardinality of a reporter.
    """

    import Telemetry.Metrics

    @components [
      :payment_required,
      :payment_signature,
      :payment_response,
      :extension_responses,
      :payment_identifier,
      :siwx,
      :client,
      :rpc,
      :verify,
      :facilitator_engine,
      :plug,
      :mcp,
      :facilitator
    ]

    @filter_schema [
      only: [
        type: {:list, {:in, @components}},
        doc: "Components to include (the second element of each event name)."
      ],
      except: [
        type: {:list, {:in, @components}},
        doc: "Components to exclude."
      ]
    ]

    @reason_tagged_components [:client, :rpc, :verify, :facilitator_engine, :extension_responses]

    @duration_buckets_ms [5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000]

    @typedoc "A `Telemetry.Metrics` metric definition."
    @type metric :: Telemetry.Metrics.t()

    @doc since: "0.9.0"
    @doc """
    Returns metric definitions for every x402 telemetry event.

    ## Examples

        iex> metrics = X402.Telemetry.Metrics.metrics()
        iex> Enum.all?(metrics, &is_struct/1)
        true
    """
    @spec metrics() :: [metric()]
    def metrics, do: metrics([])

    @doc since: "0.9.0"
    @doc """
    Returns metric definitions filtered by component.

    ## Options

    #{NimbleOptions.docs(@filter_schema)}

    ## Examples

        iex> metrics = X402.Telemetry.Metrics.metrics(only: [:plug])
        iex> Enum.all?(metrics, &(Enum.at(&1.event_name, 1) == :plug))
        true

        iex> metrics = X402.Telemetry.Metrics.metrics(except: [:facilitator, :client])
        iex> Enum.any?(metrics, &(Enum.at(&1.event_name, 1) in [:facilitator, :client]))
        false
    """
    @spec metrics(keyword()) :: [metric()]
    def metrics(opts) when is_list(opts) do
      opts = NimbleOptions.validate!(opts, @filter_schema)
      only = Keyword.get(opts, :only)
      except = Keyword.get(opts, :except, [])

      X402.Telemetry.events()
      |> Enum.filter(fn [:x402, component | _rest] ->
        (is_nil(only) or component in only) and component not in except
      end)
      |> Enum.flat_map(&definitions/1)
    end

    @doc since: "0.9.0"
    @doc """
    Reduces a `:reason` metadata value to a low-cardinality atom tag.

    Tuples reduce to their first element when it is an atom, structs to
    their `:type` field or module name, atoms and strings pass through, and
    anything else becomes `:other`.

    ## Examples

        iex> X402.Telemetry.Metrics.reason_tag(:invalid_base64)
        :invalid_base64

        iex> X402.Telemetry.Metrics.reason_tag({:verification_failed, "insufficient_funds"})
        :verification_failed

        iex> X402.Telemetry.Metrics.reason_tag(%X402.Facilitator.Error{type: :timeout})
        :timeout

        iex> X402.Telemetry.Metrics.reason_tag(%{"weird" => true})
        :other
    """
    @spec reason_tag(term()) :: atom() | String.t()
    def reason_tag(nil), do: :none
    def reason_tag(reason) when is_atom(reason), do: reason
    def reason_tag(reason) when is_binary(reason), do: reason
    def reason_tag(%{__struct__: _module, type: type}) when is_atom(type), do: type
    def reason_tag(%{__struct__: module}), do: module

    def reason_tag(tuple) when is_tuple(tuple) and tuple_size(tuple) > 0,
      do: reason_tag_head(tuple)

    def reason_tag(_reason), do: :other

    defp reason_tag_head(tuple) do
      case elem(tuple, 0) do
        head when is_atom(head) -> head
        _head -> :other
      end
    end

    @doc false
    @spec tag_values(map()) :: map()
    def tag_values(metadata) when is_map(metadata) do
      metadata
      |> Map.update(:reason, :none, &reason_tag/1)
      |> Map.update(:status, :none, &status_tag/1)
      |> Map.update(:success, :none, &success_tag/1)
      |> Map.update(:route, :none, &route_tag/1)
      |> Map.update(:kind, :none, & &1)
    end

    defp status_tag(status) when is_atom(status), do: status
    defp status_tag(status) when is_integer(status), do: status
    defp status_tag(_status), do: :other

    defp success_tag(true), do: :ok
    defp success_tag(false), do: :error
    defp success_tag(_success), do: :none

    defp route_tag(route) when is_binary(route), do: route
    defp route_tag(_route), do: :none

    # --- definitions per event ---

    defp definitions([:x402, :facilitator, operation, :stop] = event) do
      name = "x402.facilitator.#{operation}"

      [
        counter("#{name}.stop.count",
          event_name: event,
          measurement: :duration,
          tags: [:success],
          tag_values: &tag_values/1,
          description: "Facilitator #{operation} calls by outcome"
        ),
        summary("#{name}.stop.duration",
          event_name: event,
          measurement: :duration,
          unit: {:native, :millisecond},
          tags: [:success],
          tag_values: &tag_values/1,
          description: "Facilitator #{operation} round-trip duration"
        ),
        distribution("#{name}.stop.duration",
          event_name: event,
          measurement: :duration,
          unit: {:native, :millisecond},
          tags: [:success],
          tag_values: &tag_values/1,
          reporter_options: [buckets: @duration_buckets_ms],
          description: "Facilitator #{operation} round-trip duration distribution"
        )
      ]
    end

    defp definitions([:x402, :facilitator, operation, :exception] = event) do
      [
        counter("x402.facilitator.#{operation}.exception.count",
          event_name: event,
          measurement: :duration,
          tags: [:kind],
          tag_values: &tag_values/1,
          description: "Facilitator #{operation} calls that raised"
        )
      ]
    end

    defp definitions([:x402, :facilitator, _operation, :start]), do: []

    defp definitions([:x402, :facilitator, :failover] = event) do
      [
        counter("x402.facilitator.failover.count",
          event_name: event,
          measurement: :count,
          tags: [:operation, :reason],
          tag_values: &tag_values/1,
          description: "Facilitator requests that failed over to a fallback endpoint"
        )
      ]
    end

    defp definitions([:x402, :plug, :payment_rejected] = event) do
      [
        counter("x402.plug.payment_rejected.count",
          event_name: event,
          measurement: :count,
          tags: [:route, :reason],
          tag_values: &tag_values/1,
          description: "Gated requests rejected, by route and reason"
        )
      ]
    end

    defp definitions([:x402, :plug, :rate_limited] = event) do
      [
        counter("x402.plug.rate_limited.count",
          event_name: event,
          measurement: :count,
          tags: [:route],
          tag_values: &tag_values/1,
          description: "Gated requests answered 429 by the per-wallet rate limiter"
        )
      ]
    end

    defp definitions([:x402, :plug, operation] = event) do
      [
        counter("x402.plug.#{operation}.count",
          event_name: event,
          measurement: :count,
          tags: [:route],
          tag_values: &tag_values/1,
          description: "Payment gate #{operation} events by route"
        )
      ]
    end

    defp definitions([:x402, :mcp, :payment_rejected] = event) do
      [
        counter("x402.mcp.payment_rejected.count",
          event_name: event,
          measurement: :count,
          tags: [:reason],
          tag_values: &tag_values/1,
          description: "MCP tool payments rejected, by reason"
        )
      ]
    end

    defp definitions([:x402, :mcp, :call] = event) do
      [
        counter("x402.mcp.call.count",
          event_name: event,
          measurement: :count,
          tags: [:status, :reason],
          tag_values: &tag_values/1,
          description: "MCP client tool calls by outcome"
        )
      ]
    end

    defp definitions([:x402, :mcp, operation] = event) do
      [
        counter("x402.mcp.#{operation}.count",
          event_name: event,
          measurement: :count,
          description: "MCP server #{operation} events"
        )
      ]
    end

    defp definitions([:x402, component, operation] = event)
         when component in @reason_tagged_components do
      [
        counter("x402.#{component}.#{operation}.count",
          event_name: event,
          measurement: :count,
          tags: [:status, :reason],
          tag_values: &tag_values/1,
          description: "#{component} #{operation} results by status and reason"
        )
      ]
    end

    defp definitions([:x402, component, operation] = event) do
      [
        counter("x402.#{component}.#{operation}.count",
          event_name: event,
          measurement: :count,
          tags: [:status],
          tag_values: &tag_values/1,
          description: "#{component} #{operation} results by status"
        )
      ]
    end
  end
else
  defmodule X402.Telemetry.Metrics do
    @moduledoc """
    `Telemetry.Metrics` definitions for every x402 telemetry event.

    This module requires the optional `:telemetry_metrics` dependency. Add
    `{:telemetry_metrics, "~> 1.0"}` to your project dependencies before
    using it, or use the dependency-free `X402.Telemetry.Stats` aggregator.
    """

    @doc since: "0.9.0"
    @doc """
    Raises because `Telemetry.Metrics` is not available.
    """
    @spec metrics() :: no_return()
    def metrics, do: metrics([])

    @doc since: "0.9.0"
    @doc """
    Raises because `Telemetry.Metrics` is not available.
    """
    @spec metrics(keyword()) :: no_return()
    def metrics(_opts) do
      raise ArgumentError,
            "X402.Telemetry.Metrics requires the optional :telemetry_metrics dependency"
    end
  end
end
