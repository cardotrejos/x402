if Code.ensure_loaded?(Telemetry.Metrics) do
  defmodule X402.Telemetry.MetricsTest do
    use ExUnit.Case, async: true

    doctest X402.Telemetry.Metrics

    alias X402.Facilitator.Error
    alias X402.Telemetry.Metrics

    test "covers every documented event except span starts" do
      covered = Metrics.metrics() |> Enum.map(& &1.event_name) |> MapSet.new()

      expected =
        X402.Telemetry.events()
        |> Enum.reject(&match?([:x402, :facilitator, _operation, :start], &1))
        |> MapSet.new()

      assert covered == expected
    end

    test "every definition targets a documented event" do
      events = MapSet.new(X402.Telemetry.events())

      for metric <- Metrics.metrics() do
        assert MapSet.member?(events, metric.event_name), inspect(metric.event_name)
      end
    end

    test "metric names are unique per metric type" do
      keys = Enum.map(Metrics.metrics(), &{&1.__struct__, &1.name})
      assert keys == Enum.uniq(keys)
    end

    test "facilitator spans get a counter, a summary, and a bucketed distribution" do
      definitions =
        Enum.filter(Metrics.metrics(), &(&1.event_name == [:x402, :facilitator, :settle, :stop]))

      assert [
               %Telemetry.Metrics.Counter{measurement: :duration, tags: [:success]},
               %Telemetry.Metrics.Summary{unit: :millisecond, tags: [:success]},
               %Telemetry.Metrics.Distribution{
                 unit: :millisecond,
                 tags: [:success],
                 reporter_options: [buckets: buckets]
               }
             ] = definitions

      assert buckets == Enum.sort(buckets)

      assert [%Telemetry.Metrics.Counter{tags: [:kind]}] =
               Enum.filter(
                 Metrics.metrics(),
                 &(&1.event_name == [:x402, :facilitator, :settle, :exception])
               )
    end

    test "the failover counter is tagged by operation and reason" do
      assert [%Telemetry.Metrics.Counter{tags: [:operation, :reason], measurement: :count}] =
               Enum.filter(
                 Metrics.metrics(),
                 &(&1.event_name == [:x402, :facilitator, :failover])
               )
    end

    test "gate rejections are tagged by route and reason" do
      assert [%Telemetry.Metrics.Counter{tags: [:route, :reason]}] =
               Enum.filter(
                 Metrics.metrics(),
                 &(&1.event_name == [:x402, :plug, :payment_rejected])
               )

      assert [%Telemetry.Metrics.Counter{tags: [:route]}] =
               Enum.filter(Metrics.metrics(), &(&1.event_name == [:x402, :plug, :rate_limited]))
    end

    test "emit-style events are tagged by status" do
      assert [%Telemetry.Metrics.Counter{tags: [:status]}] =
               Enum.filter(
                 Metrics.metrics(),
                 &(&1.event_name == [:x402, :payment_required, :encode])
               )

      assert [%Telemetry.Metrics.Counter{tags: [:status, :reason]}] =
               Enum.filter(Metrics.metrics(), &(&1.event_name == [:x402, :client, :request]))

      assert [%Telemetry.Metrics.Counter{tags: [:status, :reason]}] =
               Enum.filter(Metrics.metrics(), &(&1.event_name == [:x402, :mcp, :call]))

      assert [%Telemetry.Metrics.Counter{tags: []}] =
               Enum.filter(
                 Metrics.metrics(),
                 &(&1.event_name == [:x402, :mcp, :payment_required])
               )
    end

    test "tag values reduce error terms to low-cardinality tags" do
      for metric <- Metrics.metrics() do
        metadata = %{
          status: :error,
          success: false,
          reason: {:verification_failed, %{"invalidReason" => "insufficient_funds"}},
          route: "/api/resource",
          operation: :verify,
          kind: :error
        }

        tags = metadata |> metric.tag_values.() |> Map.take(metric.tags)

        for {_tag, value} <- tags do
          assert is_atom(value) or is_binary(value) or is_integer(value), inspect(value)
        end
      end
    end

    test "tag_values normalizes missing and odd metadata" do
      assert %{reason: :none, status: :none, success: :none, route: :none} =
               Metrics.tag_values(%{})

      assert %{status: 503, success: :error, route: :none, reason: :timeout} =
               Metrics.tag_values(%{
                 status: 503,
                 success: false,
                 route: nil,
                 reason: %Error{type: :timeout}
               })

      assert %{status: :other, success: :ok} =
               Metrics.tag_values(%{status: "weird", success: true})
    end

    test "reason_tag handles tuples headed by non-atoms" do
      assert Metrics.reason_tag({"string", 1}) == :other
      assert Metrics.reason_tag(%URI{}) == URI
      assert Metrics.reason_tag(42) == :other
      assert Metrics.reason_tag(nil) == :none
    end

    test "metrics/1 filters by component" do
      only = Metrics.metrics(only: [:plug, :mcp])
      assert only != []
      assert Enum.all?(only, &(Enum.at(&1.event_name, 1) in [:plug, :mcp]))

      except = Metrics.metrics(except: [:plug, :mcp])
      refute Enum.any?(except, &(Enum.at(&1.event_name, 1) in [:plug, :mcp]))
      assert length(only) + length(except) == length(Metrics.metrics())

      assert Metrics.metrics(only: [:plug], except: [:plug]) == []
    end

    test "metrics/1 rejects unknown components" do
      assert_raise NimbleOptions.ValidationError, fn -> Metrics.metrics(only: [:phoenix]) end
    end
  end
else
  defmodule X402.Telemetry.MetricsTest do
    use ExUnit.Case, async: true

    alias X402.Telemetry.Metrics

    test "metrics/0 and metrics/1 raise without :telemetry_metrics" do
      assert_raise ArgumentError, ~r/telemetry_metrics/, fn -> Metrics.metrics() end
      assert_raise ArgumentError, ~r/telemetry_metrics/, fn -> Metrics.metrics(only: [:plug]) end
    end
  end
end
