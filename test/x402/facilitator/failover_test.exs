defmodule X402.Facilitator.FailoverTest do
  use ExUnit.Case, async: true

  doctest X402.Facilitator.Failover

  alias X402.Facilitator.Error
  alias X402.Facilitator.Failover

  @endpoints [%{url: "https://a"}, %{url: "https://b"}, %{url: "https://c"}]

  describe "validate_fallbacks/1" do
    test "validates each endpoint and keeps order" do
      assert {:ok, [first, second]} =
               Failover.validate_fallbacks([
                 [url: "https://b", receive_timeout_ms: 10],
                 [url: "https://c", auth: nil]
               ])

      assert Keyword.fetch!(first, :url) == "https://b"
      assert Keyword.fetch!(second, :url) == "https://c"
    end

    test "rejects a fallback without a url" do
      assert {:error, message} = Failover.validate_fallbacks([[auth: nil]])
      assert message =~ ":url"
    end

    test "rejects a non-keyword entry" do
      assert {:error, "expected each fallback to be a keyword list"} =
               Failover.validate_fallbacks(["https://b"])
    end

    test "rejects a non-list value" do
      assert {:error, "expected a list of fallback endpoints"} =
               Failover.validate_fallbacks(%{url: "https://b"})
    end

    test "rejects an invalid auth" do
      assert {:error, message} = Failover.validate_fallbacks([[url: "https://b", auth: Enum]])
      assert message =~ "X402.Facilitator.Auth"
    end
  end

  describe "validate_policy/1" do
    test "applies defaults" do
      assert Failover.validate_policy([]) == {:ok, %{max_attempts: nil, cooldown_ms: 30_000}}
    end

    test "accepts an already validated policy" do
      policy = %{max_attempts: 2, cooldown_ms: 10}
      assert Failover.validate_policy(policy) == {:ok, policy}
    end

    test "rejects invalid values" do
      assert {:error, message} = Failover.validate_policy(max_attempts: 0)
      assert message =~ ":max_attempts"

      assert {:error, "expected a keyword list of failover options"} =
               Failover.validate_policy(:none)
    end
  end

  describe "order/4" do
    test "keeps configured order when nothing is tripped" do
      assert Failover.order(@endpoints, %{}, policy(), 0) == @endpoints
    end

    test "moves tripped endpoints last but keeps them as a last resort" do
      breaker = %{"https://b" => 100, "https://a" => 100}

      assert Failover.order(@endpoints, breaker, policy(), 50) |> Enum.map(& &1.url) ==
               ["https://c", "https://a", "https://b"]
    end

    test "max_attempts caps the candidates after ordering" do
      breaker = %{"https://a" => 100}

      assert Failover.order(@endpoints, breaker, policy(max_attempts: 2), 50)
             |> Enum.map(& &1.url) == ["https://b", "https://c"]
    end
  end

  describe "run/4" do
    test "a single endpoint runs once and never trips" do
      assert Failover.run(
               [%{url: "https://a"}],
               :verify,
               fn _endpoint -> {:ok, :done} end,
               &trip/1
             ) ==
               {:ok, :done}

      error = %Error{type: :transport_error, reason: :econnrefused}

      assert Failover.run(
               [%{url: "https://a"}],
               :verify,
               fn _endpoint -> {:error, error} end,
               &trip/1
             ) ==
               {:error, error}

      refute_received {:trip, _url}
    end

    test "returns the first success and skips the rest" do
      owner = self()

      request = fn endpoint ->
        send(owner, {:request, endpoint.url})
        {:ok, endpoint.url}
      end

      assert Failover.run(@endpoints, :verify, request, &trip/1) == {:ok, "https://a"}
      assert_received {:request, "https://a"}
      refute_received {:request, "https://b"}
      refute_received {:trip, _url}
    end

    test "fails over on eligible errors, tripping and emitting per hop" do
      handler = attach_failover_handler()
      owner = self()

      request = fn
        %{url: "https://a"} ->
          {:error, %Error{type: :http_error, status: 503}}

        %{url: "https://b"} ->
          {:error, %Error{type: :timeout}}

        %{url: "https://c"} = endpoint ->
          send(owner, {:request, endpoint.url})
          {:ok, :c}
      end

      assert Failover.run(@endpoints, :verify, request, &trip/1) == {:ok, :c}

      assert_received {:trip, "https://a"}
      assert_received {:trip, "https://b"}
      refute_received {:trip, "https://c"}

      assert_received {:failover,
                       %{
                         operation: :verify,
                         from: "https://a",
                         to: "https://b",
                         reason: :http_error,
                         status: 503
                       }}

      assert_received {:failover,
                       %{operation: :verify, from: "https://b", to: "https://c", reason: :timeout}}

      :telemetry.detach(handler)
    end

    test "stops at the first non-eligible error" do
      owner = self()

      request = fn
        %{url: "https://a"} ->
          {:error, %Error{type: :http_error, status: 400}}

        endpoint ->
          send(owner, {:request, endpoint.url})
          {:ok, :nope}
      end

      assert {:error, %Error{status: 400}} = Failover.run(@endpoints, :verify, request, &trip/1)
      refute_received {:request, _url}
      refute_received {:trip, _url}
    end

    test "returns the last endpoint's error and trips it too" do
      handler = attach_failover_handler()
      error = %Error{type: :transport_error, reason: %{reason: :econnrefused}}

      request = fn _endpoint -> {:error, error} end

      assert Failover.run(@endpoints, :settle, request, &trip/1) == {:error, error}

      for %{url: url} <- @endpoints, do: assert_received({:trip, ^url})

      assert_received {:failover, %{operation: :settle, from: "https://a", to: "https://b"}}
      assert_received {:failover, %{operation: :settle, from: "https://b", to: "https://c"}}
      refute_received {:failover, %{from: "https://c"}}

      :telemetry.detach(handler)
    end

    test "settle does not fail over on errors that may have been delivered" do
      owner = self()

      for error <- [
            %Error{type: :timeout, reason: :timeout},
            %Error{type: :http_error, status: 500},
            %Error{type: :transport_error, reason: %{reason: :closed}},
            %Error{type: :transport_error, reason: :econnreset}
          ] do
        request = fn
          %{url: "https://a"} ->
            {:error, error}

          endpoint ->
            send(owner, {:request, endpoint.url})
            {:ok, :nope}
        end

        assert Failover.run(@endpoints, :settle, request, &trip/1) == {:error, error}
        refute_received {:request, _url}
        refute_received {:trip, _url}
      end
    end

    test "settle fails over on provably undelivered requests" do
      for reason <- [
            :econnrefused,
            :nxdomain,
            :ehostunreach,
            :enetunreach,
            :ehostdown,
            {:tls_alert, {:unknown_ca, ~c"bad"}},
            {:options, {:cacertfile, []}},
            %{reason: :econnrefused},
            %{__struct__: Mint.TransportError, reason: :nxdomain}
          ] do
        assert Failover.failover?(:settle, %Error{type: :transport_error, reason: reason}),
               inspect(reason)
      end
    end
  end

  defp policy(overrides \\ []),
    do: Map.merge(%{max_attempts: nil, cooldown_ms: 100}, Map.new(overrides))

  defp trip(url), do: send(self(), {:trip, url})

  defp attach_failover_handler do
    owner = self()
    handler = "failover-test-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        [:x402, :facilitator, :failover],
        fn _event, %{count: 1}, metadata, _config -> send(owner, {:failover, metadata}) end,
        nil
      )

    handler
  end
end
