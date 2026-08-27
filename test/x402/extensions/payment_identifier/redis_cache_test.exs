defmodule X402.Extensions.PaymentIdentifier.RedisCacheTest do
  use ExUnit.Case, async: true

  import Mox

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.RedisCache
  alias X402.RedisCommandMock

  setup :verify_on_exit!

  @conn :redis_conn
  @default_key "x402:payment_identifier:payment-1"

  defp mock_cache(opts \\ []) do
    {:ok, cache} =
      RedisCache.new(Keyword.merge([conn: @conn, command: RedisCommandMock], opts))

    cache
  end

  defp rejected_encoding(reason) do
    "rejected:" <> Base.encode64(:erlang.term_to_binary(reason))
  end

  describe "behaviour conformance" do
    test "implements the Cache behaviour, including put_new/3" do
      behaviours =
        RedisCache.module_info(:attributes)
        |> Keyword.get_values(:behaviour)
        |> List.flatten()

      assert Cache in behaviours
      assert X402.Behaviour.implements?(RedisCache, get: 2, put: 3, put_new: 3, delete: 2)
      assert :ok = Cache.validate_adapter({RedisCache, mock_cache()})
    end
  end

  describe "new/1" do
    test "defaults to Redix, a 1-hour TTL, and the x402 namespace" do
      assert {:ok, cache} = RedisCache.new(conn: MyApp.Redis)

      assert cache.conn == MyApp.Redis
      assert cache.command == Redix
      assert cache.ttl_ms == :timer.hours(1)
      assert cache.namespace == "x402:payment_identifier:"
    end

    test "accepts custom TTL, namespace, and command module" do
      assert {:ok, cache} =
               RedisCache.new(
                 conn: @conn,
                 ttl_ms: 5_000,
                 namespace: "myapp:",
                 command: RedisCommandMock
               )

      assert %RedisCache{ttl_ms: 5_000, namespace: "myapp:", command: RedisCommandMock} = cache
    end

    test "raises on missing or invalid options (programmer error)" do
      assert_raise NimbleOptions.ValidationError, fn -> RedisCache.new([]) end
      assert_raise NimbleOptions.ValidationError, fn -> RedisCache.new(conn: @conn, ttl_ms: 0) end

      assert_raise NimbleOptions.ValidationError, ~r/command\/2/, fn ->
        RedisCache.new(conn: @conn, command: NotACommandModule)
      end
    end
  end

  describe "put_new/3 command construction and response mapping" do
    test "issues a single SET NX PX and maps OK to :ok" do
      expect(RedisCommandMock, :command, fn @conn, command ->
        assert command == ["SET", @default_key, "verified", "NX", "PX", "3600000"]
        {:ok, "OK"}
      end)

      assert :ok = RedisCache.put_new(mock_cache(), "payment-1", :verified)
    end

    test "maps the nil reply of a lost NX race to {:error, :already_exists}" do
      expect(RedisCommandMock, :command, fn @conn, ["SET", _key, _value, "NX", "PX", _ttl] ->
        {:ok, nil}
      end)

      assert {:error, :already_exists} = RedisCache.put_new(mock_cache(), "payment-1", :verified)
    end

    test "honors custom namespace and TTL" do
      expect(RedisCommandMock, :command, fn @conn, command ->
        assert command == ["SET", "myapp:payment-1", "verified", "NX", "PX", "5000"]
        {:ok, "OK"}
      end)

      cache = mock_cache(ttl_ms: 5_000, namespace: "myapp:")
      assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    end

    test "encodes rejected values with their reason term" do
      encoded = rejected_encoding({:verification_failed, :insufficient_funds})

      expect(RedisCommandMock, :command, fn @conn, ["SET", _key, ^encoded, "NX", "PX", _ttl] ->
        {:ok, "OK"}
      end)

      assert :ok =
               RedisCache.put_new(
                 mock_cache(),
                 "payment-1",
                 {:rejected, {:verification_failed, :insufficient_funds}}
               )
    end

    test "passes connection errors through (the gate fails closed on them)" do
      error = %Redix.ConnectionError{reason: :closed}
      expect(RedisCommandMock, :command, fn @conn, _command -> {:error, error} end)

      assert {:error, ^error} = RedisCache.put_new(mock_cache(), "payment-1", :verified)
    end

    test "reports unexpected replies without inventing success" do
      expect(RedisCommandMock, :command, fn @conn, _command -> {:ok, 42} end)

      assert {:error, {:unexpected_response, 42}} =
               RedisCache.put_new(mock_cache(), "payment-1", :verified)
    end

    test "rejects invalid values and payment identifiers without issuing commands" do
      assert {:error, :invalid_cache_value} =
               RedisCache.put_new(mock_cache(), "payment-1", :unknown)

      assert {:error, :invalid_payment_id} = RedisCache.put_new(mock_cache(), :bad, :verified)
    end
  end

  describe "put/3" do
    test "issues SET PX without NX" do
      expect(RedisCommandMock, :command, fn @conn, command ->
        assert command == ["SET", @default_key, "verified", "PX", "3600000"]
        {:ok, "OK"}
      end)

      assert :ok = RedisCache.put(mock_cache(), "payment-1", :verified)
    end

    test "passes errors through and rejects invalid input" do
      error = %Redix.Error{message: "OOM command not allowed"}
      expect(RedisCommandMock, :command, fn @conn, _command -> {:error, error} end)

      assert {:error, ^error} = RedisCache.put(mock_cache(), "payment-1", :verified)
      assert {:error, :invalid_cache_value} = RedisCache.put(mock_cache(), "payment-1", "yes")
      assert {:error, :invalid_payment_id} = RedisCache.put(mock_cache(), 1, :verified)
    end
  end

  describe "get/2" do
    test "maps nil to :miss and decodes stored values" do
      RedisCommandMock
      |> expect(:command, fn @conn, ["GET", @default_key] -> {:ok, nil} end)
      |> expect(:command, fn @conn, ["GET", @default_key] -> {:ok, "verified"} end)
      |> expect(:command, fn @conn, ["GET", @default_key] ->
        {:ok, rejected_encoding({:rejected_by, :facilitator})}
      end)

      cache = mock_cache()
      assert :miss = RedisCache.get(cache, "payment-1")
      assert {:hit, :verified} = RedisCache.get(cache, "payment-1")

      assert {:hit, {:rejected, {:rejected_by, :facilitator}}} =
               RedisCache.get(cache, "payment-1")
    end

    test "fails closed on entries it cannot decode" do
      # Unknown encoding prefix.
      expect(RedisCommandMock, :command, fn @conn, _command -> {:ok, "tampered"} end)

      assert {:error, {:invalid_cache_entry, "tampered"}} =
               RedisCache.get(mock_cache(), "payment-1")

      # Rejected payload that is not Base64.
      expect(RedisCommandMock, :command, fn @conn, _command -> {:ok, "rejected:%%%"} end)

      assert {:error, {:invalid_cache_entry, "rejected:%%%"}} =
               RedisCache.get(mock_cache(), "payment-1")

      # Rejected payload whose term would allocate a new atom (:safe decode).
      atom_name = "x402_test_unknown_atom_zz"
      unknown_atom_etf = <<131, 119, byte_size(atom_name), atom_name::binary>>
      raw = "rejected:" <> Base.encode64(unknown_atom_etf)
      expect(RedisCommandMock, :command, fn @conn, _command -> {:ok, raw} end)

      assert {:error, {:invalid_cache_entry, ^raw}} = RedisCache.get(mock_cache(), "payment-1")
    end

    test "passes errors through and reports unexpected replies" do
      error = %Redix.ConnectionError{reason: :timeout}

      RedisCommandMock
      |> expect(:command, fn @conn, _command -> {:error, error} end)
      |> expect(:command, fn @conn, _command -> {:ok, 5} end)

      cache = mock_cache()
      assert {:error, ^error} = RedisCache.get(cache, "payment-1")
      assert {:error, {:unexpected_response, 5}} = RedisCache.get(cache, "payment-1")
      assert {:error, :invalid_payment_id} = RedisCache.get(cache, nil)
    end
  end

  describe "delete/2" do
    test "issues DEL and treats any integer reply as released" do
      RedisCommandMock
      |> expect(:command, fn @conn, ["DEL", @default_key] -> {:ok, 1} end)
      |> expect(:command, fn @conn, ["DEL", @default_key] -> {:ok, 0} end)

      cache = mock_cache()
      assert :ok = RedisCache.delete(cache, "payment-1")
      assert :ok = RedisCache.delete(cache, "payment-1")
    end

    test "passes errors through and rejects invalid identifiers" do
      error = %Redix.ConnectionError{reason: :closed}
      expect(RedisCommandMock, :command, fn @conn, _command -> {:error, error} end)

      assert {:error, ^error} = RedisCache.delete(mock_cache(), "payment-1")
      assert {:error, :invalid_payment_id} = RedisCache.delete(mock_cache(), %{})
    end
  end

  describe "contract conformance (in-memory Redis semantics)" do
    # A fake command layer with real SET NX PX semantics: atomicity comes
    # from serializing through the Agent, expiry from monotonic timestamps —
    # mirroring the ETSCache behaviour tests without a live server.
    defmodule FakeRedis do
      @behaviour X402.Extensions.PaymentIdentifier.RedisCache.Command

      def start_link do
        Agent.start_link(fn -> %{} end)
      end

      @impl true
      def command(agent, ["SET", key, value, "NX", "PX", ttl]) do
        Agent.get_and_update(agent, fn state ->
          case live_value(state, key) do
            nil -> {{:ok, "OK"}, put_entry(state, key, value, ttl)}
            _live -> {{:ok, nil}, state}
          end
        end)
      end

      def command(agent, ["SET", key, value, "PX", ttl]) do
        Agent.get_and_update(agent, fn state ->
          {{:ok, "OK"}, put_entry(state, key, value, ttl)}
        end)
      end

      def command(agent, ["GET", key]) do
        Agent.get(agent, fn state -> {:ok, live_value(state, key)} end)
      end

      def command(agent, ["DEL", key]) do
        Agent.get_and_update(agent, fn state ->
          {{:ok, if(Map.has_key?(state, key), do: 1, else: 0)}, Map.delete(state, key)}
        end)
      end

      defp put_entry(state, key, value, ttl) do
        expires_at = now_ms() + String.to_integer(ttl)
        Map.put(state, key, {value, expires_at})
      end

      defp live_value(state, key) do
        case Map.get(state, key) do
          {value, expires_at} -> if expires_at > now_ms(), do: value
          nil -> nil
        end
      end

      defp now_ms, do: System.monotonic_time(:millisecond)
    end

    defp fake_cache(opts \\ []) do
      {:ok, agent} = FakeRedis.start_link()

      {:ok, cache} =
        RedisCache.new(Keyword.merge([conn: agent, command: FakeRedis], opts))

      cache
    end

    test "put_new/3 lets exactly one of many concurrent claimants win" do
      cache = fake_cache()

      results =
        1..50
        |> Task.async_stream(
          fn _index -> RedisCache.put_new(cache, "contested-payment", :verified) end,
          max_concurrency: 50,
          ordered: false
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &(&1 == :ok)) == 1
      assert Enum.count(results, &(&1 == {:error, :already_exists})) == 49
    end

    test "put_new/3 rejects a live duplicate and delete/2 releases the claim" do
      cache = fake_cache()

      assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
      assert {:error, :already_exists} = RedisCache.put_new(cache, "payment-1", :verified)

      assert :ok = RedisCache.delete(cache, "payment-1")
      assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    end

    test "put_new/3 allows re-claim after the PX TTL has expired" do
      cache = fake_cache(ttl_ms: 20)

      assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
      Process.sleep(40)

      assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    end

    test "get/2 returns stored values until expiry, then :miss" do
      cache = fake_cache(ttl_ms: 30)

      assert :ok = RedisCache.put(cache, "payment-1", {:rejected, :verification_failed})
      assert {:hit, {:rejected, :verification_failed}} = RedisCache.get(cache, "payment-1")

      Process.sleep(50)
      assert :miss = RedisCache.get(cache, "payment-1")
    end

    test "put/3 overwrites and resets the TTL of an existing entry" do
      cache = fake_cache(ttl_ms: 60)

      assert :ok = RedisCache.put(cache, "payment-1", :verified)
      Process.sleep(40)
      assert :ok = RedisCache.put(cache, "payment-1", :verified)
      Process.sleep(40)

      # 80ms after the first write, but only 40ms after the reset.
      assert {:hit, :verified} = RedisCache.get(cache, "payment-1")
    end
  end
end
