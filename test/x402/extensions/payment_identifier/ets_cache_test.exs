defmodule X402.Extensions.PaymentIdentifier.ETSCacheTest do
  use ExUnit.Case, async: false

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache

  test "conforms to the Cache behaviour, including put_new/3" do
    behaviours =
      ETSCache.module_info(:attributes)
      |> Keyword.get_values(:behaviour)
      |> List.flatten()

    assert Cache in behaviours
    assert X402.Behaviour.implements?(ETSCache, get: 2, put: 3, put_new: 3, delete: 2)
    assert :ok = Cache.validate_adapter({ETSCache, ETSCache})
  end

  test "put_new/3 lets exactly one of many concurrent claimants win" do
    cache = start_cache(ttl_ms: 60_000)

    results =
      1..50
      |> Task.async_stream(
        fn _index -> ETSCache.put_new(cache, "contested-payment", :verified) end,
        max_concurrency: 50,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == {:error, :already_exists})) == 49
  end

  test "put/3 and get/2 store and retrieve verified entries" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put(cache, "payment-1", :verified)
    assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
  end

  test "delete/2 removes entries" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put(cache, "payment-1", :verified)
    assert :ok = ETSCache.delete(cache, "payment-1")
    assert :miss = ETSCache.get(cache, "payment-1")
  end

  test "get/2 expires entries after ttl" do
    cache = start_cache(ttl_ms: 10)

    assert :ok = ETSCache.put(cache, "payment-1", :verified)
    Process.sleep(20)

    assert :miss = ETSCache.get(cache, "payment-1")
  end

  test "cleanup process removes expired entries periodically" do
    cache = start_cache(ttl_ms: 50, cleanup_interval_ms: 50)

    assert :ok = ETSCache.put(cache, "payment-1", :verified)

    %{table: table} = :sys.get_state(cache)
    assert :ets.info(table, :size) == 1

    assert :ok = wait_until(fn -> :ets.info(table, :size) == 0 end)
  end

  test "supports rejected values" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put(cache, "payment-1", {:rejected, :verification_failed})
    assert {:hit, {:rejected, :verification_failed}} = ETSCache.get(cache, "payment-1")
  end

  test "stores payment id fingerprint bindings" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put_new(cache, "pid:abc", {:bound, "fingerprint"})
    assert {:hit, {:bound, "fingerprint"}} = ETSCache.get(cache, "pid:abc")
    assert {:error, :already_exists} = ETSCache.put_new(cache, "pid:abc", {:bound, "other"})
    assert {:error, :invalid_cache_value} = ETSCache.put(cache, "pid:abc", {:bound, :atom})
  end

  test "stores sign-in-with-x nonce states" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put_new(cache, "siwx:issued:abc", {:siwx_nonce, :issued})
    assert {:hit, {:siwx_nonce, :issued}} = ETSCache.get(cache, "siwx:issued:abc")
    assert :ok = ETSCache.put_new(cache, "siwx:used:abc", {:siwx_nonce, :used})

    assert {:error, :already_exists} =
             ETSCache.put_new(cache, "siwx:used:abc", {:siwx_nonce, :used})

    assert {:error, :invalid_cache_value} =
             ETSCache.put(cache, "siwx:used:abc", {:siwx_nonce, :pending})
  end

  test "rejects invalid value and invalid payment identifiers" do
    cache = start_cache(ttl_ms: 1_000)

    assert {:error, :invalid_cache_value} = ETSCache.put(cache, "payment-1", :unknown)
    assert {:error, :invalid_payment_id} = ETSCache.put(cache, :invalid, :verified)
    assert {:error, :invalid_payment_id} = ETSCache.get(cache, :invalid)
    assert {:error, :invalid_payment_id} = ETSCache.delete(cache, :invalid)
  end

  test "start_link/1 validates options" do
    assert {:error, %NimbleOptions.ValidationError{}} =
             ETSCache.start_link(cleanup_interval_ms: 0)
  end

  test "child_spec/1 uses the configured name as id" do
    assert %{id: :custom_cache} = ETSCache.child_spec(name: :custom_cache)
  end

  test "unnamed caches keep independent claims for the same payment" do
    first = start_supervised!(%{ETSCache.child_spec(name: nil) | id: :first})
    second = start_supervised!(%{ETSCache.child_spec(name: nil) | id: :second})

    assert :ok = ETSCache.put_new(first, "payment-1", :verified)
    assert :miss = ETSCache.get(second, "payment-1")
    assert :ok = ETSCache.put_new(second, "payment-1", {:rejected, :verification_failed})
    assert {:hit, :verified} = ETSCache.get(first, "payment-1")
    assert :ok = ETSCache.delete(first, "payment-1")
    assert {:hit, {:rejected, :verification_failed}} = ETSCache.get(second, "payment-1")
  end

  test "put_new/3 inserts a new entry and returns :ok" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put_new(cache, "payment-1", :verified)
    assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
  end

  test "put_new/3 returns :already_exists for a duplicate live entry" do
    cache = start_cache(ttl_ms: 1_000)

    assert :ok = ETSCache.put_new(cache, "payment-1", :verified)
    assert {:error, :already_exists} = ETSCache.put_new(cache, "payment-1", :verified)
  end

  test "put_new/3 allows re-insert after the entry has expired" do
    # Expired entries must not block legitimate retries until the cleanup
    # timer fires. put_new should atomically clean up and re-insert.
    cache = start_cache(ttl_ms: 10, cleanup_interval_ms: 60_000)

    assert :ok = ETSCache.put_new(cache, "payment-1", :verified)
    Process.sleep(20)

    # Entry is expired but cleanup hasn't run — put_new must still succeed.
    assert :ok = ETSCache.put_new(cache, "payment-1", :verified)
    assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
  end

  test "get/2 with a named cache reads the ETS table directly" do
    name = String.to_atom("ets_cache_named_#{System.unique_integer([:positive, :monotonic])}")

    start_supervised!(%{
      id: {:ets_cache, System.unique_integer([:positive, :monotonic])},
      start: {ETSCache, :start_link, [[name: name, ttl_ms: 60_000]]}
    })

    assert :ok = ETSCache.put(name, "payment-1", :verified)

    # A registered atom name is also the named-table name — the lookup happens
    # in the calling process without a GenServer round trip.
    assert {:hit, :verified} = ETSCache.get(name, "payment-1")
    assert :miss = ETSCache.get(name, "payment-unknown")
  end

  test "get/2 with a named cache treats expired direct reads as misses" do
    name = String.to_atom("ets_cache_expired_#{System.unique_integer([:positive, :monotonic])}")

    start_supervised!(%{
      id: {:ets_cache, System.unique_integer([:positive, :monotonic])},
      start: {ETSCache, :start_link, [[name: name, ttl_ms: 10, cleanup_interval_ms: 60_000]]}
    })

    assert :ok = ETSCache.put(name, "payment-1", :verified)
    Process.sleep(20)

    assert :miss = ETSCache.get(name, "payment-1")
  end

  test "get/2 falls back to the server when the atom is not a named table" do
    # Started under a :global name, so the cache owns an unnamed table.
    global_name = {:global, {:ets_cache_global, System.unique_integer([:positive, :monotonic])}}

    pid =
      start_supervised!(%{
        id: {:ets_cache, System.unique_integer([:positive, :monotonic])},
        start: {ETSCache, :start_link, [[name: global_name, ttl_ms: 60_000]]}
      })

    alias_name =
      String.to_atom("ets_cache_alias_#{System.unique_integer([:positive, :monotonic])}")

    Process.register(pid, alias_name)

    assert :ok = ETSCache.put(alias_name, "payment-1", :verified)

    # :ets.lookup(alias_name, ...) raises ArgumentError (no such table), so
    # the read is served through the GenServer instead.
    assert {:hit, :verified} = ETSCache.get(alias_name, "payment-1")
  end

  test "put_new/3 rejects invalid values and payment identifiers" do
    cache = start_cache(ttl_ms: 1_000)

    assert {:error, :invalid_cache_value} = ETSCache.put_new(cache, "payment-1", :unknown)
    assert {:error, :invalid_payment_id} = ETSCache.put_new(cache, :invalid, :verified)
    assert :miss = ETSCache.get(cache, "payment-1")
  end

  test "put_new/3 refuses new entries at max_size without evicting live claims" do
    cache = start_cache(ttl_ms: 1_000, max_size: 2)

    assert :ok = ETSCache.put_new(cache, "payment-1", :verified)
    assert :ok = ETSCache.put_new(cache, "payment-2", :verified)

    # A live claim is another payment's replay lock — never evict it to admit
    # a new claim; refuse instead (the gate fails closed on this error).
    assert {:error, :cache_full} = ETSCache.put_new(cache, "payment-3", :verified)

    %{table: table} = :sys.get_state(cache)
    assert :ets.info(table, :size) == 2
    assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
    assert {:hit, :verified} = ETSCache.get(cache, "payment-2")
  end

  describe "max_size and capacity" do
    test "enforces max_size limit" do
      max_size = 10
      cache = start_cache(max_size: max_size, cleanup_interval_ms: 60_000)

      for i <- 1..max_size do
        assert :ok = ETSCache.put(cache, "payment-#{i}", :verified)
      end

      %{table: table} = :sys.get_state(cache)
      assert :ets.info(table, :size) == max_size

      assert :ok = ETSCache.put(cache, "payment-#{max_size + 1}", :verified)

      assert :ets.info(table, :size) == max_size
    end

    test "updating existing key does not evict another key when at max_size" do
      max_size = 10
      cache = start_cache(max_size: max_size, cleanup_interval_ms: 60_000)

      for i <- 1..max_size do
        assert :ok = ETSCache.put(cache, "payment-#{i}", :verified)
      end

      %{table: table} = :sys.get_state(cache)
      assert :ets.info(table, :size) == max_size

      assert :ok = ETSCache.put(cache, "payment-1", :verified)

      assert :ets.info(table, :size) == max_size
      assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
    end

    test "put_new refuses new claims at capacity instead of evicting live claims" do
      max_size = 5
      cache = start_cache(max_size: max_size, cleanup_interval_ms: 60_000)

      # Fill the cache with live claims (an attacker's junk claims, or simply a
      # busy gate) up to capacity.
      for i <- 1..max_size do
        assert :ok = ETSCache.put_new(cache, "claim-#{i}", :verified)
      end

      # A new claim must be refused — never admitted by dropping another
      # payment's live replay lock (that would reopen double-delivery under
      # claim-before-verify junk floods).
      assert {:error, :cache_full} = ETSCache.put_new(cache, "victim-claim", :verified)

      # Every original claim survives untouched.
      for i <- 1..max_size do
        assert {:hit, :verified} = ETSCache.get(cache, "claim-#{i}")
      end

      # Re-claiming an existing id still reports the duplicate, not capacity.
      assert {:error, :already_exists} = ETSCache.put_new(cache, "claim-1", :verified)

      # Releasing a claim frees a slot for the next claim.
      assert :ok = ETSCache.delete(cache, "claim-1")
      assert :ok = ETSCache.put_new(cache, "victim-claim", :verified)
    end

    test "put_new at capacity purges expired entries before refusing" do
      max_size = 3
      cache = start_cache(max_size: max_size, ttl_ms: 30, cleanup_interval_ms: 60_000)

      for i <- 1..max_size do
        assert :ok = ETSCache.put_new(cache, "claim-#{i}", :verified)
      end

      # Let the claims expire; the periodic cleanup has not run yet
      # (cleanup_interval_ms is 60s), so the purge inside put_new must free the
      # slots on its own.
      Process.sleep(60)

      assert :ok = ETSCache.put_new(cache, "fresh-claim", :verified)
    end
  end

  defp start_cache(opts) do
    name = String.to_atom("ets_cache_#{System.unique_integer([:positive, :monotonic])}")
    options = Keyword.merge([name: name, cleanup_interval_ms: 50], opts)

    start_supervised!(%{
      id: {:ets_cache, System.unique_integer([:positive, :monotonic])},
      start: {ETSCache, :start_link, [options]}
    })
  end

  defp wait_until(fun, attempts \\ 20)

  defp wait_until(fun, attempts) when attempts > 0 do
    case fun.() do
      true ->
        :ok

      false ->
        Process.sleep(10)
        wait_until(fun, attempts - 1)
    end
  end

  defp wait_until(_fun, 0), do: {:error, :timeout}
end
