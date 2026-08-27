defmodule X402.Extensions.PaymentIdentifier.ETSCacheSecurityTest do
  use ExUnit.Case, async: false

  alias X402.Extensions.PaymentIdentifier.ETSCache

  test "enforces max_size limit" do
    max_size = 10
    cache = start_cache(max_size: max_size)

    # Fill the cache
    for i <- 1..max_size do
      assert :ok = ETSCache.put(cache, "payment-#{i}", :verified)
    end

    %{table: table} = :sys.get_state(cache)
    assert :ets.info(table, :size) == max_size

    # Add one more
    assert :ok = ETSCache.put(cache, "payment-#{max_size + 1}", :verified)

    # Size should still be max_size
    assert :ets.info(table, :size) == max_size
  end

  test "updating existing key does not evict another key when at max_size" do
    max_size = 10
    cache = start_cache(max_size: max_size)

    # Fill the cache
    for i <- 1..max_size do
      assert :ok = ETSCache.put(cache, "payment-#{i}", :verified)
    end

    %{table: table} = :sys.get_state(cache)
    assert :ets.info(table, :size) == max_size

    # Update an existing key
    assert :ok = ETSCache.put(cache, "payment-1", :verified)

    # Size should still be max_size
    assert :ets.info(table, :size) == max_size
    # Ensure "payment-1" is still there
    assert {:hit, :verified} = ETSCache.get(cache, "payment-1")
  end

  test "put_new refuses new claims at capacity instead of evicting live claims" do
    max_size = 5
    cache = start_cache(max_size: max_size)

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
    cache = start_cache(max_size: max_size, ttl_ms: 30)

    for i <- 1..max_size do
      assert :ok = ETSCache.put_new(cache, "claim-#{i}", :verified)
    end

    # Let the claims expire; the periodic cleanup has not run yet
    # (cleanup_interval_ms is 60s), so the purge inside put_new must free the
    # slots on its own.
    Process.sleep(60)

    assert :ok = ETSCache.put_new(cache, "fresh-claim", :verified)
  end

  defp start_cache(opts) do
    name = String.to_atom("ets_cache_security_#{System.unique_integer([:positive, :monotonic])}")
    options = Keyword.merge([name: name, cleanup_interval_ms: 60_000], opts)

    start_supervised!(%{
      id: {:ets_cache, System.unique_integer([:positive, :monotonic])},
      start: {ETSCache, :start_link, [options]}
    })
  end
end
