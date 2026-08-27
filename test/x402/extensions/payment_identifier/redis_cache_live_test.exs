defmodule X402.Extensions.PaymentIdentifier.RedisCacheLiveTest do
  use ExUnit.Case, async: false

  @moduletag :redis

  @moduledoc """
  Live conformance tests for the Redis cache adapter against a real server.

  Excluded from the default run (`ExUnit.start(exclude: [:smoke, :redis])`,
  same pattern as the `:smoke` facilitator tests). Run them with a Redis
  server available:

      REDIS_URL=redis://localhost:6379 mix test --only redis

  `REDIS_URL` defaults to `redis://localhost:6379`. Every test uses a unique
  key namespace and short TTLs, so the suite leaves no lasting state behind.
  """

  alias X402.Extensions.PaymentIdentifier.RedisCache

  defp redis_url, do: System.get_env("REDIS_URL", "redis://localhost:6379")

  defp start_cache(opts) do
    conn = start_supervised!({Redix, redis_url()})
    namespace = "x402:test:#{System.unique_integer([:positive, :monotonic])}:"

    {:ok, cache} = RedisCache.new(Keyword.merge([conn: conn, namespace: namespace], opts))
    cache
  end

  test "put_new/3 claims once across concurrent claimants (SET NX PX)" do
    cache = start_cache(ttl_ms: 60_000)

    results =
      1..20
      |> Task.async_stream(
        fn _index -> RedisCache.put_new(cache, "contested-payment", :verified) end,
        max_concurrency: 20,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == {:error, :already_exists})) == 19

    assert :ok = RedisCache.delete(cache, "contested-payment")
  end

  test "put_new/3 rejects a live duplicate; delete/2 releases the claim" do
    cache = start_cache(ttl_ms: 60_000)

    assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    assert {:error, :already_exists} = RedisCache.put_new(cache, "payment-1", :verified)

    assert :ok = RedisCache.delete(cache, "payment-1")
    assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    assert :ok = RedisCache.delete(cache, "payment-1")
  end

  test "an expired claim does not block a new one (server-side PX expiry)" do
    cache = start_cache(ttl_ms: 100)

    assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    assert {:error, :already_exists} = RedisCache.put_new(cache, "payment-1", :verified)

    Process.sleep(200)

    assert :miss = RedisCache.get(cache, "payment-1")
    assert :ok = RedisCache.put_new(cache, "payment-1", :verified)
    assert :ok = RedisCache.delete(cache, "payment-1")
  end

  test "get/2 and put/3 round-trip verified and rejected values" do
    cache = start_cache(ttl_ms: 60_000)

    assert :miss = RedisCache.get(cache, "payment-1")

    assert :ok = RedisCache.put(cache, "payment-1", :verified)
    assert {:hit, :verified} = RedisCache.get(cache, "payment-1")

    reason = {:verification_failed, %{"invalidReason" => "expired"}}
    assert :ok = RedisCache.put(cache, "payment-1", {:rejected, reason})
    assert {:hit, {:rejected, ^reason}} = RedisCache.get(cache, "payment-1")

    assert :ok = RedisCache.delete(cache, "payment-1")
    assert :miss = RedisCache.get(cache, "payment-1")
  end
end
