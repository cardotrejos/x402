defmodule X402.Extensions.PaymentIdentifier.ETSCacheTest do
  use ExUnit.Case, async: false

  alias X402.Extensions.PaymentIdentifier.ETSCache

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
    cache = start_cache(ttl_ms: 10, cleanup_interval_ms: 10)

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
