defmodule X402.Extensions.PaymentIdentifier.CacheTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache

  defmodule ValidCache do
    @moduledoc false
    @behaviour Cache

    @impl Cache
    def get(owner, payment_id) do
      send(owner, {:cache_get, payment_id})
      :miss
    end

    @impl Cache
    def put(owner, payment_id, value) do
      send(owner, {:cache_put, payment_id, value})
      :ok
    end

    @impl Cache
    def put_new(owner, payment_id, value) do
      send(owner, {:cache_put_new, payment_id, value})
      :ok
    end

    @impl Cache
    def delete(owner, payment_id) do
      send(owner, {:cache_delete, payment_id})
      :ok
    end
  end

  defmodule InvalidCache do
    @moduledoc false

    def get(_cache, _payment_id), do: :miss
  end

  defmodule LegacyCache do
    @moduledoc false
    # Implements the pre-0.6.0 callback set without put_new/3 — no longer a
    # complete adapter, because the gate's replay claim goes through put_new.

    def get(_cache, _payment_id), do: :miss
    def put(_cache, _payment_id, _value), do: :ok
    def delete(_cache, _payment_id), do: :ok
  end

  test "validate_adapter/1 accepts behaviour implementations" do
    assert :ok = Cache.validate_adapter({ValidCache, self()})
    assert :ok = Cache.validate_adapter({ETSCache, self()})
  end

  test "validate_adapter/1 rejects invalid adapter values" do
    assert {:error, _message} = Cache.validate_adapter({InvalidCache, self()})
    assert {:error, _message} = Cache.validate_adapter(:invalid)
  end

  test "validate_adapter/1 rejects adapters without put_new/3" do
    assert {:error, message} = Cache.validate_adapter({LegacyCache, self()})
    assert message =~ "put_new/3"
  end

  test "validate_optional_adapter/1 allows nil and valid adapters" do
    assert :ok = Cache.validate_optional_adapter(nil)
    assert :ok = Cache.validate_optional_adapter({ValidCache, self()})
  end

  test "get/2, put/3, put_new/3, and delete/2 dispatch to adapter module" do
    adapter = {ValidCache, self()}

    assert :miss = Cache.get(adapter, "payment-1")
    assert_receive {:cache_get, "payment-1"}

    assert :ok = Cache.put(adapter, "payment-1", :verified)
    assert_receive {:cache_put, "payment-1", :verified}

    assert :ok = Cache.put_new(adapter, "payment-1", :verified)
    assert_receive {:cache_put_new, "payment-1", :verified}

    assert :ok = Cache.delete(adapter, "payment-1")
    assert_receive {:cache_delete, "payment-1"}
  end

  test "returns invalid adapter errors for malformed adapter tuples" do
    assert {:error, :invalid_adapter} = Cache.get(:invalid, "payment-1")
    assert {:error, :invalid_adapter} = Cache.put(:invalid, "payment-1", :verified)
    assert {:error, :invalid_adapter} = Cache.put_new(:invalid, "payment-1", :verified)
    assert {:error, :invalid_adapter} = Cache.delete(:invalid, "payment-1")
  end
end
