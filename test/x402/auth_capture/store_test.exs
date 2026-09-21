defmodule X402.AuthCapture.StoreTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture.Store

  alias X402.AuthCapture.Store

  defmodule Adapter do
    @moduledoc false
    @behaviour Store

    @impl Store
    def fetch(:raise, _key), do: raise("not exposed")
    def fetch(:throw, _key), do: throw(:not_exposed)
    def fetch(:exit, _key), do: exit(:not_exposed)
    def fetch(reply, _key), do: reply

    @impl Store
    def transact_many(reply, _keys, _mutation), do: fetch(reply, :key)
  end

  test "validates callbacks rather than promising adapter durability" do
    assert Store.validate({Adapter, :context}) == {:ok, {Adapter, :context}}
    assert {:error, _} = Store.validate({String, :context})
    assert {:error, _} = Store.validate({:nonexistent_store_adapter, :context})
  end

  test "only an explicit nil read is absence" do
    assert Store.fetch({Adapter, {:ok, nil}}, :key) == {:ok, nil}
    assert Store.fetch({Adapter, {:ok, %{value: 1}}}, :key) == {:ok, %{value: 1}}
    assert Store.fetch({Adapter, {:error, :timeout}}, :key) == {:error, :timeout}
    assert Store.fetch({Adapter, {:ok, false}}, :key) == {:error, :invalid_store_response}
    assert Store.fetch({Adapter, :miss}, :key) == {:error, :invalid_store_response}
  end

  test "adapter exceptions, throws and exits do not expose their content" do
    for failure <- [:raise, :throw, :exit] do
      assert Store.fetch({Adapter, failure}, :key) == {:error, :store_unavailable}
      assert Store.transact({Adapter, failure}, :key, & &1) == {:error, :store_unavailable}
    end
  end

  test "transaction failures remain ambiguous, never success" do
    assert Store.transact({Adapter, {:ok, :reply}}, :key, & &1) == {:ok, :reply}
    assert Store.transact({Adapter, {:error, :timeout}}, :key, & &1) == {:error, :timeout}
    assert Store.transact({Adapter, :invalid}, :key, & &1) == {:error, :invalid_store_response}
  end
end
