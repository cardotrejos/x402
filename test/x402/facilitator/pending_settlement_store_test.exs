defmodule X402.Facilitator.PendingSettlementStoreTest do
  use ExUnit.Case, async: true

  alias X402.Facilitator.PendingSettlementStore
  alias X402.Facilitator.PendingSettlementStore.ETS, as: ETSStore

  doctest PendingSettlementStore

  defmodule AgentStore do
    @behaviour X402.Facilitator.PendingSettlementStore

    @impl true
    def get(agent, key) do
      case Agent.get(agent, &Map.fetch(&1, key)) do
        {:ok, entry} -> {:hit, entry}
        :error -> :miss
      end
    end

    @impl true
    def put(agent, key, entry), do: Agent.update(agent, &Map.put(&1, key, entry))

    @impl true
    def delete(agent, key), do: Agent.update(agent, &Map.delete(&1, key))
  end

  defmodule NotAStore do
    def get(_store, _key), do: :miss
  end

  defp entry do
    %{
      transaction: "0x" <> String.duplicate("ab", 32),
      provenance: :node_acknowledged,
      raw_transaction: nil
    }
  end

  describe "adapter dispatch" do
    setup do
      agent = start_supervised!({Agent, fn -> %{} end})
      %{adapter: {AgentStore, agent}}
    end

    test "get/2 dispatches through the adapter module", %{adapter: adapter} do
      assert PendingSettlementStore.get(adapter, "key") == :miss

      assert PendingSettlementStore.put(adapter, "key", entry()) == :ok
      assert PendingSettlementStore.get(adapter, "key") == {:hit, entry()}
    end

    test "delete/2 dispatches through the adapter module", %{adapter: adapter} do
      assert PendingSettlementStore.put(adapter, "key", entry()) == :ok
      assert PendingSettlementStore.delete(adapter, "key") == :ok
      assert PendingSettlementStore.get(adapter, "key") == :miss
    end
  end

  describe "validate_adapter/1" do
    test "accepts adapters whose module implements the behaviour" do
      assert PendingSettlementStore.validate_adapter({AgentStore, :store}) ==
               {:ok, {AgentStore, :store}}

      assert PendingSettlementStore.validate_adapter({ETSStore, MyStore}) ==
               {:ok, {ETSStore, MyStore}}
    end

    test "rejects modules missing callbacks" do
      assert {:error, message} = PendingSettlementStore.validate_adapter({NotAStore, :store})
      assert message =~ "PendingSettlementStore"
    end

    test "rejects non-tuples" do
      assert {:error, _message} = PendingSettlementStore.validate_adapter(:store)
      assert {:error, _message} = PendingSettlementStore.validate_adapter("store")
    end
  end
end
