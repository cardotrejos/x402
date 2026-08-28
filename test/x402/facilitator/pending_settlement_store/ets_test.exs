defmodule X402.Facilitator.PendingSettlementStore.ETSTest do
  use ExUnit.Case, async: true

  alias X402.Facilitator.PendingSettlementStore.ETS, as: ETSStore

  doctest ETSStore

  defp entry(overrides \\ []) do
    Map.merge(
      %{
        transaction: "0x" <> String.duplicate("ab", 32),
        provenance: :node_acknowledged,
        raw_transaction: nil
      },
      Map.new(overrides)
    )
  end

  defp start_store(opts \\ []) do
    name = Module.concat(__MODULE__, "Store#{System.unique_integer([:positive])}")
    start_supervised!({ETSStore, Keyword.merge([name: name], opts)})
    name
  end

  describe "start_link/1" do
    test "validates options" do
      assert {:error, %NimbleOptions.ValidationError{}} = ETSStore.start_link(ttl_ms: -1)
    end

    test "supports unnamed (pid-addressed) stores" do
      assert {:ok, pid} = ETSStore.start_link(name: nil)
      assert ETSStore.get(pid, "key") == :miss
      assert ETSStore.put(pid, "key", entry()) == :ok
      assert ETSStore.get(pid, "key") == {:hit, entry()}
      GenServer.stop(pid)
    end
  end

  describe "put/3 and get/2" do
    test "round-trips entries" do
      store = start_store()

      assert ETSStore.get(store, "key") == :miss
      assert ETSStore.put(store, "key", entry()) == :ok
      assert ETSStore.get(store, "key") == {:hit, entry()}
    end

    test "put overwrites an existing entry" do
      store = start_store()
      replacement = entry(provenance: :local_hash, raw_transaction: <<1, 2, 3>>)

      assert ETSStore.put(store, "key", entry()) == :ok
      assert ETSStore.put(store, "key", replacement) == :ok
      assert ETSStore.get(store, "key") == {:hit, replacement}
    end

    test "rejects malformed entries" do
      store = start_store()

      assert ETSStore.put(store, "key", %{transaction: "0xab"}) == {:error, :invalid_entry}

      assert ETSStore.put(store, "key", entry(provenance: :other)) ==
               {:error, :invalid_entry}

      assert ETSStore.put(store, "key", :not_a_map) == {:error, :invalid_entry}
    end

    test "rejects non-binary keys" do
      store = start_store()

      assert ETSStore.put(store, :key, entry()) == {:error, :invalid_key}
      assert ETSStore.get(store, :key) == {:error, :invalid_key}
      assert ETSStore.delete(store, :key) == {:error, :invalid_key}
    end

    test "expired entries read as :miss" do
      store = start_store(ttl_ms: 0)

      assert ETSStore.put(store, "key", entry()) == :ok
      assert ETSStore.get(store, "key") == :miss
    end

    test "named tables serve reads without the GenServer" do
      store = start_store()
      assert ETSStore.put(store, "key", entry()) == :ok

      # Suspend the server; the read must still succeed via the ETS table.
      :sys.suspend(store)
      assert ETSStore.get(store, "key") == {:hit, entry()}
      :sys.resume(store)
    end
  end

  describe "delete/2" do
    test "removes entries and tolerates absent keys" do
      store = start_store()

      assert ETSStore.put(store, "key", entry()) == :ok
      assert ETSStore.delete(store, "key") == :ok
      assert ETSStore.get(store, "key") == :miss
      assert ETSStore.delete(store, "key") == :ok
    end
  end

  describe "capacity" do
    test "fails closed at max_size instead of evicting live entries" do
      store = start_store(max_size: 2)

      assert ETSStore.put(store, "one", entry()) == :ok
      assert ETSStore.put(store, "two", entry()) == :ok
      assert ETSStore.put(store, "three", entry()) == {:error, :store_full}

      # Existing keys can still be overwritten at capacity.
      assert ETSStore.put(store, "one", entry(provenance: :local_hash, raw_transaction: <<1>>)) ==
               :ok
    end

    test "purges expired entries to admit new ones" do
      store = start_store(max_size: 1, ttl_ms: 0)

      assert ETSStore.put(store, "one", entry()) == :ok
      assert ETSStore.put(store, "two", entry()) == :ok
    end
  end

  describe "cleanup loop" do
    test "removes expired entries on the cleanup tick" do
      store = start_store(ttl_ms: 0, cleanup_interval_ms: 10)

      assert ETSStore.put(store, "key", entry()) == :ok

      Process.sleep(30)
      # The entry is gone from the table itself (not just filtered on read).
      assert :ets.lookup(store, "key") == []
    end
  end
end
