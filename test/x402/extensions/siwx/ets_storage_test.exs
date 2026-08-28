defmodule X402.Extensions.SIWX.ETSStorageTest do
  use ExUnit.Case, async: false

  alias X402.Extensions.SIWX.ETSStorage

  describe "start_link/1" do
    test "validates options" do
      assert {:error, %NimbleOptions.ValidationError{}} =
               ETSStorage.start_link(cleanup_interval_ms: 0)
    end

    test "creates a child spec" do
      name = unique_atom("storage")
      table = unique_atom("table")

      spec = ETSStorage.child_spec(name: name, table: table)

      assert spec.id == name
      assert spec.type == :worker
      assert spec.restart == :permanent
    end
  end

  describe "get/put/delete" do
    test "stores and retrieves access records" do
      {storage, _table} = start_storage()

      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x1"}, 5_000)

      assert {:ok, record} = ETSStorage.get(storage, "0xabc", "/paid/resource")
      assert record.payment_proof == %{"tx" => "0x1"}
      assert is_integer(record.expires_at_ms)
    end

    test "returns not_found for missing records" do
      {storage, _table} = start_storage()

      assert ETSStorage.get(storage, "0xmissing", "/paid/resource") == {:error, :not_found}
    end

    test "deletes records" do
      {storage, _table} = start_storage()

      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x1"}, 5_000)
      assert :ok = ETSStorage.delete(storage, "0xabc", "/paid/resource")
      assert ETSStorage.get(storage, "0xabc", "/paid/resource") == {:error, :not_found}
    end

    test "returns invalid_arguments for malformed put inputs" do
      {storage, _table} = start_storage()

      assert ETSStorage.put(storage, :bad, "/paid/resource", %{}, 1_000) ==
               {:error, :invalid_arguments}

      assert ETSStorage.put(storage, "0xabc", "/paid/resource", %{}, -1) ==
               {:error, :invalid_arguments}
    end

    test "returns not_found for malformed get inputs" do
      {storage, _table} = start_storage()

      assert ETSStorage.get(storage, :bad, "/paid/resource") == {:error, :not_found}
      assert ETSStorage.get(storage, "0xabc", nil) == {:error, :not_found}
    end

    test "returns :ok for malformed delete inputs" do
      {storage, _table} = start_storage()

      assert ETSStorage.delete(storage, :bad, "/paid/resource") == :ok
      assert ETSStorage.delete(storage, "0xabc", nil) == :ok
    end

    test "get/2, put/4, and delete/2 use the default storage server" do
      # Register the default name with a test-specific table so the default
      # delegates are exercised without claiming the default table name.
      start_supervised!(
        {ETSStorage, name: X402.Extensions.SIWX.ETSStorage, table: unique_atom("default_table")}
      )

      assert :ok = ETSStorage.put("0xabc", "/paid/resource", %{"tx" => "0x1"}, 5_000)

      assert {:ok, record} = ETSStorage.get("0xabc", "/paid/resource")
      assert record.payment_proof == %{"tx" => "0x1"}

      assert :ok = ETSStorage.delete("0xabc", "/paid/resource")
      assert ETSStorage.get("0xabc", "/paid/resource") == {:error, :not_found}
    end

    test "put/5 refuses new entries once max_size is reached" do
      name = unique_atom("storage")
      table = unique_atom("table")

      storage = start_supervised!({ETSStorage, name: name, table: table, max_size: 1})

      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x1"}, 5_000)

      # Updating an existing key never grows the table and stays allowed.
      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x2"}, 5_000)

      assert ETSStorage.put(storage, "0xdef", "/paid/resource", %{"tx" => "0x3"}, 5_000) ==
               {:error, :storage_full}
    end
  end

  describe "ttl behavior" do
    test "expired entries return not_found on read" do
      {storage, _table} = start_storage(cleanup_interval_ms: 10_000)

      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x1"}, 5)
      Process.sleep(25)

      assert ETSStorage.get(storage, "0xabc", "/paid/resource") == {:error, :not_found}
    end

    test "periodic cleanup removes expired entries" do
      name = unique_atom("storage")
      table = unique_atom("table")

      storage =
        start_supervised!({ETSStorage, name: name, table: table, cleanup_interval_ms: 10})

      assert :ok = ETSStorage.put(storage, "0xabc", "/paid/resource", %{"tx" => "0x1"}, 1)

      Process.sleep(40)

      assert :ets.lookup(table, {"0xabc", "/paid/resource"}) == []
    end
  end

  defp start_storage(opts \\ []) do
    name = unique_atom("storage")
    table = unique_atom("table")

    server = start_supervised!({ETSStorage, Keyword.merge([name: name, table: table], opts)})
    {server, table}
  end

  defp unique_atom(prefix) do
    String.to_atom("#{prefix}_#{System.unique_integer([:positive, :monotonic])}")
  end
end
