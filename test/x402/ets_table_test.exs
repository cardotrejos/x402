defmodule X402.ETSTableTest do
  use ExUnit.Case, async: true

  alias X402.ETSTable

  setup do
    name = :"x402_ets_table_test_#{System.unique_integer([:positive, :monotonic])}"
    on_exit(fn -> ETSTable.delete(name) end)
    {:ok, name: name}
  end

  test "ensure/2 creates the table once and survives the caller exiting", %{name: name} do
    task = Task.async(fn -> ETSTable.ensure(name, [:set]) end)
    assert Task.await(task) == name

    assert :ets.whereis(name) != :undefined
    assert :ets.insert(name, {:k, 1})
    assert ETSTable.ensure(name, [:set]) == name
    assert :ets.lookup(name, :k) == [{:k, 1}]
  end

  test "concurrent first callers all end up with the same table", %{name: name} do
    results =
      1..20
      |> Task.async_stream(fn _index -> ETSTable.ensure(name, [:set]) end, max_concurrency: 20)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [name]
    assert :ets.whereis(name) != :undefined
  end

  test "delete/1 removes the table and tolerates repeats", %{name: name} do
    assert ETSTable.delete(name) == :ok

    ETSTable.ensure(name, [:set])
    assert ETSTable.delete(name) == :ok
    assert :ets.whereis(name) == :undefined
    assert ETSTable.delete(name) == :ok
  end

  test "delete/1 handles a table whose owner row is missing", %{name: name} do
    ETSTable.ensure(name, [:set])
    [{owner_key, _pid}] = :ets.tab2list(name)
    :ets.delete(name, owner_key)

    assert ETSTable.delete(name) == :ok
    assert :ets.whereis(name) != :undefined
  end
end
