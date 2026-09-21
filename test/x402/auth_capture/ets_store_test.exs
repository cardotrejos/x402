defmodule X402.AuthCapture.ETSStoreTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture.ETSStore

  alias X402.AuthCapture.ETSStore
  alias X402.AuthCapture.Store

  setup do
    %{server: start_supervised!(ETSStore)}
  end

  test "serializes concurrent read-modify-write without lost updates", %{server: server} do
    results =
      1..32
      |> Task.async_stream(
        fn _ ->
          ETSStore.transact(server, :counter, fn current ->
            next = (current || %{value: 0}).value + 1
            {:commit, %{value: next}, next}
          end)
        end,
        max_concurrency: 32
      )
      |> Enum.map(fn {:ok, {:ok, value}} -> value end)

    assert Enum.sort(results) == Enum.to_list(1..32)
    assert ETSStore.fetch(server, :counter) == {:ok, %{value: 32}}
    assert ETSStore.fetch(server, :missing) == {:ok, nil}
  end

  test "aborts and callback failures preserve the previous value and owner", %{server: server} do
    assert ETSStore.transact(server, :key, fn nil -> {:commit, %{value: 1}, :saved} end) ==
             {:ok, :saved}

    for callback <- [
          fn _ -> {:abort, :denied} end,
          fn _ -> {:commit, nil, :bad} end,
          fn _ -> :bad end,
          fn _ -> raise "not exposed" end,
          fn _ -> throw(:not_exposed) end,
          fn _ -> exit(:not_exposed) end
        ] do
      assert {:error, _} = ETSStore.transact(server, :key, callback)
      assert ETSStore.fetch(server, :key) == {:ok, %{value: 1}}
      assert Process.alive?(server)
    end
  end

  test "a dead store fails closed through the adapter boundary", %{server: server} do
    GenServer.stop(server)
    assert Store.fetch({ETSStore, server}, :key) == {:error, :store_unavailable}
    assert Store.transact({ETSStore, server}, :key, & &1) == {:error, :store_unavailable}
  end

  test "rejects invalid startup options" do
    assert {:error, %NimbleOptions.ValidationError{}} = ETSStore.start_link(name: "invalid")
    assert {:error, %NimbleOptions.ValidationError{}} = ETSStore.start_link(ttl: 1)
  end

  test "multi-key mutations commit both records or neither", %{server: server} do
    for _ <- 1..32 do
      assert {:ok, :saved} =
               ETSStore.transact_many(server, [:left, :right], fn values ->
                 left = (values.left || %{count: 0}).count
                 right = (values.right || %{count: 0}).count

                 if left == right,
                   do: {:commit, %{left: %{count: left + 1}, right: %{count: right + 1}}, :saved},
                   else: {:abort, :torn_snapshot}
               end)
    end

    assert ETSStore.fetch(server, :left) == {:ok, %{count: 32}}
    assert ETSStore.fetch(server, :right) == {:ok, %{count: 32}}

    assert ETSStore.transact_many(server, [:left, :right], fn _ ->
             {:commit, %{left: %{count: 33}, outside: %{}}, :bad}
           end) == {:error, :invalid_store_mutation}

    assert ETSStore.fetch(server, :left) == {:ok, %{count: 32}}
    assert ETSStore.fetch(server, :outside) == {:ok, nil}

    assert ETSStore.transact(server, :left, fn value -> {:keep, value} end) ==
             {:ok, %{count: 32}}
  end
end
