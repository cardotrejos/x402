defmodule X402.Facilitator.NonceManagerTest do
  use ExUnit.Case, async: true

  doctest X402.Facilitator.NonceManager

  alias X402.Facilitator.NonceManager

  defp start_manager do
    start_supervised!({NonceManager, []})
  end

  test "fetches once, then increments locally" do
    manager = start_manager()
    parent = self()

    fetch = fn ->
      send(parent, :fetched)
      {:ok, 7}
    end

    assert {:ok, 7} = NonceManager.checkout(manager, "0xAbC", fetch)
    assert {:ok, 8} = NonceManager.checkout(manager, "0xabc", fetch)
    assert {:ok, 9} = NonceManager.checkout(manager, "0xABC", fetch)

    assert_received :fetched
    refute_received :fetched
  end

  test "concurrent checkouts receive distinct consecutive nonces" do
    manager = start_manager()
    fetch = fn -> {:ok, 100} end

    nonces =
      1..50
      |> Enum.map(fn _i ->
        Task.async(fn ->
          {:ok, nonce} = NonceManager.checkout(manager, "0xfee", fetch)
          nonce
        end)
      end)
      |> Task.await_many()

    assert Enum.sort(nonces) == Enum.to_list(100..149)
  end

  test "reset defers until in-flight settlements drain, then re-fetches" do
    manager = start_manager()

    assert {:ok, 1} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 1} end)
    assert :ok = NonceManager.reset(manager, "0xFEE")

    # The reset is deferred: nonce 1 is still in flight, so tracking must
    # survive and hand out 2 rather than re-fetch under it.
    assert {:ok, 2} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 99} end)

    assert :ok = NonceManager.complete(manager, "0xfee", 1)
    assert :ok = NonceManager.complete(manager, "0xfee", 2)

    # Drained — the deferred reset applies and the next checkout re-fetches.
    assert {:ok, 42} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 42} end)
  end

  test "releasing the tail nonce rolls it back without a gap" do
    manager = start_manager()

    assert {:ok, 5} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 5} end)
    assert {:ok, 6} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 0} end)

    assert :ok = NonceManager.release(manager, "0xfee", 6)

    # The tail came back unused — the next checkout takes it again.
    assert {:ok, 6} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 0} end)
  end

  test "releasing a middle nonce re-fetches once in-flight settlements drain" do
    manager = start_manager()

    assert {:ok, 5} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 5} end)
    assert {:ok, 6} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 0} end)

    # 5 fails while 6 is still in flight — a gap at the node. 6 must keep
    # its nonce (no reissue), and once it drains the address re-fetches.
    assert :ok = NonceManager.release(manager, "0xfee", 5)
    assert {:ok, 7} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 0} end)

    assert :ok = NonceManager.complete(manager, "0xfee", 6)
    assert :ok = NonceManager.complete(manager, "0xfee", 7)

    assert {:ok, 11} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 11} end)
  end

  test "raising fetch functions are caught, not fatal" do
    manager = start_manager()

    assert {:error, {:nonce_fetch_failed, %RuntimeError{}}} =
             NonceManager.checkout(manager, "0xfee", fn -> raise "boom" end)

    assert {:ok, 3} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 3} end)
  end

  test "fetch errors propagate and are not stored" do
    manager = start_manager()

    assert {:error, :boom} = NonceManager.checkout(manager, "0xfee", fn -> {:error, :boom} end)
    assert {:ok, 5} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 5} end)
  end

  test "invalid fetch results are rejected" do
    manager = start_manager()

    assert {:error, {:invalid_nonce, "0x1"}} =
             NonceManager.checkout(manager, "0xfee", fn -> {:ok, "0x1"} end)
  end

  test "tracks addresses independently" do
    manager = start_manager()

    assert {:ok, 1} = NonceManager.checkout(manager, "0xaaa", fn -> {:ok, 1} end)
    assert {:ok, 9} = NonceManager.checkout(manager, "0xbbb", fn -> {:ok, 9} end)
    assert {:ok, 2} = NonceManager.checkout(manager, "0xaaa", fn -> {:ok, 0} end)
  end

  test "start_link registers the manager under a name" do
    name = :"nonce_manager_#{System.unique_integer([:positive, :monotonic])}"
    start_supervised!({NonceManager, name: name})

    assert {:ok, 3} = NonceManager.checkout(name, "0xfee", fn -> {:ok, 3} end)
  end

  test "complete and release on an untracked address are no-ops" do
    manager = start_manager()

    assert :ok = NonceManager.complete(manager, "0xfee", 3)
    assert :ok = NonceManager.release(manager, "0xfee", 3)

    # Nothing was stored — the first checkout still fetches from the node.
    assert {:ok, 7} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 7} end)
  end

  test "reset with nothing in flight drops the address immediately" do
    manager = start_manager()

    assert {:ok, 5} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 5} end)
    assert :ok = NonceManager.complete(manager, "0xfee", 5)
    assert :ok = NonceManager.reset(manager, "0xfee")

    # The tracked entry is gone — the next checkout re-fetches.
    assert {:ok, 42} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 42} end)
  end

  test "fetch results that are not result tuples are rejected" do
    manager = start_manager()

    assert {:error, {:invalid_nonce, :bogus}} =
             NonceManager.checkout(manager, "0xfee", fn -> :bogus end)
  end
end
