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

  test "reset forgets the address so the next checkout re-fetches" do
    manager = start_manager()

    assert {:ok, 1} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 1} end)
    assert :ok = NonceManager.reset(manager, "0xFEE")
    assert {:ok, 42} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 42} end)
    assert {:ok, 43} = NonceManager.checkout(manager, "0xfee", fn -> {:ok, 0} end)
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
end
