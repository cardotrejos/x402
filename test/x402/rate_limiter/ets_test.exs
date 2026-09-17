defmodule X402.RateLimiter.ETSTest do
  use ExUnit.Case, async: true

  doctest X402.RateLimiter.ETS

  alias X402.RateLimiter.ETS

  setup do
    {:ok, table: :"rate_limiter_ets_test_#{System.unique_integer([:positive, :monotonic])}"}
  end

  test "counts down the remaining allowance and then denies", %{table: table} do
    assert ETS.hit(table, :a, 3, 10_000) == {:allow, 2}
    assert ETS.hit(table, :a, 3, 10_000) == {:allow, 1}
    assert ETS.hit(table, :a, 3, 10_000) == {:allow, 0}
    assert {:deny, retry_after_ms} = ETS.hit(table, :a, 3, 10_000)
    assert retry_after_ms in 1..10_000
  end

  test "denied hits do not extend the window", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :a, 1, 10_000)
    assert {:deny, first} = ETS.hit(table, :a, 1, 10_000)
    Process.sleep(5)
    assert {:deny, second} = ETS.hit(table, :a, 1, 10_000)
    assert second <= first
  end

  test "opens a fresh window once the previous one closes", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :a, 1, 30)
    assert {:deny, _retry} = ETS.hit(table, :a, 1, 30)
    Process.sleep(40)
    assert {:allow, 0} = ETS.hit(table, :a, 1, 30)
  end

  test "keys are independent", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, {:payer, "0xa"}, 1, 10_000)
    assert {:allow, 0} = ETS.hit(table, {:payer, "0xb"}, 1, 10_000)
    assert {:deny, _retry} = ETS.hit(table, {:payer, "0xa"}, 1, 10_000)
  end

  test "keys may be arbitrary terms including match-spec-looking atoms", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :"$1", 1, 10_000)
    assert {:allow, 0} = ETS.hit(table, :_, 1, 10_000)
    assert {:deny, _retry} = ETS.hit(table, :"$1", 1, 10_000)
    assert {:deny, _retry} = ETS.hit(table, :_, 1, 10_000)
  end

  test "nil selects the default table" do
    key = {:default_table_probe, System.unique_integer([:positive])}
    assert {:allow, 0} = ETS.hit(nil, key, 1, 10_000)
    assert {:deny, _retry} = ETS.hit(ETS, key, 1, 10_000)
  end

  test "concurrent hits never exceed the limit", %{table: table} do
    limit = 25

    results =
      1..200
      |> Task.async_stream(fn _index -> ETS.hit(table, :shared, limit, 60_000) end,
        max_concurrency: 50
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:allow, _remaining}, &1)) == limit
    assert Enum.count(results, &match?({:deny, _retry}, &1)) == 200 - limit
  end

  test "concurrent window rollovers open exactly one new window", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :roll, 1, 20)
    Process.sleep(30)

    results =
      1..50
      |> Task.async_stream(fn _index -> ETS.hit(table, :roll, 1, 60_000) end,
        max_concurrency: 50
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:allow, 0}, &1)) == 1
  end

  test "sweep/1 removes closed windows only", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :old, 1, 20)
    assert {:allow, 0} = ETS.hit(table, :fresh, 1, 60_000)
    Process.sleep(30)

    assert ETS.sweep(table) == 1
    assert ETS.sweep(table) == 0
    assert {:deny, _retry} = ETS.hit(table, :fresh, 1, 60_000)
    assert {:allow, 0} = ETS.hit(table, :old, 1, 60_000)
  end

  test "reset/1 clears every counter", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :a, 1, 60_000)
    assert {:allow, 0} = ETS.hit(table, :b, 1, 60_000)

    assert ETS.reset(table) == :ok

    assert {:allow, 0} = ETS.hit(table, :a, 1, 60_000)
    assert {:allow, 0} = ETS.hit(table, :b, 1, 60_000)
  end

  test "sweeps opportunistically after many hits", %{table: table} do
    assert {:allow, 0} = ETS.hit(table, :stale, 1, 10)
    Process.sleep(20)

    for index <- 1..1_100, do: ETS.hit(table, {:churn, index}, 1, 60_000)

    assert :ets.lookup(table, :stale) == []
  end

  test "the table survives the creating process exiting", %{table: table} do
    task = Task.async(fn -> ETS.hit(table, :a, 1, 60_000) end)
    assert {:allow, 0} = Task.await(task)

    assert {:deny, _retry} = ETS.hit(table, :a, 1, 60_000)
  end

  test "concurrent first use creates the table once" do
    table = :"rate_limiter_race_#{System.unique_integer([:positive])}"

    results =
      1..20
      |> Task.async_stream(fn _index -> ETS.hit(table, :race, 100, 60_000) end,
        max_concurrency: 20
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.all?(results, &match?({:allow, _remaining}, &1))
    assert :ets.whereis(table) != :undefined
    assert [{:race, 20, _start, _end}] = :ets.lookup(table, :race)
  end
end
