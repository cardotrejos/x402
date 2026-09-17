defmodule X402.Client.BudgetTest do
  use ExUnit.Case, async: true

  doctest X402.Client.Budget

  alias X402.Client.Budget

  @usdc "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @dai "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"

  describe "start_link/1" do
    test "registers under :name and accepts integer-string limits" do
      name = :"budget_#{System.unique_integer([:positive])}"
      start_supervised!({Budget, name: name, limit: "250"})

      assert Budget.reserve(name, @usdc, 250) == :ok
      assert Budget.spent(name) == %{total: 250, per_asset: %{String.downcase(@usdc) => 250}}
    end

    test "validates the limit and per-asset limits" do
      assert_raise NimbleOptions.ValidationError, ~r/:limit/, fn ->
        Budget.start_link([])
      end

      assert_raise NimbleOptions.ValidationError, ~r/integer/, fn ->
        Budget.start_link(limit: "1.5")
      end

      assert_raise NimbleOptions.ValidationError, ~r/integer/, fn ->
        Budget.start_link(limit: -1)
      end

      assert_raise NimbleOptions.ValidationError, ~r/integer/, fn ->
        Budget.start_link(limit: 10, per_asset: %{@usdc => "lots"})
      end
    end
  end

  describe "reserve/3 and release/3" do
    test "enforces the total limit and leaves the budget untouched on refusal" do
      budget = start_supervised!({Budget, limit: 100})

      assert Budget.reserve(budget, @usdc, 70) == :ok

      assert Budget.reserve(budget, @dai, "31") ==
               {:error,
                {:budget_exceeded,
                 %{scope: :total, asset: @dai, amount: 31, limit: 100, spent: 70}}}

      assert Budget.spent(budget) == %{total: 70, per_asset: %{String.downcase(@usdc) => 70}}
      assert Budget.reserve(budget, @dai, 30) == :ok
    end

    test "enforces per-asset limits case-insensitively" do
      budget = start_supervised!({Budget, limit: 1_000, per_asset: %{@usdc => 50}})

      assert Budget.reserve(budget, String.downcase(@usdc), 40) == :ok

      assert Budget.reserve(budget, @usdc, 11) ==
               {:error,
                {:budget_exceeded,
                 %{scope: :asset, asset: @usdc, amount: 11, limit: 50, spent: 40}}}

      # Other assets only see the total limit.
      assert Budget.reserve(budget, @dai, 900) == :ok

      assert Budget.spent(budget) == %{
               total: 940,
               per_asset: %{String.downcase(@usdc) => 40, String.downcase(@dai) => 900}
             }
    end

    test "release gives the amount back and never goes below zero" do
      budget = start_supervised!({Budget, limit: 100})

      assert Budget.reserve(budget, @usdc, 60) == :ok
      assert Budget.release(budget, @usdc, 100) == :ok
      assert Budget.spent(budget) == %{total: 0, per_asset: %{String.downcase(@usdc) => 0}}
      assert Budget.release(budget, @dai, 5) == :ok
      assert Budget.spent(budget).per_asset[String.downcase(@dai)] == 0
      assert Budget.reserve(budget, @usdc, 100) == :ok
    end

    test "rejects invalid amounts without touching the budget" do
      budget = start_supervised!({Budget, limit: 100})

      assert Budget.reserve(budget, @usdc, "-1") == {:error, :invalid_amount}
      assert Budget.reserve(budget, @usdc, nil) == {:error, :invalid_amount}
      assert Budget.reserve(budget, @usdc, "1e3") == {:error, :invalid_amount}
      assert Budget.release(budget, @usdc, 1.5) == {:error, :invalid_amount}
      assert Budget.spent(budget) == %{total: 0, per_asset: %{}}
    end

    test "concurrent reservations never overspend" do
      budget = start_supervised!({Budget, limit: 100})

      results =
        1..50
        |> Task.async_stream(fn _index -> Budget.reserve(budget, @usdc, 10) end,
          max_concurrency: 50
        )
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &(&1 == :ok)) == 10
      assert Enum.count(results, &match?({:error, {:budget_exceeded, _details}}, &1)) == 40
      assert Budget.spent(budget).total == 100
    end
  end

  describe "validate_ref/1" do
    test "accepts pids and registered names" do
      assert Budget.validate_ref(self()) == {:ok, self()}
      assert Budget.validate_ref(:budget) == {:ok, :budget}
      assert Budget.validate_ref({:global, :budget}) == {:ok, {:global, :budget}}

      assert Budget.validate_ref({:via, Registry, {Reg, :b}}) ==
               {:ok, {:via, Registry, {Reg, :b}}}
    end

    test "rejects anything else" do
      assert {:error, _message} = Budget.validate_ref(nil)
      assert {:error, _message} = Budget.validate_ref("budget")
      assert {:error, _message} = Budget.validate_ref({:via, "Registry", :b})
    end
  end
end
