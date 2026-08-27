defmodule X402.PaywallTest do
  use ExUnit.Case, async: true
  doctest X402.Paywall

  alias X402.Paywall

  defmodule Implementing do
    @behaviour X402.Paywall

    @impl X402.Paywall
    def render(_payment_required, _conn_info), do: {:ok, "<html></html>"}
  end

  defmodule NotImplementing do
  end

  describe "validate_module/1" do
    test "accepts a module implementing the behaviour" do
      assert Paywall.validate_module(Implementing) == {:ok, Implementing}
      assert Paywall.validate_module(X402.Paywall.Default) == {:ok, X402.Paywall.Default}
    end

    test "rejects a module without render/2" do
      assert Paywall.validate_module(NotImplementing) ==
               {:error, "expected a module implementing X402.Paywall"}
    end

    test "rejects nil and non-module values" do
      assert Paywall.validate_module(nil) ==
               {:error, "expected a module implementing X402.Paywall"}

      assert Paywall.validate_module("X402.Paywall.Default") ==
               {:error, "expected a module implementing X402.Paywall"}

      assert Paywall.validate_module({Implementing, []}) ==
               {:error, "expected a module implementing X402.Paywall"}
    end
  end
end
