defmodule X402.Client.HooksTest do
  use ExUnit.Case, async: true

  doctest X402.Client.Hooks
  doctest X402.Client.Hooks.Context
  doctest X402.Client.Hooks.Default

  alias X402.Client.Hooks
  alias X402.Client.Hooks.Context
  alias X402.Client.Hooks.Default

  defmodule Partial do
    @moduledoc false
    def before_payment(context, _metadata), do: {:cont, context}
  end

  describe "validate_module/1" do
    test "accepts modules implementing every callback" do
      assert Hooks.validate_module(Default) == {:ok, Default}
    end

    test "rejects modules missing callbacks and non-modules" do
      assert {:error, message} = Hooks.validate_module(Partial)
      assert message =~ "X402.Client.Hooks"
      assert {:error, _message} = Hooks.validate_module("hooks")
      assert {:error, _message} = Hooks.validate_module(nil)
    end
  end

  describe "X402.Client.Hooks.Default" do
    test "every callback continues with the context unchanged" do
      context = Context.new(%{"accepts" => []}, %{"scheme" => "exact"}, max_amount: "1")
      metadata = %{operation: :build_payment, hook_module: Default, scheme: "exact", network: nil}

      assert Default.before_payment(context, metadata) == {:cont, context}

      assert Default.after_payment(%{context | payload: %{}}, metadata) ==
               {:cont, %{context | payload: %{}}}

      assert Default.on_payment_failure(%{context | error: :boom}, metadata) ==
               {:cont, %{context | error: :boom}}
    end
  end

  describe "X402.Client.Hooks.Context.new/3" do
    test "accepts a nil payment_required for bare requirements" do
      context = Context.new(nil, %{"scheme" => "exact"}, [])
      assert context.payment_required == nil
      assert context.opts == []
    end
  end
end
