defmodule X402.HooksTest do
  use ExUnit.Case, async: true

  alias X402.Hooks
  alias X402.Hooks.Context

  defmodule ValidHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.Context

    def before_verify(%Context{} = context, _metadata), do: {:cont, context}
    def after_verify(%Context{} = context, _metadata), do: {:cont, context}
    def on_verify_failure(%Context{} = context, _metadata), do: {:cont, context}
    def before_settle(%Context{} = context, _metadata), do: {:cont, context}
    def after_settle(%Context{} = context, _metadata), do: {:cont, context}
    def on_settle_failure(%Context{} = context, _metadata), do: {:cont, context}
  end

  defmodule InvalidHooks do
    @moduledoc false

    def before_verify(_context, _metadata), do: :ok
  end

  test "validate_module/1 accepts modules implementing X402.Hooks" do
    assert {:ok, ValidHooks} = Hooks.validate_module(ValidHooks)
  end

  test "validate_module/1 rejects modules missing required callbacks" do
    assert {:error, "expected a module implementing X402.Hooks"} =
             Hooks.validate_module(InvalidHooks)
  end

  test "validate_module/1 rejects non-module values" do
    assert {:error, "expected a module implementing X402.Hooks"} = Hooks.validate_module("bad")
  end

  defmodule ResourceHooks do
    @moduledoc false
    @behaviour X402.Hooks

    alias X402.Hooks.RequestContext

    def before_verify(context, _metadata), do: {:cont, context}
    def after_verify(context, _metadata), do: {:cont, context}
    def on_verify_failure(context, _metadata), do: {:cont, context}
    def before_settle(context, _metadata), do: {:cont, context}
    def after_settle(context, _metadata), do: {:cont, context}
    def on_settle_failure(context, _metadata), do: {:cont, context}

    def on_protected_request(%RequestContext{} = context, %{result: result} = metadata) do
      send(self(), {:protected_request, metadata})

      case result do
        :raise -> raise "boom"
        :throw -> throw(:boom)
        :empty -> {:cont, %{context | requirements: []}}
        :bad_extensions -> {:cont, %{context | extensions: nil}}
        :not_struct -> {:cont, %{requirements: [%{}]}}
        :bad_status -> {:halt, {600, %{}}}
        :bad_body -> {:halt, {403, "nope"}}
        other -> other
      end
    end

    def on_verified_payment_canceled(_context, %{result: :raise}), do: raise("cancel boom")
    def on_verified_payment_canceled(_context, %{result: :throw}), do: throw(:cancel_boom)

    def on_verified_payment_canceled(context, metadata) do
      send(self(), {:canceled, context, metadata})
      :ignored
    end
  end

  describe "run_protected_request/3" do
    alias X402.Hooks.RequestContext

    @context RequestContext.new(transport: :http, requirements: [%{"scheme" => "exact"}])

    test "continues untouched for modules without the callback" do
      assert {:cont, @context} = Hooks.run_protected_request(ValidHooks, @context, %{})
      assert {:cont, @context} = Hooks.run_protected_request(Hooks.Default, @context, %{})
    end

    test "passes through valid results" do
      updated = %{@context | requirements: [%{"scheme" => "upto"}]}

      assert {:cont, ^updated} =
               Hooks.run_protected_request(ResourceHooks, @context, %{result: {:cont, updated}})

      assert_received {:protected_request, %{transport: :http, hook_module: ResourceHooks}}

      assert {:halt, :skip_payment} =
               Hooks.run_protected_request(ResourceHooks, @context, %{
                 result: {:halt, :skip_payment}
               })

      assert {:halt, {403, %{"error" => "no"}}} =
               Hooks.run_protected_request(ResourceHooks, @context, %{
                 result: {:halt, {403, %{"error" => "no"}}}
               })
    end

    test "rejects invalid results and raised or thrown failures" do
      for result <- [:ok, :empty, :bad_extensions, :not_struct, :bad_status, :bad_body] do
        assert {:error, {:hook_invalid_return, :on_protected_request, _value}} =
                 Hooks.run_protected_request(ResourceHooks, @context, %{result: result}),
               "expected #{inspect(result)} to be rejected"
      end

      assert {:error, {:hook_callback_failed, :on_protected_request, %RuntimeError{}}} =
               Hooks.run_protected_request(ResourceHooks, @context, %{result: :raise})

      assert {:error, {:hook_callback_failed, :on_protected_request, {:throw, :boom}}} =
               Hooks.run_protected_request(ResourceHooks, @context, %{result: :throw})
    end
  end

  describe "run_verified_payment_canceled/3" do
    alias X402.Hooks.RequestContext

    @context RequestContext.new(transport: :mcp, tool: "search")

    test "is a no-op for modules without the callback" do
      assert :ok = Hooks.run_verified_payment_canceled(ValidHooks, @context, %{reason: :x})
    end

    test "invokes the callback with transport and hook module metadata" do
      metadata = %{reason: :handler_failed, response_status: 500}
      assert :ok = Hooks.run_verified_payment_canceled(ResourceHooks, @context, metadata)

      assert_received {:canceled, @context,
                       %{
                         reason: :handler_failed,
                         response_status: 500,
                         transport: :mcp,
                         hook_module: ResourceHooks
                       }}
    end

    test "logs raised and thrown failures" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert :ok =
                   Hooks.run_verified_payment_canceled(ResourceHooks, @context, %{result: :raise})

          assert :ok =
                   Hooks.run_verified_payment_canceled(ResourceHooks, @context, %{result: :throw})
        end)

      assert log =~ "on_verified_payment_canceled/2 failed"
      assert log =~ "cancel boom"
      assert log =~ "cancel_boom"
    end
  end
end
