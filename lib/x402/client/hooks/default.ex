defmodule X402.Client.Hooks.Default do
  @moduledoc """
  Default no-op implementation of `X402.Client.Hooks`.

  Every callback returns `{:cont, context}` so payment creation proceeds
  unchanged.
  """

  @behaviour X402.Client.Hooks

  alias X402.Client.Hooks.Context

  @doc since: "0.9.0"
  @doc """
  Continues payment creation without changes.

  ## Examples

      iex> context = X402.Client.Hooks.Context.new(nil, %{"scheme" => "exact"}, [])
      iex> X402.Client.Hooks.Default.before_payment(context, %{}) == {:cont, context}
      true
  """
  @spec before_payment(Context.t(), map()) :: {:cont, Context.t()}
  def before_payment(%Context{} = context, _metadata), do: {:cont, context}

  @doc since: "0.9.0"
  @doc """
  Continues after payment creation without changes.
  """
  @spec after_payment(Context.t(), map()) :: {:cont, Context.t()}
  def after_payment(%Context{} = context, _metadata), do: {:cont, context}

  @doc since: "0.9.0"
  @doc """
  Continues failure handling without changes.
  """
  @spec on_payment_failure(Context.t(), map()) :: {:cont, Context.t()}
  def on_payment_failure(%Context{} = context, _metadata), do: {:cont, context}
end
