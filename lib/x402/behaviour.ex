defmodule X402.Behaviour do
  @moduledoc """
  Utilities for working with Elixir behaviours and callback implementations.
  """

  @doc since: "0.3.0"
  defmacro __using__(opts) do
    callbacks = Keyword.fetch!(opts, :callbacks)

    quote do
      @required_callbacks unquote(callbacks)

      @spec implementation?(module()) :: boolean()
      defp implementation?(module), do: X402.Behaviour.implements?(module, @required_callbacks)
    end
  end

  @doc since: "0.1.0"
  @doc """
  Checks if a module implements a set of callbacks.

  The `callbacks` argument should be a list of `{name, arity}` tuples.
  """
  @spec implements?(module(), [{atom(), integer()}]) :: boolean()
  def implements?(module, callbacks) do
    Code.ensure_loaded?(module) and
      Enum.all?(callbacks, fn {name, arity} ->
        function_exported?(module, name, arity)
      end)
  end

  @doc since: "0.3.0"
  @doc """
  Validates that a module implements a behaviour.

  This function is designed for `NimbleOptions` custom validation.
  """
  @spec validate_implementation(term(), module(), [{atom(), integer()}]) ::
          :ok | {:error, String.t()}
  def validate_implementation(module, behaviour, callbacks) when is_atom(module) do
    if implements?(module, callbacks) do
      :ok
    else
      {:error, "expected a module implementing #{inspect(behaviour)}"}
    end
  end

  def validate_implementation(_invalid, behaviour, _callbacks) do
    {:error, "expected a module implementing #{inspect(behaviour)}"}
  end
end
