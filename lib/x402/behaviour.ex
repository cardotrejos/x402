defmodule X402.Behaviour do
  @moduledoc false

  @doc """
  Checks if a module implements a set of callbacks.
  """
  @spec implements?(module(), [{atom(), arity()}]) :: boolean()
  def implements?(module, callbacks) do
    Code.ensure_loaded?(module) and
      Enum.all?(callbacks, fn {name, arity} ->
        function_exported?(module, name, arity)
      end)
  end
end
