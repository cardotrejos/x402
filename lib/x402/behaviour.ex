defmodule X402.Behaviour do
  @moduledoc """
  Utility functions for checking behaviour implementations.

  Used internally to verify that modules implement the required
  callbacks for x402 extension behaviours.
  """

  @doc since: "0.4.0"
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
