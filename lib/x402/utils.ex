defmodule X402.Utils do
  @moduledoc false

  @doc """
  Returns the value for a given key in a map, trying the string key first, then the atom key.
  """
  @spec map_value(map(), {String.t(), atom()}) :: term()
  def map_value(map, {string_key, atom_key}) do
    case Map.fetch(map, string_key) do
      {:ok, value} ->
        value

      :error ->
        Map.get(map, atom_key)
    end
  end

  @doc """
  Returns the value for a nested key path in a map.

  Traverses the map using `map_value/2` for each key in the path.
  Returns `nil` if any intermediate value is not a map or if the key is not found.
  """
  @spec nested_map_value(map(), [{String.t(), atom()}]) :: term()
  def nested_map_value(map, [key]) when is_map(map), do: map_value(map, key)

  def nested_map_value(map, [key | rest]) when is_map(map) do
    case map_value(map, key) do
      %{} = nested -> nested_map_value(nested, rest)
      _other -> nil
    end
  end

  def nested_map_value(_not_map, _keys), do: nil

  @doc """
  Returns the first non-nil value from the given list.
  """
  @spec first_present([term()]) :: term() | nil
  def first_present(values), do: Enum.find(values, &(not is_nil(&1)))
end
