defmodule X402.AuthCapture.Output do
  @moduledoc false
  @max_bytes 1_048_576
  @max_depth 64

  @doc false
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_bytes

  @doc false
  @spec encode(term()) :: {:ok, binary()} | {:error, atom()}
  def encode(value) do
    with {:ok, _remaining} <- size(value, @max_bytes, 0),
         {:ok, iodata} <- Jason.encode_to_iodata(value),
         true <- :erlang.iolist_size(iodata) <= @max_bytes do
      {:ok, IO.iodata_to_binary(iodata)}
    else
      _invalid -> {:error, :invalid_output}
    end
  end

  # Bound plain-JSON input before invoking an encoder. Escape expansion is
  # bounded by the input budget; custom encoders cannot allocate unbounded
  # output from a small struct. Check encoded size again before flattening.
  @spec size(term(), integer(), non_neg_integer()) :: {:ok, integer()} | :error
  defp size(_value, budget, depth) when budget < 0 or depth > @max_depth, do: :error
  defp size(%_struct{}, _budget, _depth), do: :error

  defp size(value, budget, _depth) when is_binary(value),
    do: remaining(budget - byte_size(value) - 2)

  defp size(value, budget, _depth) when value in [true, nil], do: remaining(budget - 4)
  defp size(false, budget, _depth), do: remaining(budget - 5)

  defp size(value, budget, depth) when is_atom(value),
    do: size(Atom.to_string(value), budget, depth)

  defp size(value, budget, _depth) when is_float(value), do: remaining(budget - 1)

  defp size(value, budget, _depth) when is_integer(value) do
    if :erlang.external_size(value) <= budget,
      do: remaining(budget - byte_size(Integer.to_string(value))),
      else: :error
  end

  defp size(value, budget, depth) when is_list(value), do: list_size(value, budget - 2, depth + 1)

  defp size(value, budget, depth) when is_map(value) do
    Enum.reduce_while(value, remaining(budget - 2), fn {key, value}, state ->
      case member_size(key, value, state, depth + 1) do
        {:ok, _} = next -> {:cont, next}
        :error -> {:halt, :error}
      end
    end)
  end

  defp size(_value, _budget, _depth), do: :error

  @spec member_size(term(), term(), tuple() | :error, non_neg_integer()) :: tuple() | :error
  defp member_size(key, value, {:ok, budget}, depth) when is_binary(key) or is_atom(key) do
    with {:ok, budget} <- size(key, budget - 2, depth), do: size(value, budget, depth)
  end

  defp member_size(_key, _value, _state, _depth), do: :error

  @spec list_size(term(), integer(), non_neg_integer()) :: tuple() | :error
  defp list_size([], budget, _depth), do: remaining(budget)

  defp list_size([head | tail], budget, depth) do
    with {:ok, budget} <- size(head, budget - 1, depth), do: list_size(tail, budget, depth)
  end

  defp list_size(_tail, _budget, _depth), do: :error

  @spec remaining(integer()) :: {:ok, integer()} | :error
  defp remaining(budget) when budget >= 0, do: {:ok, budget}
  defp remaining(_budget), do: :error
end
