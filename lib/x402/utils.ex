defmodule X402.Utils do
  @moduledoc false

  @max_decimal_scale 18

  @spec parse_decimal(term()) :: {:ok, {non_neg_integer(), non_neg_integer()}} | :error
  def parse_decimal(value) when is_integer(value) and value >= 0, do: {:ok, {value, 0}}
  def parse_decimal(value) when is_binary(value), do: parse_decimal_string(String.trim(value))
  def parse_decimal(_value), do: :error

  @spec parse_decimal_string(String.t()) :: {:ok, {non_neg_integer(), non_neg_integer()}} | :error
  defp parse_decimal_string(""), do: :error

  defp parse_decimal_string(value) do
    cond do
      Regex.match?(~r/^\d+$/, value) ->
        {:ok, {String.to_integer(value), 0}}

      Regex.match?(~r/^\d+\.\d+$/, value) ->
        [whole, fraction] = String.split(value, ".", parts: 2)
        do_parse_fractional(whole, String.trim_trailing(fraction, "0"))

      true ->
        :error
    end
  end

  defp do_parse_fractional(whole, ""), do: {:ok, {String.to_integer(whole), 0}}

  defp do_parse_fractional(whole, fraction) do
    scale = String.length(fraction)

    if scale <= @max_decimal_scale do
      {:ok, {String.to_integer(whole <> fraction), scale}}
    else
      :error
    end
  end

  @spec compare_decimal(
          {non_neg_integer(), non_neg_integer()},
          {non_neg_integer(), non_neg_integer()}
        ) :: :lt | :eq | :gt
  def compare_decimal({left_value, left_scale}, {right_value, right_scale})
      when left_scale == right_scale do
    compare_integer(left_value, right_value)
  end

  def compare_decimal({left_value, left_scale}, {right_value, right_scale})
      when left_scale > right_scale do
    compare_integer(left_value, right_value * Integer.pow(10, left_scale - right_scale))
  end

  def compare_decimal({left_value, left_scale}, {right_value, right_scale}) do
    compare_integer(left_value * Integer.pow(10, right_scale - left_scale), right_value)
  end

  @spec compare_integer(non_neg_integer(), non_neg_integer()) :: :lt | :eq | :gt
  def compare_integer(left, right) when left < right, do: :lt
  def compare_integer(left, right) when left > right, do: :gt
  def compare_integer(_left, _right), do: :eq

  @spec nested_map_value(map(), [{String.t(), atom()}]) :: term()
  def nested_map_value(map, [key]) when is_map(map), do: map_value(map, key)

  def nested_map_value(map, [key | rest]) when is_map(map) do
    case map_value(map, key) do
      %{} = nested -> nested_map_value(nested, rest)
      _other -> nil
    end
  end

  def nested_map_value(_not_map, _keys), do: nil

  @spec map_value(map(), {String.t(), atom()}) :: term()
  def map_value(map, {string_key, atom_key}) do
    case Map.fetch(map, string_key) do
      {:ok, value} ->
        value

      :error ->
        Map.get(map, atom_key)
    end
  end

  @spec first_present([term() | (-> term())]) :: term() | nil
  def first_present([]), do: nil

  def first_present([func | rest]) when is_function(func, 0) do
    case func.() do
      nil -> first_present(rest)
      value -> value
    end
  end

  def first_present([nil | rest]), do: first_present(rest)
  def first_present([value | _rest]), do: value
end
