defmodule X402.Utils do
  @moduledoc """
  Shared utility functions for the X402 library.

  Centralises helpers for Base64 decoding, map access, decimal parsing,
  and decimal comparison that are used across payment processing modules.
  """

  @doc """
  Decodes a Base64 string with or without padding.

  ## Examples

      iex> X402.Utils.decode_base64("")
      {:error, :invalid_base64}

      iex> X402.Utils.decode_base64("aGVsbG8=")
      {:ok, "hello"}

      iex> X402.Utils.decode_base64("not-valid-!!!")
      {:error, :invalid_base64}

  """
  @doc since: "0.1.0"
  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  def decode_base64(""), do: {:error, :invalid_base64}

  def decode_base64(value) do
    case Base.decode64(value, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end

  @doc """
  Finds the first non-nil value in a list.

  ## Examples

      iex> X402.Utils.first_present([nil, nil, "found"])
      "found"

      iex> X402.Utils.first_present([nil, nil])
      nil

      iex> X402.Utils.first_present([false, "other"])
      false

  """
  @doc since: "0.1.0"
  @spec first_present([term()]) :: term() | nil
  def first_present([]), do: nil
  def first_present([nil | rest]), do: first_present(rest)
  def first_present([value | _rest]), do: value

  @doc """
  Retrieves a value from a map using either a string or atom key.

  Prefers the string key if present, falls back to atom key.

  ## Examples

      iex> X402.Utils.map_value(%{"key" => "string_val"}, {"key", :key})
      "string_val"

      iex> X402.Utils.map_value(%{key: "atom_val"}, {"key", :key})
      "atom_val"

      iex> X402.Utils.map_value(%{}, {"key", :key})
      nil

  """
  @doc since: "0.1.0"
  @spec map_value(map(), {String.t(), atom()}) :: term()
  def map_value(map, {string_key, atom_key}) do
    case Map.fetch(map, string_key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key)
    end
  end

  @doc """
  Retrieves a nested value from a map using a list of string/atom key pairs.
  """
  @doc since: "0.1.0"
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
  Puts a value into a map, preferring the existing key type (string over atom).
  """
  @doc since: "0.1.0"
  @spec map_put(map(), {String.t(), atom()}, term()) :: map()
  def map_put(map, {string_key, atom_key}, value) do
    cond do
      Map.has_key?(map, string_key) -> Map.put(map, string_key, value)
      Map.has_key?(map, atom_key) -> Map.put(map, atom_key, value)
      true -> Map.put(map, string_key, value)
    end
  end

  @doc """
  Deletes both string and atom versions of a key from a map.
  """
  @doc since: "0.1.0"
  @spec map_delete(map(), {String.t(), atom()}) :: map()
  def map_delete(map, {string_key, atom_key}) do
    map |> Map.delete(string_key) |> Map.delete(atom_key)
  end

  @doc """
  Parses a decimal value (integer or string) into a `{value, scale}` tuple
  where `value / 10^scale` equals the original number.

  Returns `:error` for negative integers, non-numeric strings, or strings
  without a leading digit (e.g. `".5"`).

  ## Examples

      iex> X402.Utils.parse_decimal(42)
      {:ok, {42, 0}}

      iex> X402.Utils.parse_decimal("12.50")
      {:ok, {125, 1}}

      iex> X402.Utils.parse_decimal("0.001")
      {:ok, {1, 3}}

      iex> X402.Utils.parse_decimal(".5")
      :error

      iex> X402.Utils.parse_decimal("")
      :error

      iex> X402.Utils.parse_decimal(-1)
      :error

  """
  @doc since: "0.1.0"
  @spec parse_decimal(term()) :: {:ok, {non_neg_integer(), non_neg_integer()}} | :error
  def parse_decimal(value) when is_integer(value) and value >= 0, do: {:ok, {value, 0}}
  def parse_decimal(value) when is_binary(value), do: parse_decimal_string(String.trim(value))
  def parse_decimal(_value), do: :error

  @spec parse_decimal_string(String.t()) :: {:ok, {non_neg_integer(), non_neg_integer()}} | :error
  defp parse_decimal_string(""), do: :error
  # Reject leading-dot strings like ".5" — require at least one leading digit
  defp parse_decimal_string("." <> _rest), do: :error

  defp parse_decimal_string(value) do
    case parse_whole(value, 0) do
      {whole, ""} ->
        {:ok, {whole, 0}}

      {whole, "." <> fraction} ->
        case parse_fraction(fraction, 0, 0, 0) do
          {:ok, fraction_val, fraction_len} ->
            scale = fraction_len
            {:ok, {whole * Integer.pow(10, scale) + fraction_val, scale}}

          :error ->
            :error
        end

      _other ->
        :error
    end
  end

  defp parse_whole(<<c, rest::binary>>, acc) when c >= ?0 and c <= ?9,
    do: parse_whole(rest, acc * 10 + (c - ?0))

  defp parse_whole(rest, acc), do: {acc, rest}

  defp parse_fraction(<<c, rest::binary>>, acc, len, last_nonzero_len) when c >= ?0 and c <= ?9 do
    digit = c - ?0
    new_acc = acc * 10 + digit
    new_len = len + 1
    new_last_nonzero_len = if digit != 0, do: new_len, else: last_nonzero_len
    parse_fraction(rest, new_acc, new_len, new_last_nonzero_len)
  end

  defp parse_fraction("", acc, len, last_nonzero_len) when len > 0 do
    trimmed_acc = div(acc, Integer.pow(10, len - last_nonzero_len))
    {:ok, trimmed_acc, last_nonzero_len}
  end

  defp parse_fraction(_bin, _acc, _len, _last_nonzero_len), do: :error

  @doc """
  Compares two `{value, scale}` decimal tuples.

  Returns `:lt`, `:eq`, or `:gt`.

  ## Examples

      iex> X402.Utils.compare_decimal({10, 1}, {1, 0})
      :eq

      iex> X402.Utils.compare_decimal({5, 1}, {1, 0})
      :lt

      iex> X402.Utils.compare_decimal({15, 1}, {1, 0})
      :gt

  """
  @doc since: "0.1.0"
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

  defp compare_integer(left, right) when left < right, do: :lt
  defp compare_integer(left, right) when left > right, do: :gt
  defp compare_integer(_left, _right), do: :eq
end
