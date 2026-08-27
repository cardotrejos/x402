defmodule X402.Base58 do
  @moduledoc """
  Base58 encoding and decoding using the Bitcoin alphabet.

  Solana addresses, transaction signatures, and blockhashes are Base58
  strings over the Bitcoin alphabet
  (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` — no `0`,
  `O`, `I`, or `l`). Leading zero bytes encode as leading `1` characters,
  one per byte, matching the reference implementations.

  Pure functions with no dependencies; used by `X402.Solana` and
  `X402.Scheme.ExactSVM`.
  """

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @typedoc "A Base58-encoded string."
  @type encoded :: String.t()

  digit_index = Enum.with_index(@alphabet)

  @doc since: "0.6.0"
  @doc """
  Encodes a binary as a Base58 string.

  Test vectors are the Bitcoin Core `base58_encode_decode.json` suite.

  ## Examples

      iex> X402.Base58.encode("")
      ""

      iex> X402.Base58.encode(<<0x61>>)
      "2g"

      iex> X402.Base58.encode(<<0x62, 0x62, 0x62>>)
      "a3gV"

      iex> X402.Base58.encode(<<0x51, 0x6B, 0x6F, 0xCD, 0x0F>>)
      "ABnLTmg"

      iex> X402.Base58.encode("simply a long string")
      "2cFupjhnEsSn59qHXstmK2ffpLv2"

      iex> X402.Base58.encode(<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>)
      "1111111111"
  """
  @spec encode(binary()) :: encoded()
  def encode(binary) when is_binary(binary) do
    {zeros, rest} = split_leading_zeros(binary)
    digits = rest |> :binary.decode_unsigned() |> encode_digits([])
    IO.iodata_to_binary([List.duplicate(?1, zeros) | digits])
  end

  @doc since: "0.6.0"
  @doc """
  Decodes a Base58 string, returning `:error` for invalid characters.

  ## Examples

      iex> X402.Base58.decode("2g")
      {:ok, "a"}

      iex> X402.Base58.decode("a3gV")
      {:ok, "bbb"}

      iex> X402.Base58.decode("1111111111")
      {:ok, <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>}

      iex> X402.Base58.decode("")
      {:ok, ""}

      iex> X402.Base58.decode("invalid0base58")
      :error

      iex> X402.Base58.decode(:not_a_string)
      :error
  """
  @spec decode(term()) :: {:ok, binary()} | :error
  def decode(string) when is_binary(string) do
    with {:ok, chars} <- valid_charlist(string) do
      {zeros, rest} = Enum.split_while(chars, &(&1 == ?1))
      {:ok, :binary.copy(<<0>>, length(zeros)) <> decode_digits(rest)}
    end
  end

  def decode(_string), do: :error

  @spec split_leading_zeros(binary()) :: {non_neg_integer(), binary()}
  defp split_leading_zeros(binary) do
    zeros =
      binary
      |> :binary.bin_to_list()
      |> Enum.take_while(&(&1 == 0))
      |> length()

    {zeros, :binary.part(binary, zeros, byte_size(binary) - zeros)}
  end

  @spec encode_digits(non_neg_integer(), [char()]) :: [char()]
  defp encode_digits(0, acc), do: acc

  defp encode_digits(n, acc) do
    encode_digits(div(n, 58), [Enum.at(@alphabet, rem(n, 58)) | acc])
  end

  @spec valid_charlist(binary()) :: {:ok, charlist()} | :error
  defp valid_charlist(string) do
    chars = String.to_charlist(string)

    case Enum.all?(chars, &(&1 in @alphabet)) do
      true -> {:ok, chars}
      false -> :error
    end
  end

  @spec decode_digits(charlist()) :: binary()
  defp decode_digits(chars) do
    chars
    |> Enum.reduce(0, fn char, acc -> acc * 58 + digit_value(char) end)
    |> integer_to_binary()
  end

  @spec integer_to_binary(non_neg_integer()) :: binary()
  defp integer_to_binary(0), do: ""
  defp integer_to_binary(n), do: :binary.encode_unsigned(n)

  for {char, index} <- digit_index do
    defp digit_value(unquote(char)), do: unquote(index)
  end
end
