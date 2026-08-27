defmodule X402.RLP do
  @moduledoc """
  Minimal pure [RLP](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/)
  (Recursive Length Prefix) encoding.

  Provides exactly the encoding surface `X402.Transaction` needs to build
  EIP-1559 typed transactions: binaries, non-negative integers (encoded as
  their minimal big-endian byte representation, so `0` encodes as the empty
  string), and nested lists thereof. There is no decoder — the library never
  needs to parse RLP, and settlement tests decode raw transactions with their
  own reference decoder to prove the encoding.

  ## Examples

      iex> X402.RLP.encode("dog")
      <<0x83, "dog">>

      iex> X402.RLP.encode(["cat", "dog"])
      <<0xC8, 0x83, "cat", 0x83, "dog">>

      iex> X402.RLP.encode(0)
      <<0x80>>

      iex> X402.RLP.encode(1024)
      <<0x82, 0x04, 0x00>>
  """

  @typedoc "An RLP-encodable item: a binary, a non-negative integer, or a list of items."
  @type item :: binary() | non_neg_integer() | [item()]

  @doc since: "0.6.0"
  @doc """
  RLP-encodes a binary, a non-negative integer, or a (nested) list of items.

  Integers are encoded as their minimal big-endian byte representation per
  the Ethereum convention (`0` becomes the empty byte string, so leading
  zero bytes never appear).

  ## Examples

      iex> X402.RLP.encode("")
      <<0x80>>

      iex> X402.RLP.encode(<<0x7F>>)
      <<0x7F>>

      iex> X402.RLP.encode(15)
      <<0x0F>>

      iex> X402.RLP.encode([])
      <<0xC0>>

      iex> X402.RLP.encode([[], [[]], [[], [[]]]])
      <<0xC7, 0xC0, 0xC1, 0xC0, 0xC3, 0xC0, 0xC1, 0xC0>>
  """
  @spec encode(item()) :: binary()
  def encode(item) when is_binary(item), do: encode_binary(item)

  def encode(item) when is_integer(item) and item >= 0,
    do: encode_binary(integer_bytes(item))

  def encode(items) when is_list(items) do
    payload = Enum.map_join(items, &encode/1)
    length_prefix(byte_size(payload), 0xC0) <> payload
  end

  @spec encode_binary(binary()) :: binary()
  defp encode_binary(<<byte>> = bytes) when byte < 0x80, do: bytes

  defp encode_binary(bytes), do: length_prefix(byte_size(bytes), 0x80) <> bytes

  @spec length_prefix(non_neg_integer(), 0x80 | 0xC0) :: binary()
  defp length_prefix(length, offset) when length < 56, do: <<offset + length>>

  defp length_prefix(length, offset) do
    length_bytes = integer_bytes(length)
    <<offset + 55 + byte_size(length_bytes)>> <> length_bytes
  end

  # Minimal big-endian representation: zero encodes as the empty string.
  @spec integer_bytes(non_neg_integer()) :: binary()
  defp integer_bytes(0), do: <<>>
  defp integer_bytes(integer), do: :binary.encode_unsigned(integer)
end
