defmodule X402.TestRLPDecoder do
  @moduledoc false

  # Minimal reference RLP decoder used only by tests, to prove the library's
  # pure encoder (`X402.RLP` / `X402.Transaction`) against independently
  # decoded structures: settlement tests decode the exact signed raw
  # transaction the engine broadcasts and assert every field.

  @doc """
  Decodes one RLP item, returning `{item, rest}` where an item is a binary
  or a (nested) list of items.
  """
  @spec decode(binary()) :: {binary() | list(), binary()}
  def decode(<<byte, rest::binary>>) when byte < 0x80, do: {<<byte>>, rest}

  def decode(<<byte, rest::binary>>) when byte <= 0xB7 do
    length = byte - 0x80
    <<payload::binary-size(length), rest::binary>> = rest
    {payload, rest}
  end

  def decode(<<byte, rest::binary>>) when byte <= 0xBF do
    length_size = byte - 0xB7
    <<length::unsigned-big-integer-size(length_size)-unit(8), rest::binary>> = rest
    <<payload::binary-size(length), rest::binary>> = rest
    {payload, rest}
  end

  def decode(<<byte, rest::binary>>) when byte <= 0xF7 do
    length = byte - 0xC0
    <<payload::binary-size(length), rest::binary>> = rest
    {decode_list(payload, []), rest}
  end

  def decode(<<byte, rest::binary>>) do
    length_size = byte - 0xF7
    <<length::unsigned-big-integer-size(length_size)-unit(8), rest::binary>> = rest
    <<payload::binary-size(length), rest::binary>> = rest
    {decode_list(payload, []), rest}
  end

  @doc """
  Decodes an EIP-1559 raw transaction (`0x02 || rlp([...])`) into its
  twelve signed fields, as minimal-big-endian binaries.
  """
  @spec decode_eip1559(binary()) :: [binary() | list()]
  def decode_eip1559(<<0x02, rlp::binary>>) do
    {fields, <<>>} = decode(rlp)
    fields
  end

  @spec decode_list(binary(), [binary() | list()]) :: [binary() | list()]
  defp decode_list(<<>>, acc), do: Enum.reverse(acc)

  defp decode_list(payload, acc) do
    {item, rest} = decode(payload)
    decode_list(rest, [item | acc])
  end
end
