defmodule X402.ERC6492 do
  @moduledoc """
  ERC-6492 signature wrapper parsing and building.

  [ERC-6492](https://eips.ethereum.org/EIPS/eip-6492) lets a not-yet-deployed
  ("counterfactual") smart wallet produce a verifiable signature by wrapping
  the wallet's inner signature together with the factory call that would
  deploy it:

      abi.encode((factory, factoryCalldata, innerSignature)) || magic_suffix

  where the magic suffix is the 32-byte value `0x6492...6492`.

  This module is pure binary handling — no cryptography and no RPC. Whether a
  wrapped signature is actually *valid* is decided by `X402.Verify.EVM`:
  a counterfactual signature is never accepted until an on-chain simulation
  proves the deployed wallet would accept it (fail-closed, mirroring the
  reference Go implementation).
  """

  @magic_suffix :binary.copy(<<0x64, 0x92>>, 16)

  @zero_address "0x" <> String.duplicate("0", 40)

  @typedoc """
  A parsed signature.

  `wrapped?` is `true` when the ERC-6492 magic suffix was present. `factory`
  and `factory_calldata` are `nil` unless the wrapper carried deployment
  information (a non-zero factory address with non-empty calldata).
  `inner_signature` is the raw signature bytes — the unwrapped inner
  signature for wrapped input, the input itself otherwise.
  """
  @type parsed :: %{
          wrapped?: boolean(),
          factory: String.t() | nil,
          factory_calldata: binary() | nil,
          inner_signature: binary()
        }

  @doc since: "0.6.0"
  @doc """
  Returns the 32-byte ERC-6492 magic suffix.

  ## Examples

      iex> byte_size(X402.ERC6492.magic_suffix())
      32
  """
  @spec magic_suffix() :: <<_::256>>
  def magic_suffix, do: @magic_suffix

  @doc since: "0.6.0"
  @doc """
  Returns `true` when the signature carries the ERC-6492 magic suffix.

  Accepts raw bytes or a `0x`-prefixed hex string.

  ## Examples

      iex> X402.ERC6492.wrapped?(<<1, 2, 3>>)
      false

      iex> {:ok, wrapped} =
      ...>   X402.ERC6492.wrap(
      ...>     "0x2222222222222222222222222222222222222222",
      ...>     <<0xAB>>,
      ...>     :binary.copy(<<0x01>>, 65)
      ...>   )
      iex> X402.ERC6492.wrapped?(wrapped)
      true
  """
  @spec wrapped?(binary()) :: boolean()
  def wrapped?(signature) when is_binary(signature) do
    case decode_signature_bytes(signature) do
      {:ok, bytes} -> magic_suffix?(bytes)
      {:error, _reason} -> false
    end
  end

  @doc since: "0.6.0"
  @doc """
  Parses a signature, unwrapping the ERC-6492 envelope when present.

  Accepts raw bytes or a `0x`-prefixed hex string. Signatures without the
  magic suffix parse as `wrapped?: false` with the bytes passed through as
  `inner_signature`. A wrapper whose factory is the zero address or whose
  calldata is empty parses with `factory: nil` (no deployment information),
  matching the reference implementations.

  Returns `{:error, :invalid_erc6492_wrapper}` when the magic suffix is
  present but the ABI-encoded prefix is malformed, and
  `{:error, :invalid_signature}` for non-hex string input.

  ## Examples

      iex> {:ok, parsed} = X402.ERC6492.parse(:binary.copy(<<0x01>>, 65))
      iex> {parsed.wrapped?, parsed.factory, byte_size(parsed.inner_signature)}
      {false, nil, 65}

      iex> inner = :binary.copy(<<0x07>>, 65)
      iex> {:ok, wrapped} =
      ...>   X402.ERC6492.wrap("0x2222222222222222222222222222222222222222", <<0xAB, 0xCD>>, inner)
      iex> {:ok, parsed} = X402.ERC6492.parse(wrapped)
      iex> {parsed.wrapped?, parsed.factory, parsed.factory_calldata, parsed.inner_signature}
      {true, "0x2222222222222222222222222222222222222222", <<0xAB, 0xCD>>, inner}

      iex> X402.ERC6492.parse("0xzz")
      {:error, :invalid_signature}
  """
  @spec parse(binary()) ::
          {:ok, parsed()} | {:error, :invalid_signature | :invalid_erc6492_wrapper}
  def parse(signature) when is_binary(signature) do
    with {:ok, bytes} <- decode_signature_bytes(signature) do
      case magic_suffix?(bytes) do
        true ->
          parse_wrapper(binary_part(bytes, 0, byte_size(bytes) - 32))

        false ->
          {:ok, %{wrapped?: false, factory: nil, factory_calldata: nil, inner_signature: bytes}}
      end
    end
  end

  @doc since: "0.6.0"
  @doc """
  Builds an ERC-6492 wrapped signature from its parts.

  `factory` is a `0x`-prefixed EVM address; `factory_calldata` and
  `inner_signature` are raw bytes. Returns the raw wrapped bytes
  (`abi.encode((address, bytes, bytes)) || magic_suffix`).

  ## Examples

      iex> {:ok, wrapped} =
      ...>   X402.ERC6492.wrap(
      ...>     "0x2222222222222222222222222222222222222222",
      ...>     <<0xAB>>,
      ...>     :binary.copy(<<0x01>>, 65)
      ...>   )
      iex> X402.ERC6492.wrapped?(wrapped)
      true

      iex> X402.ERC6492.wrap("0x123", <<>>, <<>>)
      {:error, :invalid_address}
  """
  @spec wrap(String.t(), binary(), binary()) :: {:ok, binary()} | {:error, :invalid_address}
  def wrap(factory, factory_calldata, inner_signature)
      when is_binary(factory) and is_binary(factory_calldata) and is_binary(inner_signature) do
    with {:ok, factory_word} <- X402.EIP712.encode_address(factory) do
      calldata_offset = 3 * 32
      signature_offset = calldata_offset + 32 + padded_size(factory_calldata)

      encoded =
        factory_word <>
          <<calldata_offset::unsigned-big-integer-size(256)>> <>
          <<signature_offset::unsigned-big-integer-size(256)>> <>
          encode_dynamic_bytes(factory_calldata) <>
          encode_dynamic_bytes(inner_signature) <>
          @magic_suffix

      {:ok, encoded}
    end
  end

  # -- Wrapper decoding -------------------------------------------------------

  @spec parse_wrapper(binary()) :: {:ok, parsed()} | {:error, :invalid_erc6492_wrapper}
  defp parse_wrapper(
         <<0::unsigned-big-integer-size(96), factory_bytes::binary-size(20),
           calldata_offset::unsigned-big-integer-size(256),
           signature_offset::unsigned-big-integer-size(256), _rest::binary>> = encoded
       ) do
    with {:ok, factory_calldata} <- decode_dynamic_bytes(encoded, calldata_offset),
         {:ok, inner_signature} <- decode_dynamic_bytes(encoded, signature_offset) do
      factory = "0x" <> Base.encode16(factory_bytes, case: :lower)

      case factory != @zero_address and factory_calldata != <<>> do
        true ->
          {:ok,
           %{
             wrapped?: true,
             factory: factory,
             factory_calldata: factory_calldata,
             inner_signature: inner_signature
           }}

        false ->
          {:ok,
           %{
             wrapped?: true,
             factory: nil,
             factory_calldata: nil,
             inner_signature: inner_signature
           }}
      end
    end
  end

  defp parse_wrapper(_encoded), do: {:error, :invalid_erc6492_wrapper}

  @spec decode_dynamic_bytes(binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :invalid_erc6492_wrapper}
  defp decode_dynamic_bytes(encoded, offset)
       when is_integer(offset) and offset + 32 <= byte_size(encoded) do
    <<length::unsigned-big-integer-size(256)>> = binary_part(encoded, offset, 32)

    case offset + 32 + length <= byte_size(encoded) do
      true -> {:ok, binary_part(encoded, offset + 32, length)}
      false -> {:error, :invalid_erc6492_wrapper}
    end
  end

  defp decode_dynamic_bytes(_encoded, _offset), do: {:error, :invalid_erc6492_wrapper}

  # -- Encoding helpers -------------------------------------------------------

  @spec encode_dynamic_bytes(binary()) :: binary()
  defp encode_dynamic_bytes(bytes) do
    <<byte_size(bytes)::unsigned-big-integer-size(256)>> <> pad_right(bytes)
  end

  @spec pad_right(binary()) :: binary()
  defp pad_right(bytes) do
    case rem(byte_size(bytes), 32) do
      0 -> bytes
      remainder -> bytes <> :binary.copy(<<0>>, 32 - remainder)
    end
  end

  @spec padded_size(binary()) :: non_neg_integer()
  defp padded_size(bytes), do: byte_size(pad_right(bytes))

  # -- Input decoding ---------------------------------------------------------

  @spec decode_signature_bytes(binary()) :: {:ok, binary()} | {:error, :invalid_signature}
  defp decode_signature_bytes("0x" <> hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_signature}
    end
  end

  defp decode_signature_bytes(bytes) when is_binary(bytes), do: {:ok, bytes}

  @spec magic_suffix?(binary()) :: boolean()
  defp magic_suffix?(bytes) when byte_size(bytes) >= 32 do
    binary_part(bytes, byte_size(bytes) - 32, 32) == @magic_suffix
  end

  defp magic_suffix?(_bytes), do: false
end
