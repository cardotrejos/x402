defmodule X402.Transaction do
  @moduledoc """
  Minimal [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) (type-2)
  transaction encoding and signing digests.

  Built for `X402.Facilitator.Engine`'s settlement path: the facilitator
  assembles a `transferWithAuthorization` call, signs its digest through the
  `X402.Signer` behaviour, and broadcasts the raw transaction via
  `eth_sendRawTransaction`. The module is deliberately narrow — type-2
  transactions only, always with an empty access list — and pure except for
  `digest/1`, which needs the optional `ex_keccak` dependency.

  The signing preimage is `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
  maxFeePerGas, gasLimit, to, value, data, accessList])` and the broadcast
  form appends the signature as `yParity, r, s`. EIP-1559 signatures carry
  `yParity` (`0`/`1`), **not** the legacy `27`/`28` recovery id;
  `encode_signed/2` accepts both and normalizes.

  ## Examples

      iex> tx = %X402.Transaction{
      ...>   chain_id: 1,
      ...>   nonce: 0,
      ...>   max_priority_fee_per_gas: 1,
      ...>   max_fee_per_gas: 2,
      ...>   gas_limit: 21_000,
      ...>   to: "0x1111111111111111111111111111111111111111"
      ...> }
      iex> {:ok, preimage} = X402.Transaction.preimage(tx)
      iex> Base.encode16(preimage, case: :lower)
      "02df0180010282520894111111111111111111111111111111111111111180" <> "80c0"
  """

  alias X402.RLP
  alias X402.Wallet

  @enforce_keys [:chain_id, :nonce, :max_priority_fee_per_gas, :max_fee_per_gas, :gas_limit, :to]
  defstruct [
    :chain_id,
    :nonce,
    :max_priority_fee_per_gas,
    :max_fee_per_gas,
    :gas_limit,
    :to,
    value: 0,
    data: <<>>
  ]

  @typedoc """
  An EIP-1559 transaction.

  `to` is a `0x`-prefixed EVM address, `data` the raw calldata bytes, and all
  quantities non-negative integers in wei / gas units. The access list is
  always empty.
  """
  @type t :: %__MODULE__{
          chain_id: non_neg_integer(),
          nonce: non_neg_integer(),
          max_priority_fee_per_gas: non_neg_integer(),
          max_fee_per_gas: non_neg_integer(),
          gas_limit: non_neg_integer(),
          to: String.t(),
          value: non_neg_integer(),
          data: binary()
        }

  @typedoc "Encoding errors."
  @type error :: :invalid_address | :invalid_transaction | :invalid_signature_format

  @doc since: "0.6.0"
  @doc """
  Returns the unsigned signing preimage: `0x02 || rlp(unsigned fields)`.

  The digest a signer signs is the keccak-256 hash of this preimage — see
  `digest/1`.

  ## Examples

      iex> X402.Transaction.preimage(%X402.Transaction{
      ...>   chain_id: 1,
      ...>   nonce: 0,
      ...>   max_priority_fee_per_gas: 1,
      ...>   max_fee_per_gas: 2,
      ...>   gas_limit: 21_000,
      ...>   to: "0xnope"
      ...> })
      {:error, :invalid_address}
  """
  @spec preimage(t()) :: {:ok, binary()} | {:error, error()}
  def preimage(%__MODULE__{} = transaction) do
    with {:ok, fields} <- unsigned_fields(transaction) do
      {:ok, <<0x02>> <> RLP.encode(fields)}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes the 32-byte signing digest: `keccak256(preimage)`.

  Requires the optional `ex_keccak` dependency and returns
  `{:error, :missing_dependency}` when it is unavailable.
  """
  @spec digest(t()) :: {:ok, <<_::256>>} | {:error, error() | :missing_dependency}
  def digest(%__MODULE__{} = transaction) do
    with {:ok, keccak_module} <- X402.EIP712.keccak_module(),
         {:ok, preimage} <- preimage(transaction) do
      {:ok, keccak_module.hash_256(preimage)}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Encodes the broadcast-ready raw transaction from a 65-byte signature.

  `signature` is `r || s || v` where `v` may be an EIP-1559 `yParity`
  (`0`/`1`) **or** a legacy recovery id (`27`/`28`, as produced by
  `X402.Signer.sign_eip712/3`); both are normalized to `yParity`. `r` and
  `s` are RLP-encoded as integers, so leading zero bytes are stripped per
  the Ethereum convention.

  Returns the raw bytes to submit via `eth_sendRawTransaction` (hex-encode
  with a `0x` prefix first).

  ## Examples

      iex> tx = %X402.Transaction{
      ...>   chain_id: 1,
      ...>   nonce: 0,
      ...>   max_priority_fee_per_gas: 1,
      ...>   max_fee_per_gas: 2,
      ...>   gas_limit: 21_000,
      ...>   to: "0x1111111111111111111111111111111111111111"
      ...> }
      iex> signature = <<1::unsigned-big-integer-size(256), 2::unsigned-big-integer-size(256), 28>>
      iex> {:ok, raw} = X402.Transaction.encode_signed(tx, signature)
      iex> Base.encode16(raw, case: :lower)
      "02e20180010282520894111111111111111111111111111111111111111180" <> "80c0010102"

      iex> tx = %X402.Transaction{
      ...>   chain_id: 1,
      ...>   nonce: 0,
      ...>   max_priority_fee_per_gas: 1,
      ...>   max_fee_per_gas: 2,
      ...>   gas_limit: 21_000,
      ...>   to: "0x1111111111111111111111111111111111111111"
      ...> }
      iex> X402.Transaction.encode_signed(tx, <<0, 1, 2>>)
      {:error, :invalid_signature_format}
  """
  @spec encode_signed(t(), binary()) :: {:ok, binary()} | {:error, error()}
  def encode_signed(%__MODULE__{} = transaction, signature) when is_binary(signature) do
    with {:ok, fields} <- unsigned_fields(transaction),
         {:ok, {y_parity, r, s}} <- split_signature(signature) do
      {:ok, <<0x02>> <> RLP.encode(fields ++ [y_parity, r, s])}
    end
  end

  # -- Field encoding ---------------------------------------------------------

  @spec unsigned_fields(t()) :: {:ok, [RLP.item()]} | {:error, error()}
  defp unsigned_fields(%__MODULE__{} = transaction) do
    with {:ok, to_bytes} <- address_bytes(transaction.to),
         :ok <- validate_quantities(transaction) do
      {:ok,
       [
         transaction.chain_id,
         transaction.nonce,
         transaction.max_priority_fee_per_gas,
         transaction.max_fee_per_gas,
         transaction.gas_limit,
         to_bytes,
         transaction.value,
         transaction.data,
         []
       ]}
    end
  end

  @spec address_bytes(term()) :: {:ok, binary()} | {:error, :invalid_address}
  defp address_bytes(address) when is_binary(address) do
    case Wallet.valid_evm?(address) do
      true ->
        "0x" <> hex = address
        Base.decode16(hex, case: :mixed)

      false ->
        {:error, :invalid_address}
    end
  end

  defp address_bytes(_address), do: {:error, :invalid_address}

  @spec validate_quantities(t()) :: :ok | {:error, :invalid_transaction}
  defp validate_quantities(%__MODULE__{} = transaction) do
    quantities = [
      transaction.chain_id,
      transaction.nonce,
      transaction.max_priority_fee_per_gas,
      transaction.max_fee_per_gas,
      transaction.gas_limit,
      transaction.value
    ]

    case is_binary(transaction.data) and Enum.all?(quantities, &non_neg_integer?/1) do
      true -> :ok
      false -> {:error, :invalid_transaction}
    end
  end

  @spec non_neg_integer?(term()) :: boolean()
  defp non_neg_integer?(value), do: is_integer(value) and value >= 0

  @spec split_signature(binary()) ::
          {:ok, {0 | 1, non_neg_integer(), non_neg_integer()}}
          | {:error, :invalid_signature_format}
  defp split_signature(<<r::binary-size(32), s::binary-size(32), v>>) when v in [0, 1, 27, 28] do
    y_parity =
      case v do
        v when v in [0, 1] -> v
        v -> v - 27
      end

    {:ok, {y_parity, :binary.decode_unsigned(r), :binary.decode_unsigned(s)}}
  end

  defp split_signature(_signature), do: {:error, :invalid_signature_format}
end
