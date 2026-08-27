defmodule X402.Signer.LocalKey do
  @moduledoc """
  `X402.Signer` backed by a raw secp256k1 private key held in memory.

  Requires the optional `ex_secp256k1` and `ex_keccak` dependencies;
  `new/1` returns `{:error, :missing_dependency}` when they are unavailable.

  The struct redacts the private key when inspected, but the key still lives
  in process memory — prefer an external signer implementation (KMS, hardware
  wallet) for production payers holding significant funds.

  ## Examples

      {:ok, signer} = X402.Signer.LocalKey.new("0x" <> String.duplicate("11", 32))
      {:ok, address} = X402.Signer.LocalKey.address(signer)
  """

  @behaviour X402.Signer

  alias X402.EIP3009

  @enforce_keys [:private_key, :address]
  defstruct [:private_key, :address]

  @typedoc "A local secp256k1 signing key with its derived EVM address."
  @type t :: %__MODULE__{private_key: binary(), address: String.t()}

  @doc since: "0.6.0"
  @doc """
  Builds a signer from a 32-byte secp256k1 private key.

  Accepts the raw 32-byte binary or its hex encoding (with or without a
  leading `0x`). The EVM address is derived once at construction.

  Returns `{:error, :invalid_private_key}` for malformed keys and
  `{:error, :missing_dependency}` when the optional `ex_secp256k1` /
  `ex_keccak` dependencies are unavailable.

  ## Examples

      iex> X402.Signer.LocalKey.new("not hex")
      {:error, :invalid_private_key}

      iex> {:ok, signer} = X402.Signer.LocalKey.new("0x" <> String.duplicate("11", 32))
      iex> signer.address
      "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  """
  @spec new(binary()) :: {:ok, t()} | {:error, :invalid_private_key | :missing_dependency}
  def new(private_key) when is_binary(private_key) do
    with {:ok, key_bytes} <- normalize_key(private_key),
         {:ok, address} <- EIP3009.derive_address(key_bytes) do
      {:ok, %__MODULE__{private_key: key_bytes, address: address}}
    end
  end

  def new(_private_key), do: {:error, :invalid_private_key}

  @doc since: "0.6.0"
  @doc """
  Returns the EVM address derived from the private key.
  """
  @impl X402.Signer
  @spec address(t()) :: {:ok, String.t()}
  def address(%__MODULE__{address: address}), do: {:ok, address}

  @doc since: "0.6.0"
  @doc """
  Signs the precomputed EIP-712 digest with the local key.

  The typed data is ignored — a local key can sign the digest directly.
  """
  @impl X402.Signer
  @spec sign_eip712(t(), binary(), X402.Signer.typed_data()) ::
          {:ok, X402.Signer.signature()} | {:error, term()}
  def sign_eip712(%__MODULE__{private_key: private_key}, digest, _typed_data)
      when is_binary(digest) and byte_size(digest) == 32 do
    with {:ok, secp256k1_module} <- secp256k1_module(),
         {:ok, {signature, recovery_id}} <- secp256k1_module.sign_compact(digest, private_key) do
      {:ok, signature <> <<recovery_id + 27>>}
    end
  end

  def sign_eip712(%__MODULE__{}, _digest, _typed_data), do: {:error, :invalid_digest}

  @spec normalize_key(binary()) :: {:ok, binary()} | {:error, :invalid_private_key}
  defp normalize_key(key) when byte_size(key) == 32, do: {:ok, key}
  defp normalize_key("0x" <> hex), do: decode_key_hex(hex)
  defp normalize_key(hex) when byte_size(hex) == 64, do: decode_key_hex(hex)
  defp normalize_key(_key), do: {:error, :invalid_private_key}

  @spec decode_key_hex(binary()) :: {:ok, binary()} | {:error, :invalid_private_key}
  defp decode_key_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, key_bytes} when byte_size(key_bytes) == 32 -> {:ok, key_bytes}
      _decoded -> {:error, :invalid_private_key}
    end
  end

  # Resolved at runtime via Module.concat so the library compiles without the
  # optional dependency (same pattern as X402.Extensions.SIWX.Verifier.Default).
  @spec secp256k1_module() :: {:ok, module()} | {:error, :missing_dependency}
  defp secp256k1_module do
    secp256k1_module = Module.concat(["ExSecp256k1"])

    case Code.ensure_loaded?(secp256k1_module) and
           function_exported?(secp256k1_module, :sign_compact, 2) do
      true -> {:ok, secp256k1_module}
      false -> {:error, :missing_dependency}
    end
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%{address: address}, opts) do
      concat(["#X402.Signer.LocalKey<address: ", to_doc(address, opts), ", ...>"])
    end
  end
end
