defmodule X402.Signer.SolanaKey do
  @moduledoc """
  `X402.Signer` backed by a raw Ed25519 private key held in memory.

  Signs Solana transaction message bytes through OTP's `:crypto` (EdDSA on
  the `ed25519` curve) — no extra dependencies. `new/1` accepts:

  * a raw 32-byte Ed25519 seed
  * a 64-byte Solana keypair (`seed <> public_key`, the `solana-keygen`
    format) — the embedded public key is checked against the derived one
  * the Base64 or Base58 encoding of either

  The struct redacts the private key when inspected, but the key still
  lives in process memory — prefer an external signer implementation (KMS,
  hardware wallet) for production payers holding significant funds.

  ## Examples

      {:ok, signer} = X402.Signer.SolanaKey.new(:crypto.strong_rand_bytes(32))
      {:ok, address} = X402.Signer.SolanaKey.address(signer)
  """

  @behaviour X402.Signer

  alias X402.Base58

  @enforce_keys [:seed, :address]
  defstruct [:seed, :address]

  @typedoc "A local Ed25519 signing key with its derived Solana address."
  @type t :: %__MODULE__{seed: binary(), address: String.t()}

  @doc since: "0.6.0"
  @doc """
  Builds a signer from an Ed25519 seed or Solana keypair.

  Returns `{:error, :invalid_private_key}` for malformed keys and for
  64-byte keypairs whose public half does not match the seed.

  ## Examples

      iex> {:ok, signer} = X402.Signer.SolanaKey.new(:binary.copy(<<1>>, 32))
      iex> signer.address
      "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"

      iex> X402.Signer.SolanaKey.new("not a key")
      {:error, :invalid_private_key}
  """
  @spec new(binary()) :: {:ok, t()} | {:error, :invalid_private_key}
  def new(private_key) when is_binary(private_key) do
    with {:ok, seed, expected_public} <- normalize_key(private_key) do
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)

      case expected_public == nil or expected_public == public do
        true -> {:ok, %__MODULE__{seed: seed, address: Base58.encode(public)}}
        false -> {:error, :invalid_private_key}
      end
    end
  end

  def new(_private_key), do: {:error, :invalid_private_key}

  @doc since: "0.6.0"
  @doc """
  Returns the Base58 Solana address derived from the private key.
  """
  @impl X402.Signer
  @spec address(t()) :: {:ok, String.t()}
  def address(%__MODULE__{address: address}), do: {:ok, address}

  @doc since: "0.6.0"
  @doc """
  Signs `message` with the local Ed25519 key.

  Ed25519 signing is deterministic (RFC 8032), so the same key and message
  always produce the same 64-byte signature.
  """
  @impl X402.Signer
  @spec sign_ed25519(t(), binary()) :: {:ok, X402.Signer.ed25519_signature()}
  def sign_ed25519(%__MODULE__{seed: seed}, message) when is_binary(message) do
    {:ok, :crypto.sign(:eddsa, :none, message, [seed, :ed25519])}
  end

  @spec normalize_key(binary()) ::
          {:ok, binary(), binary() | nil} | {:error, :invalid_private_key}
  defp normalize_key(<<seed::binary-size(32)>>), do: {:ok, seed, nil}

  defp normalize_key(<<seed::binary-size(32), public::binary-size(32)>>),
    do: {:ok, seed, public}

  defp normalize_key(encoded) do
    case decode_key(encoded) do
      {:ok, raw} when byte_size(raw) in [32, 64] -> normalize_key(raw)
      _other -> {:error, :invalid_private_key}
    end
  end

  # Base58 is tried FIRST: typical Base58 secrets (44/88 characters —
  # Phantom exports, solana-keygen) are also valid Base64 lengths, so a
  # Base64-first decode "succeeds" with 33/66 garbage bytes and the real
  # Base58 form is never tried. Only decodes yielding a valid key size are
  # accepted from either alphabet; ambiguous strings resolve as Base58, the
  # Solana convention.
  @spec decode_key(binary()) :: {:ok, binary()} | :error
  defp decode_key(encoded) do
    case decode_sized(&Base58.decode/1, encoded) do
      {:ok, raw} -> {:ok, raw}
      :error -> decode_sized(&Base.decode64/1, encoded)
    end
  end

  @spec decode_sized((binary() -> {:ok, binary()} | :error), binary()) ::
          {:ok, binary()} | :error
  defp decode_sized(decoder, encoded) do
    case decoder.(encoded) do
      {:ok, raw} when byte_size(raw) in [32, 64] -> {:ok, raw}
      _other -> :error
    end
  end

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(%{address: address}, opts) do
      concat(["#X402.Signer.SolanaKey<address: ", to_doc(address, opts), ", ...>"])
    end
  end
end
