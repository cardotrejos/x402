defmodule X402.Extensions.SIWX.Verifier.Ed25519 do
  @moduledoc """
  SIWX signature verifier for Solana (`solana:*`) wallets.

  Verifies the Ed25519 signature over the Sign-In-With-Solana message text
  through OTP's `:crypto` — no extra dependencies. The signature and the
  address are the Base58 encodings Solana wallets produce: a 64-byte
  signature and a 32-byte public key.
  """

  @behaviour X402.Extensions.SIWX.Verifier

  alias X402.Base58

  # The eight canonical small-order point encodings (the 8-torsion subgroup
  # of the Ed25519 curve). A signature under one of these "public keys"
  # can be forged for any message by classic verifiers, so they are refused
  # before touching :crypto — the same guard the reference SIWS verifier
  # applies.
  @small_order_points [
    <<1, 0::248>>,
    <<0::256>>,
    <<0::248, 0x80>>,
    <<0xEC, 0xFF::integer-size(240), 0x7F>>,
    Base.decode16!("C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A"),
    Base.decode16!("C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA"),
    Base.decode16!("26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05"),
    Base.decode16!("26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85")
  ]

  @doc since: "0.9.0"
  @doc """
  Verifies a Base58 Ed25519 signature over `message` for a Base58 address.

  Returns `{:ok, true}` when the signature verifies under the public key the
  address encodes, `{:ok, false}` when it does not, and
  `{:error, :malformed_signature}` / `{:error, :invalid_address}` when the
  Base58 encodings or byte lengths are wrong.

  ## Examples

      iex> X402.Extensions.SIWX.Verifier.Ed25519.verify_signature("hello", "not base58 0", "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9")
      {:error, :malformed_signature}

      iex> X402.Extensions.SIWX.Verifier.Ed25519.verify_signature("hello", "1111", "too-short")
      {:error, :invalid_address}
  """
  @impl true
  @spec verify_signature(String.t(), String.t(), String.t()) ::
          {:ok, boolean()}
          | {:error, :malformed_signature | :invalid_address | :invalid_arguments}
  def verify_signature(message, signature, address)
      when is_binary(message) and is_binary(signature) and is_binary(address) do
    with {:ok, public_key} <- decode_public_key(address),
         {:ok, signature_bytes} <- decode_signature(signature) do
      case public_key in @small_order_points do
        true ->
          {:ok, false}

        false ->
          {:ok, :crypto.verify(:eddsa, :none, message, signature_bytes, [public_key, :ed25519])}
      end
    end
  end

  def verify_signature(_message, _signature, _address), do: {:error, :invalid_arguments}

  @spec decode_public_key(String.t()) :: {:ok, <<_::256>>} | {:error, :invalid_address}
  defp decode_public_key(address) do
    case Base58.decode(address) do
      {:ok, <<public_key::binary-size(32)>>} -> {:ok, public_key}
      _other -> {:error, :invalid_address}
    end
  end

  @spec decode_signature(String.t()) :: {:ok, <<_::512>>} | {:error, :malformed_signature}
  defp decode_signature(signature) do
    case Base58.decode(signature) do
      {:ok, <<signature_bytes::binary-size(64)>>} -> {:ok, signature_bytes}
      _other -> {:error, :malformed_signature}
    end
  end
end
