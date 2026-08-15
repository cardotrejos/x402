defmodule X402.Extensions.SIWX.Verifier.Default do
  @moduledoc """
  Default EVM SIWX signature verifier using `ex_secp256k1`.

  Signatures are verified using Ethereum's personal-sign hashing convention
  (`EIP-191`) and secp256k1 public-key recovery.
  """

  @behaviour X402.Extensions.SIWX.Verifier

  alias X402.Wallet

  @eth_sign_prefix "\x19Ethereum Signed Message:\n"

  @doc since: "0.3.0"
  @doc """
  Verifies a SIWX signature for an EVM address.

  Returns `{:ok, true}` when the recovered signer address matches the provided
  address (case-insensitive). Returns `{:error, :missing_dependency}` when the
  optional `ex_secp256k1` or `ex_keccak` dependency is unavailable.

  ## Examples

      iex> X402.Extensions.SIWX.Verifier.Default.verify_signature("hello", "0x1234", "0x1111111111111111111111111111111111111111")
      {:error, :invalid_signature}
  """
  @impl true
  @spec verify_signature(String.t(), String.t(), String.t()) ::
          {:ok, boolean()} | {:error, term()}
  def verify_signature(message, signature, address)
      when is_binary(message) and is_binary(signature) and is_binary(address) do
    with :ok <- validate_address(address),
         {:ok, compact_signature, recovery_id} <- decode_signature(signature),
         {:ok, secp256k1_module, keccak_module} <- crypto_modules(),
         message_hash <- message_hash(message, keccak_module),
         {:ok, public_key} <-
           secp256k1_module.recover_compact(message_hash, compact_signature, recovery_id),
         {:ok, recovered_address} <- public_key_to_address(public_key, keccak_module) do
      {:ok, String.downcase(recovered_address) == String.downcase(address)}
    else
      {:error, :recovery_failure} -> {:ok, false}
      {:error, reason} -> {:error, reason}
    end
  end

  def verify_signature(_message, _signature, _address), do: {:error, :invalid_arguments}

  @spec validate_address(String.t()) :: :ok | {:error, :invalid_address}
  defp validate_address(address) do
    case Wallet.valid_evm?(address) do
      true -> :ok
      false -> {:error, :invalid_address}
    end
  end

  @spec decode_signature(String.t()) :: {:ok, binary(), 0 | 1} | {:error, :invalid_signature}
  defp decode_signature(signature) do
    with {:ok, signature_binary} <- decode_signature_hex(signature),
         <<compact_signature::binary-size(64), recovery_byte::unsigned-integer-size(8)>> <-
           signature_binary,
         {:ok, recovery_id} <- normalize_recovery_id(recovery_byte) do
      {:ok, compact_signature, recovery_id}
    else
      _ -> {:error, :invalid_signature}
    end
  end

  @spec decode_signature_hex(String.t()) :: {:ok, binary()} | {:error, :invalid_signature}
  defp decode_signature_hex("0x" <> encoded), do: decode_signature_hex(encoded)

  defp decode_signature_hex(encoded) do
    case Base.decode16(encoded, case: :mixed) do
      {:ok, signature_binary} when byte_size(signature_binary) == 65 -> {:ok, signature_binary}
      _ -> {:error, :invalid_signature}
    end
  end

  @spec normalize_recovery_id(non_neg_integer()) :: {:ok, 0 | 1} | {:error, :invalid_signature}
  defp normalize_recovery_id(recovery_id) when recovery_id in [0, 1], do: {:ok, recovery_id}

  defp normalize_recovery_id(recovery_id) when recovery_id in [27, 28],
    do: {:ok, recovery_id - 27}

  defp normalize_recovery_id(recovery_id) when recovery_id >= 35 do
    {:ok, rem(recovery_id - 35, 2)}
  end

  defp normalize_recovery_id(_recovery_id), do: {:error, :invalid_signature}

  @spec crypto_modules() :: {:ok, module(), module()} | {:error, :missing_dependency}
  defp crypto_modules do
    secp256k1_module = Module.concat(["ExSecp256k1"])
    keccak_module = Module.concat(["ExKeccak"])

    case Code.ensure_loaded?(secp256k1_module) and
           function_exported?(secp256k1_module, :recover_compact, 3) and
           Code.ensure_loaded?(keccak_module) and function_exported?(keccak_module, :hash_256, 1) do
      true -> {:ok, secp256k1_module, keccak_module}
      false -> {:error, :missing_dependency}
    end
  end

  @spec message_hash(String.t(), module()) :: binary()
  defp message_hash(message, keccak_module) do
    prefixed = @eth_sign_prefix <> Integer.to_string(byte_size(message)) <> message
    keccak_module.hash_256(prefixed)
  end

  @spec public_key_to_address(binary(), module()) ::
          {:ok, String.t()} | {:error, :invalid_public_key}
  defp public_key_to_address(<<4, public_key::binary-size(64)>>, keccak_module),
    do: hashed_public_key_to_address(public_key, keccak_module)

  defp public_key_to_address(<<public_key::binary-size(64)>>, keccak_module),
    do: hashed_public_key_to_address(public_key, keccak_module)

  defp public_key_to_address(_public_key, _keccak_module), do: {:error, :invalid_public_key}

  @spec hashed_public_key_to_address(binary(), module()) :: {:ok, String.t()}
  defp hashed_public_key_to_address(public_key, keccak_module) do
    hash = keccak_module.hash_256(public_key)
    address = binary_part(hash, byte_size(hash) - 20, 20)
    {:ok, "0x" <> Base.encode16(address, case: :lower)}
  end
end
