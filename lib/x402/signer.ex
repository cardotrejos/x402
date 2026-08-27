defmodule X402.Signer do
  @moduledoc """
  Behaviour for client-side payment signers.

  A signer produces the cryptographic signatures a payer client needs to
  authorize x402 payments. Implementations are structs whose module implements
  this behaviour; the library dispatches on the struct's module, so custom
  signers (KMS-backed, hardware wallets, remote signing services) can be
  supplied anywhere the library takes a signer.

  ## Callback design

  The reference SDKs expose two shapes: the TypeScript `ClientEvmSigner`
  signs full EIP-712 *typed data* (`signTypedData`), because wallet-backed and
  remote signers refuse raw digests, while the Go client signer signs the
  precomputed EIP-712 *digest* from a local private key. This behaviour
  supports both: `c:sign_eip712/3` receives the precomputed 32-byte digest
  (sufficient for local keys and raw-signing KMS APIs) *and* the full typed
  data map (domain/types/primaryType/message, mirroring the EIP-712 JSON
  representation) for implementations that must reconstruct the message.

  Implementations return the raw 65-byte `r || s || v` signature. `v` may be
  `0`/`1` or `27`/`28`; the dispatcher normalizes it to `27`/`28` as expected
  by EIP-3009 contracts.

  ## Built-in implementation

  `X402.Signer.LocalKey` signs with a raw secp256k1 private key and requires
  the optional `ex_secp256k1` and `ex_keccak` dependencies.
  """

  @typedoc "A struct whose module implements `X402.Signer`."
  @type t :: struct()

  @typedoc """
  EIP-712 typed data in its JSON representation.

  Contains the `"domain"`, `"types"`, `"primaryType"`, and `"message"` keys.
  """
  @type typed_data :: map()

  @typedoc "A raw 65-byte `r || s || v` signature."
  @type signature :: <<_::520>>

  @doc """
  Returns the signer's payment address (for EVM, a `0x`-prefixed hex address).
  """
  @callback address(signer :: t()) :: {:ok, String.t()} | {:error, term()}

  @doc """
  Signs an EIP-712 digest and returns the 65-byte `r || s || v` signature.

  `digest` is the precomputed 32-byte EIP-712 digest
  (`keccak256(0x19 0x01 || domainSeparator || structHash)`). `typed_data` is
  the full EIP-712 typed data for implementations that cannot sign raw
  digests.
  """
  @callback sign_eip712(signer :: t(), digest :: binary(), typed_data :: typed_data()) ::
              {:ok, signature()} | {:error, term()}

  @doc since: "0.6.0"
  @doc """
  Returns the address of a signer, dispatching on its struct module.

  ## Examples

      iex> X402.Signer.address(:not_a_signer)
      {:error, :invalid_signer}
  """
  @spec address(t()) :: {:ok, String.t()} | {:error, term()}
  def address(%module{} = signer), do: module.address(signer)
  def address(_signer), do: {:error, :invalid_signer}

  @doc since: "0.6.0"
  @doc """
  Signs an EIP-712 digest with a signer, dispatching on its struct module.

  Normalizes the recovery byte to `27`/`28` and rejects signatures that are
  not 65 bytes with `{:error, :invalid_signature_format}`.

  ## Examples

      iex> X402.Signer.sign_eip712(:not_a_signer, <<0::256>>, %{})
      {:error, :invalid_signer}
  """
  @spec sign_eip712(t(), binary(), typed_data()) :: {:ok, signature()} | {:error, term()}
  def sign_eip712(%module{} = signer, digest, typed_data)
      when is_binary(digest) and is_map(typed_data) do
    with {:ok, signature} <- module.sign_eip712(signer, digest, typed_data) do
      normalize_signature(signature)
    end
  end

  def sign_eip712(_signer, _digest, _typed_data), do: {:error, :invalid_signer}

  @spec normalize_signature(term()) :: {:ok, signature()} | {:error, :invalid_signature_format}
  defp normalize_signature(<<compact::binary-size(64), v>>) when v in [0, 1],
    do: {:ok, compact <> <<v + 27>>}

  defp normalize_signature(<<_compact::binary-size(64), v>> = signature) when v in [27, 28],
    do: {:ok, signature}

  defp normalize_signature(_signature), do: {:error, :invalid_signature_format}
end
