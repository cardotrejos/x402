defmodule X402.Extensions.SIWX.Verification do
  @moduledoc false

  # Implements the verification rules of the sign-in-with-x spec for
  # X402.Extensions.SIWX.verify/2: field checks in the spec's order, then
  # signature verification routed by chain family, then single-use nonce
  # consumption. Each failure maps to one invalid_siwx_* code.

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.Challenge
  alias X402.Extensions.SIWX.Message
  alias X402.Extensions.SIWX.Verifier
  alias X402.Wallet

  @default_max_age_seconds 300
  @default_clock_skew_seconds 60
  @nonce_pattern ~r/\A[a-f0-9]{32}\z/
  @evm_signature_pattern ~r/\A0x[0-9a-fA-F]{130}\z/
  @issued_prefix "siwx:issued:"
  @used_prefix "siwx:used:"

  @opts_schema [
    domain: [
      type: :string,
      required: true,
      doc: "The server's configured public host; `domain` must equal it exactly."
    ],
    uri: [
      type: :string,
      required: true,
      doc: """
      The configured URI the proof is bound to; `uri` must equal it exactly
      (a single trailing slash is ignored on both sides).
      """
    ],
    supported_chains: [
      type: {:custom, Challenge, :validate_supported_chains, []},
      required: true,
      doc: "Accepted chains, in the form `X402.Extensions.SIWX.challenge/1` takes."
    ],
    now: [
      type: {:or, [{:struct, DateTime}, nil]},
      default: nil,
      doc: "The current time; `DateTime.utc_now/0` when omitted."
    ],
    max_age_seconds: [
      type: :pos_integer,
      default: @default_max_age_seconds,
      doc: "Maximum age of `issuedAt`."
    ],
    clock_skew_seconds: [
      type: :non_neg_integer,
      default: @default_clock_skew_seconds,
      doc: "Tolerance for an `issuedAt` slightly in the future."
    ],
    nonce_cache: [
      type: {:custom, __MODULE__, :validate_nonce_cache, []},
      default: nil,
      doc: """
      Optional `X402.Extensions.PaymentIdentifier.Cache` adapter tuple
      tracking issued and used nonces. Without it nonces are only checked
      for format and the time window.
      """
    ],
    evm_verifier: [
      type: {:custom, Verifier, :validate_module, []},
      default: Verifier.Default,
      doc: "`X402.Extensions.SIWX.Verifier` for `eip155:*` proofs."
    ],
    ed25519_verifier: [
      type: {:custom, Verifier, :validate_module, []},
      default: Verifier.Ed25519,
      doc: "`X402.Extensions.SIWX.Verifier` for `solana:*` proofs."
    ]
  ]

  @spec opts_schema() :: keyword()
  def opts_schema, do: @opts_schema

  @spec validate_nonce_cache(term()) :: {:ok, Cache.adapter() | nil} | {:error, String.t()}
  def validate_nonce_cache(nil), do: {:ok, nil}

  def validate_nonce_cache(adapter) do
    case Cache.validate_optional_adapter(adapter) do
      :ok -> {:ok, adapter}
      {:error, message} -> {:error, message}
    end
  end

  @spec issued_key(String.t()) :: String.t()
  def issued_key(nonce), do: @issued_prefix <> nonce

  @spec used_key(String.t()) :: String.t()
  def used_key(nonce), do: @used_prefix <> nonce

  @spec verify(SIWX.decoded(), keyword()) ::
          {:ok, SIWX.identity()} | {:error, SIWX.verify_error()}
  def verify(decoded, opts) do
    opts = opts |> NimbleOptions.validate!(@opts_schema) |> Map.new()
    now = opts.now || DateTime.utc_now()

    with {:ok, fields, signed_message} <- normalize(decoded),
         :ok <- check_domain(fields, opts.domain),
         :ok <- check_uri(fields, opts.uri),
         :ok <- check_issued_at(fields, now, opts),
         :ok <- check_expiration(fields, now),
         :ok <- check_not_before(fields, now),
         :ok <- check_nonce_format(fields),
         :ok <- check_nonce_issued(fields, opts.nonce_cache),
         {:ok, family} <- check_chain(fields, opts.supported_chains),
         {:ok, message} <- message(family, fields, signed_message),
         :ok <- check_signature(family, fields, message, opts),
         :ok <- consume_nonce(fields, opts.nonce_cache) do
      {:ok, %{address: fields["address"], chain_id: fields["chainId"], fields: fields}}
    end
  end

  # -- Normalization ----------------------------------------------------------

  # Spec proofs carry their fields; the message is rebuilt from them.
  # Legacy proofs carry the signed text itself, so the signature is checked
  # over that exact text rather than a rebuilt one.
  @spec normalize(SIWX.decoded()) ::
          {:ok, map(), String.t() | nil} | {:error, :invalid_payload}
  defp normalize({:spec, fields}) do
    case SIWX.validate_proof(fields) do
      {:ok, validated} -> {:ok, validated, nil}
      {:error, _reason} -> {:error, :invalid_payload}
    end
  end

  defp normalize({:legacy, %{"message" => message, "signature" => signature}}) do
    case SIWX.decode(message) do
      {:ok, payload} ->
        {:ok,
         %{
           "domain" => payload.domain,
           "address" => payload.address,
           "statement" => payload.statement,
           "uri" => payload.uri,
           "version" => payload.version,
           "chainId" => payload.chain_id,
           "type" => Message.signature_type(:eip155),
           "nonce" => payload.nonce,
           "issuedAt" => payload.issued_at,
           "expirationTime" => payload.expiration_time,
           "signature" => signature
         }, message}

      {:error, _reason} ->
        {:error, :invalid_payload}
    end
  end

  defp normalize(_decoded), do: {:error, :invalid_payload}

  # -- Field checks -----------------------------------------------------------

  @spec check_domain(map(), String.t()) :: :ok | {:error, :invalid_siwx_domain_mismatch}
  defp check_domain(%{"domain" => domain}, domain), do: :ok
  defp check_domain(_fields, _domain), do: {:error, :invalid_siwx_domain_mismatch}

  @spec check_uri(map(), String.t()) :: :ok | {:error, :invalid_siwx_uri_mismatch}
  defp check_uri(%{"uri" => uri}, expected) do
    case trim_slash(uri) == trim_slash(expected) do
      true -> :ok
      false -> {:error, :invalid_siwx_uri_mismatch}
    end
  end

  @spec trim_slash(String.t()) :: String.t()
  defp trim_slash(uri), do: String.replace_suffix(uri, "/", "")

  @spec check_issued_at(map(), DateTime.t(), map()) ::
          :ok
          | {:error,
             :invalid_siwx_issued_at
             | :invalid_siwx_issued_at_too_old
             | :invalid_siwx_issued_at_in_future}
  defp check_issued_at(%{"issuedAt" => issued_at}, now, opts) do
    case parse_datetime(issued_at) do
      {:ok, issued_at} ->
        age = DateTime.diff(now, issued_at, :second)

        cond do
          age < -opts.clock_skew_seconds -> {:error, :invalid_siwx_issued_at_in_future}
          age > opts.max_age_seconds -> {:error, :invalid_siwx_issued_at_too_old}
          true -> :ok
        end

      :error ->
        {:error, :invalid_siwx_issued_at}
    end
  end

  @spec check_expiration(map(), DateTime.t()) ::
          :ok | {:error, :invalid_siwx_expiration_time | :invalid_siwx_expired}
  defp check_expiration(fields, now) do
    case Map.get(fields, "expirationTime") do
      nil ->
        :ok

      value ->
        case parse_datetime(value) do
          {:ok, expiration} -> in_future(expiration, now, :invalid_siwx_expired)
          :error -> {:error, :invalid_siwx_expiration_time}
        end
    end
  end

  @spec in_future(DateTime.t(), DateTime.t(), atom()) :: :ok | {:error, atom()}
  defp in_future(datetime, now, code) do
    case DateTime.compare(datetime, now) do
      :gt -> :ok
      _other -> {:error, code}
    end
  end

  @spec check_not_before(map(), DateTime.t()) ::
          :ok | {:error, :invalid_siwx_not_before | :invalid_siwx_not_yet_valid}
  defp check_not_before(fields, now) do
    case Map.get(fields, "notBefore") do
      nil ->
        :ok

      value ->
        case parse_datetime(value) do
          {:ok, not_before} -> not_after(not_before, now, :invalid_siwx_not_yet_valid)
          :error -> {:error, :invalid_siwx_not_before}
        end
    end
  end

  @spec not_after(DateTime.t(), DateTime.t(), atom()) :: :ok | {:error, atom()}
  defp not_after(datetime, now, code) do
    case DateTime.compare(datetime, now) do
      :gt -> {:error, code}
      _other -> :ok
    end
  end

  @spec parse_datetime(term()) :: {:ok, DateTime.t()} | :error
  defp parse_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      {:error, _reason} -> :error
    end
  end

  defp parse_datetime(_value), do: :error

  @spec check_nonce_format(map()) :: :ok | {:error, :invalid_siwx_nonce}
  defp check_nonce_format(%{"nonce" => nonce}) do
    case Regex.match?(@nonce_pattern, nonce) do
      true -> :ok
      false -> {:error, :invalid_siwx_nonce}
    end
  end

  @spec check_nonce_issued(map(), Cache.adapter() | nil) :: :ok | {:error, :invalid_siwx_nonce}
  defp check_nonce_issued(_fields, nil), do: :ok

  defp check_nonce_issued(%{"nonce" => nonce}, cache) do
    case Cache.get(cache, issued_key(nonce)) do
      {:hit, {:siwx_nonce, :issued}} -> :ok
      _other -> {:error, :invalid_siwx_nonce}
    end
  end

  # The single-use claim is taken only after the signature verified, so an
  # invalid proof can never burn a nonce another request needs.
  @spec consume_nonce(map(), Cache.adapter() | nil) :: :ok | {:error, :invalid_siwx_nonce}
  defp consume_nonce(_fields, nil), do: :ok

  defp consume_nonce(%{"nonce" => nonce}, cache) do
    case Cache.put_new(cache, used_key(nonce), {:siwx_nonce, :used}) do
      :ok -> :ok
      {:error, _reason} -> {:error, :invalid_siwx_nonce}
    end
  end

  # -- Chain and signature ----------------------------------------------------

  @spec check_chain(map(), [map()]) ::
          {:ok, Message.family()}
          | {:error, :invalid_siwx_chain_id | :invalid_siwx_unsupported_chain}
  defp check_chain(%{"chainId" => chain_id, "type" => type}, supported_chains) do
    with {:ok, family} <- chain_family(chain_id),
         :ok <- ensure_supported(chain_id, type, supported_chains) do
      {:ok, family}
    end
  end

  @spec chain_family(String.t()) ::
          {:ok, Message.family()}
          | {:error, :invalid_siwx_chain_id | :invalid_siwx_unsupported_chain}
  defp chain_family(chain_id) do
    case Message.family(chain_id) do
      {:ok, family} -> {:ok, family}
      {:error, :invalid_chain_id} -> {:error, :invalid_siwx_chain_id}
      {:error, :unsupported_chain} -> {:error, :invalid_siwx_unsupported_chain}
    end
  end

  @spec ensure_supported(String.t(), String.t(), [map()]) ::
          :ok | {:error, :invalid_siwx_unsupported_chain}
  defp ensure_supported(chain_id, type, supported_chains) do
    case Enum.any?(supported_chains, &(&1["chainId"] == chain_id and &1["type"] == type)) do
      true -> :ok
      false -> {:error, :invalid_siwx_unsupported_chain}
    end
  end

  @spec message(Message.family(), map(), String.t() | nil) ::
          {:ok, String.t()} | {:error, :invalid_siwx_chain_id | :invalid_siwx_unsupported_chain}
  defp message(_family, _fields, signed_message) when is_binary(signed_message),
    do: {:ok, signed_message}

  defp message(_family, fields, nil) do
    case Message.build(fields) do
      {:ok, message} -> {:ok, message}
      {:error, :invalid_chain_id} -> {:error, :invalid_siwx_chain_id}
      {:error, _reason} -> {:error, :invalid_siwx_unsupported_chain}
    end
  end

  @spec check_signature(Message.family(), map(), String.t(), map()) ::
          :ok
          | {:error,
             :invalid_siwx_signature
             | :invalid_siwx_malformed_signature
             | :invalid_siwx_verifier_error}
  defp check_signature(:eip155, fields, message, opts) do
    with :ok <- ensure_evm_encoding(fields) do
      run_verifier(opts.evm_verifier, message, fields["signature"], fields["address"])
    end
  end

  defp check_signature(:solana, fields, message, opts) do
    with :ok <- ensure_solana_address(fields) do
      run_verifier(opts.ed25519_verifier, message, fields["signature"], fields["address"])
    end
  end

  @spec ensure_evm_encoding(map()) :: :ok | {:error, :invalid_siwx_malformed_signature}
  defp ensure_evm_encoding(%{"address" => address, "signature" => signature}) do
    case Wallet.valid_evm?(address) and Regex.match?(@evm_signature_pattern, signature) do
      true -> :ok
      false -> {:error, :invalid_siwx_malformed_signature}
    end
  end

  @spec ensure_solana_address(map()) :: :ok | {:error, :invalid_siwx_malformed_signature}
  defp ensure_solana_address(%{"address" => address}) do
    case Wallet.valid_solana?(address) do
      true -> :ok
      false -> {:error, :invalid_siwx_malformed_signature}
    end
  end

  # A verifier that raises (RPC client blew up during EIP-1271, for
  # instance) is reported as invalid_siwx_verifier_error, like the spec's
  # "verifier threw" case, rather than crashing the request.
  @spec run_verifier(module(), String.t(), String.t(), String.t()) ::
          :ok
          | {:error,
             :invalid_siwx_signature
             | :invalid_siwx_malformed_signature
             | :invalid_siwx_verifier_error}
  defp run_verifier(verifier, message, signature, address) do
    case verifier.verify_signature(message, signature, address) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, :invalid_siwx_signature}
      {:error, reason} when reason in [:invalid_signature, :malformed_signature] -> malformed()
      {:error, reason} when reason in [:invalid_address, :invalid_arguments] -> malformed()
      {:error, _reason} -> {:error, :invalid_siwx_verifier_error}
      _other -> {:error, :invalid_siwx_verifier_error}
    end
  rescue
    _exception -> {:error, :invalid_siwx_verifier_error}
  end

  @spec malformed() :: {:error, :invalid_siwx_malformed_signature}
  defp malformed, do: {:error, :invalid_siwx_malformed_signature}
end
