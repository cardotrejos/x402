defmodule X402.Client.SIWX do
  @opts_schema [
    chain_id: [
      type: {:or, [:string, {:in, [:auto]}]},
      required: true,
      doc: """
      CAIP-2 chain to sign for, or `:auto` to pick the first advertised
      `supportedChains` entry the signer can sign (EVM signers map to
      `eip155:*`, Solana signers to `solana:*`).
      """
    ],
    address: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Address placed in the proof; the signer's address when omitted."
    ],
    signature_scheme: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Optional `signatureScheme` hint copied into the proof."
    ],
    domain: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: """
      Expected challenge `domain`. Required for transports without a
      resource URL (MCP); for HTTP it defaults to the resource URL's host.
      """
    ]
  ]

  @moduledoc """
  Client side of the `sign-in-with-x` extension: answering a challenge.

  When a server advertises a Sign-In-With-X challenge under
  `PaymentRequired.extensions["sign-in-with-x"]`, a client that has already
  paid for the resource can prove control of its wallet instead of paying
  again. `authenticate/4` picks the chain to sign for, refuses challenges
  that are not bound to the resource's origin, signs the CAIP-122 message
  with `X402.Extensions.SIWX.sign/3`, and returns the `SIGN-IN-WITH-X`
  header value. `X402.Client.Finch` and `X402.MCP.Client` drive the full
  flow through their `:siwx` option; use this module directly with any
  other transport.

  ## Options

  The `:siwx` option of the drivers is a keyword list:

  #{NimbleOptions.docs(@opts_schema)}
  """

  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.Message
  alias X402.Signer
  alias X402.Telemetry
  alias X402.Utils

  @typedoc "Validated `:siwx` driver options."
  @type opts :: [
          chain_id: String.t() | :auto,
          address: String.t() | nil,
          signature_scheme: String.t() | nil,
          domain: String.t() | nil
        ]

  @typedoc "A signed challenge, ready to send."
  @type proof :: %{header: String.t(), chain_id: String.t(), address: String.t()}

  @typedoc "Errors returned by `authenticate/4`, wrapped as `{:siwx, reason}`."
  @type reason ::
          :invalid_challenge
          | :domain_mismatch
          | :uri_mismatch
          | :unsupported_chain
          | SIWX.sign_error()
          | SIWX.signed_encode_error()

  @doc since: "0.8.0"
  @doc """
  Validates a driver's `:siwx` option.

  `nil` and `false` disable automatic Sign-In-With-X; a keyword list is
  validated against the options above. Designed for `NimbleOptions` custom
  validation.

  ## Examples

      iex> X402.Client.SIWX.validate_opts(false)
      {:ok, nil}

      iex> {:ok, opts} = X402.Client.SIWX.validate_opts(chain_id: :auto)
      iex> Enum.sort(opts)
      [address: nil, chain_id: :auto, domain: nil, signature_scheme: nil]

      iex> {:error, message} = X402.Client.SIWX.validate_opts(address: "0xabc")
      iex> message =~ ":chain_id"
      true
  """
  @spec validate_opts(term()) :: {:ok, opts() | nil} | {:error, String.t()}
  def validate_opts(disabled) when disabled in [nil, false], do: {:ok, nil}

  def validate_opts(opts) when is_list(opts) do
    case NimbleOptions.validate(opts, @opts_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, %NimbleOptions.ValidationError{message: message}} -> {:error, message}
    end
  end

  def validate_opts(_opts), do: {:error, "expected nil, false, or a keyword list"}

  @doc since: "0.8.0"
  @doc """
  Fetches the advertised challenge from a `PaymentRequired` map.

  ## Examples

      iex> challenge = %{"info" => %{"domain" => "api.example.com"}, "supportedChains" => []}
      iex> payment_required = %{"x402Version" => 2, "accepts" => [], "extensions" => %{"sign-in-with-x" => challenge}}
      iex> X402.Client.SIWX.fetch_challenge(payment_required)
      {:ok, challenge}

      iex> X402.Client.SIWX.fetch_challenge(%{"x402Version" => 2, "accepts" => []})
      :error
  """
  @spec fetch_challenge(map()) :: {:ok, map()} | :error
  def fetch_challenge(payment_required) when is_map(payment_required) do
    with extensions when is_map(extensions) <-
           Utils.map_value(payment_required, {"extensions", :extensions}),
         %{} = challenge <- Map.get(extensions, SIWX.extension_key()) do
      {:ok, challenge}
    else
      _absent -> :error
    end
  end

  def fetch_challenge(_payment_required), do: :error

  @doc since: "0.8.0"
  @doc """
  Signs the challenge advertised in a `PaymentRequired` map.

  Returns `:none` when the server advertised no `sign-in-with-x`
  challenge, `{:ok, proof}` with the `SIGN-IN-WITH-X` header value once
  signed, or `{:error, {:siwx, reason}}`.

  Before signing, the challenge is checked against the resource it was
  issued for, as the spec requires: its `info.domain` must equal (ignoring case)
  `siwx_opts[:domain]` when given, otherwise the host (optionally with
  port) of `:resource_url`; and, when `:resource_url` is given, the origin
  (scheme, host, port) of `info.uri` must equal the URL's origin. Failures
  are reported as `:domain_mismatch` / `:uri_mismatch`. With neither a
  trusted domain nor a resource URL, signing fails with `:domain_mismatch`.
  Never derive the expected domain from the untrusted challenge.

  With `chain_id: :auto` the first entry of `supportedChains` whose family
  the signer can sign is used (`eip155:*` needs `c:X402.Signer.sign_message/2`,
  `solana:*` needs `c:X402.Signer.sign_ed25519/2`); no match yields
  `:unsupported_chain`. Signing errors from `X402.Extensions.SIWX.sign/3`
  are returned as they are.

  Emits `[:x402, :client, :siwx]` with `status: :error` on failure; the
  drivers emit the `:ok` event once they know the outcome.

  ## Options

  * `:resource_url` — the URL that returned the 402, for the origin check.

  ## Examples

      iex> {:ok, signer} = X402.Signer.SolanaKey.new(:binary.copy(<<1>>, 32))
      iex> challenge = X402.Extensions.SIWX.challenge(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "eip155:8453"}, %{chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}]
      ...> )
      iex> payment_required = %{"x402Version" => 2, "accepts" => [], "extensions" => %{"sign-in-with-x" => challenge}}
      iex> {:ok, proof} = X402.Client.SIWX.authenticate(payment_required, signer, [chain_id: :auto],
      ...>   resource_url: "https://api.example.com/premium")
      iex> {proof.chain_id, proof.address}
      {"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"}
      iex> {:ok, {:spec, fields}} = X402.Extensions.SIWX.decode_signed(proof.header)
      iex> fields["nonce"] == challenge["info"]["nonce"]
      true

      iex> X402.Client.SIWX.authenticate(%{"x402Version" => 2, "accepts" => []}, :signer, chain_id: :auto)
      :none
  """
  @spec authenticate(map(), Signer.t(), keyword(), keyword()) ::
          {:ok, proof()} | :none | {:error, {:siwx, reason()}}
  def authenticate(payment_required, signer, siwx_opts, opts \\ [])
      when is_map(payment_required) and is_list(siwx_opts) and is_list(opts) do
    case fetch_challenge(payment_required) do
      {:ok, challenge} ->
        challenge
        |> sign_challenge(signer, siwx_opts, Keyword.get(opts, :resource_url))
        |> emit_error()

      :error ->
        :none
    end
  end

  @spec sign_challenge(map(), Signer.t(), keyword(), String.t() | nil) ::
          {:ok, proof()} | {:error, {:siwx, reason()}}
  defp sign_challenge(challenge, signer, siwx_opts, resource_url) do
    with {:ok, info} <- fetch_info(challenge),
         :ok <- check_domain(info, Keyword.get(siwx_opts, :domain), resource_url),
         :ok <- check_uri(info, resource_url),
         {:ok, chain_id} <- resolve_chain(challenge, Keyword.fetch!(siwx_opts, :chain_id), signer),
         {:ok, fields} <- sign(challenge, signer, chain_id, siwx_opts),
         {:ok, header} <- encode(fields) do
      {:ok, %{header: header, chain_id: chain_id, address: fields["address"]}}
    end
  end

  @spec fetch_info(map()) :: {:ok, map()} | {:error, {:siwx, :invalid_challenge}}
  defp fetch_info(challenge) do
    case Utils.map_value(challenge, {"info", :info}) do
      %{} = info -> {:ok, info}
      _other -> {:error, {:siwx, :invalid_challenge}}
    end
  end

  @spec check_domain(map(), String.t() | nil, String.t() | nil) ::
          :ok | {:error, {:siwx, :domain_mismatch}}
  defp check_domain(info, expected, resource_url) do
    domain = Utils.map_value(info, {"domain", :domain})

    allowed =
      case {expected, resource_url} do
        {expected, _url} when is_binary(expected) -> [expected]
        {nil, url} when is_binary(url) -> url_domains(url)
        {nil, nil} -> []
      end

    case is_binary(domain) and domain != "" and
           Enum.any?(allowed, &(String.downcase(&1) == String.downcase(domain))) do
      true -> :ok
      false -> {:error, {:siwx, :domain_mismatch}}
    end
  end

  @spec url_domains(String.t()) :: [String.t()]
  defp url_domains(url) do
    case URI.parse(url) do
      %URI{host: host, port: port} when is_binary(host) and is_integer(port) ->
        [host, "#{host}:#{port}"]

      %URI{host: host} when is_binary(host) ->
        [host]

      _uri ->
        []
    end
  end

  @spec check_uri(map(), String.t() | nil) :: :ok | {:error, {:siwx, :uri_mismatch}}
  defp check_uri(_info, nil), do: :ok

  defp check_uri(info, resource_url) do
    uri = Utils.map_value(info, {"uri", :uri})

    case is_binary(uri) and origin(uri) == origin(resource_url) and origin(uri) != nil do
      true -> :ok
      false -> {:error, {:siwx, :uri_mismatch}}
    end
  end

  @spec origin(String.t()) :: {String.t(), String.t(), integer() | nil} | nil
  defp origin(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, port: port} when is_binary(scheme) and is_binary(host) ->
        {String.downcase(scheme), String.downcase(host), port}

      _uri ->
        nil
    end
  end

  @spec resolve_chain(map(), String.t() | :auto, Signer.t()) ::
          {:ok, String.t()} | {:error, {:siwx, :unsupported_chain}}
  defp resolve_chain(_challenge, chain_id, _signer) when is_binary(chain_id), do: {:ok, chain_id}

  defp resolve_chain(challenge, :auto, signer) do
    families = signer_families(signer)

    challenge
    |> supported_chain_ids()
    |> Enum.find(&signable_chain?(&1, families))
    |> case do
      nil -> {:error, {:siwx, :unsupported_chain}}
      chain_id -> {:ok, chain_id}
    end
  end

  @spec signable_chain?(String.t(), [Message.family()]) :: boolean()
  defp signable_chain?(chain_id, families) do
    case Message.family(chain_id) do
      {:ok, family} -> family in families
      _other -> false
    end
  end

  @spec supported_chain_ids(map()) :: [String.t()]
  defp supported_chain_ids(challenge) do
    case Utils.map_value(challenge, {"supportedChains", :supported_chains}) do
      chains when is_list(chains) ->
        chains
        |> Enum.map(&chain_entry_id/1)
        |> Enum.filter(&is_binary/1)

      _other ->
        []
    end
  end

  @spec chain_entry_id(term()) :: term()
  defp chain_entry_id(entry) when is_map(entry),
    do: Utils.map_value(entry, {"chainId", :chain_id})

  defp chain_entry_id(entry) when is_list(entry), do: Keyword.get(entry, :chain_id)
  defp chain_entry_id(_entry), do: nil

  @spec signer_families(term()) :: [Message.family()]
  defp signer_families(%module{}) do
    Enum.flat_map([{:eip155, {:sign_message, 2}}, {:solana, {:sign_ed25519, 2}}], fn
      {family, {name, arity}} ->
        case X402.Behaviour.implements?(module, [{name, arity}]) do
          true -> [family]
          false -> []
        end
    end)
  end

  defp signer_families(_signer), do: []

  @spec sign(map(), Signer.t(), String.t(), keyword()) ::
          {:ok, SIWX.fields()} | {:error, {:siwx, SIWX.sign_error()}}
  defp sign(challenge, signer, chain_id, siwx_opts) do
    sign_opts = [
      chain_id: chain_id,
      address: Keyword.get(siwx_opts, :address),
      signature_scheme: Keyword.get(siwx_opts, :signature_scheme)
    ]

    case SIWX.sign(challenge, signer, sign_opts) do
      {:ok, fields} -> {:ok, fields}
      {:error, reason} -> {:error, {:siwx, reason}}
    end
  end

  @spec encode(SIWX.fields()) :: {:ok, String.t()} | {:error, {:siwx, SIWX.signed_encode_error()}}
  defp encode(fields) do
    case SIWX.encode_signed(fields) do
      {:ok, header} -> {:ok, header}
      {:error, reason} -> {:error, {:siwx, reason}}
    end
  end

  @spec emit_error({:ok, proof()} | {:error, {:siwx, reason()}}) ::
          {:ok, proof()} | {:error, {:siwx, reason()}}
  defp emit_error({:error, {:siwx, reason}} = error) do
    Telemetry.emit(:client, :siwx, :error, %{reason: reason})
    error
  end

  defp emit_error(ok), do: ok
end
