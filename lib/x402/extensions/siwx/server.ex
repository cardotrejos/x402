defmodule X402.Extensions.SIWX.Server do
  @moduledoc """
  Server-side Sign-In-With-X: challenge issuance, proof verification, and
  payer records.

  Bundles the pieces a resource server needs to let a wallet that already
  paid skip payment: it builds the challenge advertised on 402 responses
  (`challenge/1`), verifies `SIGN-IN-WITH-X` proofs (`verify/2`), records
  which address paid for which resource after settlement
  (`record_payment/4`), and combines verification with that history
  (`authenticate/3`). `X402.Plug.PaymentGate` drives it through its `:siwx`
  option; use it directly from other frameworks.

      {:ok, siwx} =
        X402.Extensions.SIWX.Server.new(
          domain: "api.example.com",
          uri: "https://api.example.com",
          supported_chains: [%{chain_id: "eip155:8453"}],
          nonce_cache: {X402.Extensions.PaymentIdentifier.ETSCache, MyApp.SIWXNonces}
        )

      # on every 402
      {:ok, challenge} = X402.Extensions.SIWX.Server.challenge(siwx)

      # on a request carrying SIGN-IN-WITH-X
      case X402.Extensions.SIWX.Server.authenticate(siwx, header, resource_url) do
        {:ok, %{address: address}} -> serve(conn)
        {:error, :not_authorized} -> respond_402(conn)
        {:error, code} -> respond_402(conn, error: code)
      end

      # after a successful settlement
      :ok = X402.Extensions.SIWX.Server.record_payment(siwx, payer, resource_url, settle_response)

  ## Nonces

  Each challenge carries a fresh nonce. With a `:nonce_cache` (any
  `X402.Extensions.PaymentIdentifier.Cache` adapter) issued nonces are
  recorded and consumed on verification, so a proof authenticates exactly
  once and only against a challenge this server issued. Without a cache —
  the default — a proof is only bound by its `issuedAt` window
  (`:max_age_seconds`) and can be replayed within it; configure a cache in
  production.

  ## Storage

  Payer records live in an `X402.Extensions.SIWX.Storage` adapter keyed by
  `{address, resource}`; `X402.Extensions.SIWX.ETSStorage` (its default
  process) is used unless `:storage` is set. Pass `{module, server}` to
  address a specific storage process; the module must then expose the
  server-taking `get/3`, `put/5`, and `delete/3` like `ETSStorage` does.
  """

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.Challenge
  alias X402.Extensions.SIWX.ETSStorage
  alias X402.Extensions.SIWX.Storage
  alias X402.Extensions.SIWX.Verification
  alias X402.Extensions.SIWX.Verifier

  @default_ttl_ms 24 * 60 * 60 * 1000

  @opts_schema [
    domain: [
      type: :string,
      required: true,
      doc: "Public host advertised in the challenge and required in proofs."
    ],
    uri: [
      type: :string,
      required: true,
      doc: "Public URI advertised in the challenge and required in proofs."
    ],
    supported_chains: [
      type: {:custom, Challenge, :validate_supported_chains, []},
      required: true,
      doc: "Accepted chains, in the form `X402.Extensions.SIWX.challenge/1` takes."
    ],
    statement: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Human-readable statement included in the challenge."
    ],
    resources: [
      type: {:list, :string},
      default: [],
      doc: "Resource URIs included in the challenge."
    ],
    expiration_seconds: [
      type: :pos_integer,
      default: 300,
      doc: "Lifetime of an advertised challenge (`expirationTime - issuedAt`)."
    ],
    max_age_seconds: [
      type: :pos_integer,
      default: 300,
      doc: "Maximum age of a proof's `issuedAt`."
    ],
    clock_skew_seconds: [
      type: :non_neg_integer,
      default: 60,
      doc: "Tolerance for a proof's `issuedAt` slightly in the future."
    ],
    nonce_cache: [
      type: {:custom, __MODULE__, :validate_nonce_cache, []},
      default: nil,
      doc: """
      `X402.Extensions.PaymentIdentifier.Cache` adapter tuple (or an
      `ETSCache` server name) that records issued nonces and consumes them
      on verification. Strongly recommended: without it proofs can be
      replayed within `:max_age_seconds`.
      """
    ],
    storage: [
      type: {:custom, __MODULE__, :validate_storage, []},
      default: ETSStorage,
      doc: """
      `X402.Extensions.SIWX.Storage` module, or `{module, server}` to address
      a specific storage process.
      """
    ],
    ttl_ms: [
      type: :pos_integer,
      default: @default_ttl_ms,
      doc: "How long a recorded payment grants access, in milliseconds."
    ],
    verifier: [
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

  @typedoc "Validated server configuration, built by `new/1`."
  @type t :: %{
          domain: String.t(),
          uri: String.t(),
          supported_chains: [map()],
          statement: String.t() | nil,
          resources: [String.t()],
          expiration_seconds: pos_integer(),
          max_age_seconds: pos_integer(),
          clock_skew_seconds: non_neg_integer(),
          nonce_cache: Cache.adapter() | nil,
          storage: storage(),
          ttl_ms: pos_integer(),
          verifier: module(),
          ed25519_verifier: module()
        }

  @typedoc "A storage module, or a module paired with the server it should address."
  @type storage :: module() | {module(), term()}

  @typedoc "A verified identity together with the payment record that authorizes it."
  @type session :: %{
          address: String.t(),
          chain_id: String.t(),
          fields: SIWX.fields(),
          access: Storage.access_record()
        }

  @doc false
  @spec opts_schema() :: keyword()
  def opts_schema, do: @opts_schema

  @doc since: "0.7.0"
  @doc """
  Validates server options.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}

  ## Examples

      iex> {:ok, siwx} = X402.Extensions.SIWX.Server.new(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "eip155:8453"}]
      ...> )
      iex> {siwx.storage, siwx.nonce_cache, siwx.ttl_ms}
      {X402.Extensions.SIWX.ETSStorage, nil, 86_400_000}

      iex> {:error, %NimbleOptions.ValidationError{}} =
      ...>   X402.Extensions.SIWX.Server.new(domain: "api.example.com")
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, NimbleOptions.ValidationError.t()}
  def new(opts) when is_list(opts) do
    with {:ok, validated} <- NimbleOptions.validate(opts, @opts_schema) do
      {:ok, Map.new(validated)}
    end
  end

  @doc since: "0.7.0"
  @doc """
  Validates server options, raising `NimbleOptions.ValidationError` on
  failure.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) when is_list(opts) do
    opts |> NimbleOptions.validate!(@opts_schema) |> Map.new()
  end

  @doc false
  @spec validate_options(term()) :: {:ok, t()} | {:error, String.t()}
  def validate_options(opts) when is_list(opts) do
    case new(opts) do
      {:ok, config} -> {:ok, config}
      {:error, %NimbleOptions.ValidationError{} = error} -> {:error, Exception.message(error)}
    end
  end

  def validate_options(_invalid), do: {:error, "expected a keyword list of SIWX server options"}

  @doc false
  @spec validate_nonce_cache(term()) :: {:ok, Cache.adapter() | nil} | {:error, String.t()}
  def validate_nonce_cache(nil), do: {:ok, nil}

  def validate_nonce_cache({module, _cache} = adapter) when is_atom(module) do
    case Cache.validate_adapter(adapter) do
      :ok ->
        {:ok, adapter}

      {:error, message} ->
        {:error,
         message <>
           "; to address a remote ETSCache as {name, node}, wrap it explicitly: " <>
           "{X402.Extensions.PaymentIdentifier.ETSCache, {name, node}}"}
    end
  end

  def validate_nonce_cache(server) when is_atom(server) or is_pid(server),
    do: {:ok, {ETSCache, server}}

  def validate_nonce_cache({:via, registry, _term} = server) when is_atom(registry),
    do: {:ok, {ETSCache, server}}

  def validate_nonce_cache(_invalid),
    do: {:error, "expected nil, an ETSCache server, or a {module, cache} adapter tuple"}

  @doc false
  @spec validate_storage(term()) :: {:ok, storage()} | {:error, String.t()}
  def validate_storage({module, _server} = storage) when is_atom(module) do
    with {:ok, _module} <- Storage.validate_module(module),
         true <- X402.Behaviour.implements?(module, get: 3, put: 5, delete: 3) do
      {:ok, storage}
    else
      false ->
        {:error,
         "expected #{inspect(module)} to export get/3, put/5, and delete/3 " <>
           "to be addressed as {module, server}"}

      {:error, message} ->
        {:error, message}
    end
  end

  def validate_storage(module), do: Storage.validate_module(module)

  @doc since: "0.7.0"
  @doc """
  Builds a fresh challenge and, with a `:nonce_cache`, records its nonce as
  issued.

  Returns the map to advertise under `PaymentRequired.extensions["sign-in-with-x"]`.
  Fails only when the nonce could not be recorded; a challenge whose nonce
  is unknown to the server would never verify, so it is better not to
  advertise one.

  ## Examples

      iex> siwx = X402.Extensions.SIWX.Server.new!(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "eip155:8453"}]
      ...> )
      iex> {:ok, challenge} = X402.Extensions.SIWX.Server.challenge(siwx)
      iex> {challenge["info"]["domain"], challenge["supportedChains"]}
      {"api.example.com", [%{"chainId" => "eip155:8453", "type" => "eip191"}]}
  """
  @spec challenge(t()) :: {:ok, map()} | {:error, term()}
  def challenge(%{} = config) do
    challenge =
      Challenge.build(
        domain: config.domain,
        uri: config.uri,
        supported_chains: config.supported_chains,
        statement: config.statement,
        resources: config.resources,
        expiration_seconds: config.expiration_seconds
      )

    with :ok <- remember_nonce(config, challenge["info"]["nonce"]) do
      {:ok, challenge}
    end
  end

  @doc since: "0.7.0"
  @doc """
  Records a challenge nonce as issued in the `:nonce_cache`.

  A no-op (`:ok`) without a cache. `challenge/1` calls this for you; use it
  when advertising a challenge built some other way.
  """
  @spec remember_nonce(t(), String.t()) :: :ok | {:error, term()}
  def remember_nonce(%{nonce_cache: nil}, _nonce), do: :ok

  def remember_nonce(%{nonce_cache: cache}, nonce) when is_binary(nonce) do
    case Cache.put_new(cache, Verification.issued_key(nonce), {:siwx_nonce, :issued}) do
      :ok -> :ok
      {:error, :already_exists} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc since: "0.7.0"
  @doc """
  Verifies a `SIGN-IN-WITH-X` proof against the server configuration.

  Accepts the raw header value or the tuple `X402.Extensions.SIWX.decode_signed/1`
  returns; see `X402.Extensions.SIWX.verify/2` for the checks and error
  codes. With a `:nonce_cache` the nonce is consumed on success.
  """
  @spec verify(t(), SIWX.decoded() | String.t()) ::
          {:ok, SIWX.identity()} | {:error, SIWX.verify_error()}
  def verify(%{} = config, proof) do
    SIWX.verify(proof,
      domain: config.domain,
      uri: config.uri,
      supported_chains: config.supported_chains,
      max_age_seconds: config.max_age_seconds,
      clock_skew_seconds: config.clock_skew_seconds,
      nonce_cache: config.nonce_cache,
      evm_verifier: config.verifier,
      ed25519_verifier: config.ed25519_verifier
    )
  end

  @doc since: "0.7.0"
  @doc """
  Verifies a proof and checks that its address has a payment record for
  `resource`.

  Returns the identity with the access record under `:access`,
  `{:error, :not_authorized}` when the proof is valid but no record exists
  (respond with a fresh challenge and payment requirements), or the
  verification error otherwise.
  """
  @spec authenticate(t(), SIWX.decoded() | String.t(), String.t()) ::
          {:ok, session()} | {:error, SIWX.verify_error() | :not_authorized}
  def authenticate(%{} = config, proof, resource) when is_binary(resource) do
    with {:ok, identity} <- verify(config, proof),
         {:ok, record} <- authorized(config, identity.address, resource) do
      {:ok, Map.put(identity, :access, record)}
    end
  end

  @doc since: "0.7.0"
  @doc """
  Looks up the payment record for an address and resource.
  """
  @spec authorized(t(), String.t(), String.t()) ::
          {:ok, Storage.access_record()} | {:error, :not_authorized}
  def authorized(%{storage: storage}, address, resource)
      when is_binary(address) and is_binary(resource) do
    case storage_get(storage, normalize_address(address), resource) do
      {:ok, record} -> {:ok, record}
      {:error, :not_found} -> {:error, :not_authorized}
    end
  end

  @doc since: "0.7.0"
  @doc """
  Records that `address` paid for `resource`, granting access for `:ttl_ms`.

  `payment_proof` is stored alongside the record (the facilitator's settle
  response, typically) and returned by `authenticate/3` under
  `access.payment_proof`.
  """
  @spec record_payment(t(), String.t(), String.t(), term()) :: :ok | {:error, term()}
  def record_payment(%{storage: storage, ttl_ms: ttl_ms}, address, resource, payment_proof)
      when is_binary(address) and is_binary(resource) do
    storage_put(storage, normalize_address(address), resource, payment_proof, ttl_ms)
  end

  @doc since: "0.7.0"
  @doc """
  Revokes the payment record for an address and resource.
  """
  @spec revoke(t(), String.t(), String.t()) :: :ok
  def revoke(%{storage: storage}, address, resource)
      when is_binary(address) and is_binary(resource) do
    storage_delete(storage, normalize_address(address), resource)
  end

  # EVM addresses are case-insensitive (EIP-55 checksums are display-only),
  # so the same wallet can present as either lowercase or checksummed
  # depending on the source (facilitator settle response, browser wallet,
  # LocalKey). Storage keys must fold those variants together; Solana
  # base58 addresses are case-sensitive and pass through untouched.
  @spec normalize_address(String.t()) :: String.t()
  defp normalize_address("0x" <> _rest = address), do: String.downcase(address)
  defp normalize_address(address), do: address

  @spec storage_get(storage(), String.t(), String.t()) ::
          {:ok, Storage.access_record()} | {:error, :not_found}
  defp storage_get({module, server}, address, resource), do: module.get(server, address, resource)
  defp storage_get(module, address, resource), do: module.get(address, resource)

  @spec storage_put(storage(), String.t(), String.t(), term(), pos_integer()) ::
          :ok | {:error, term()}
  defp storage_put({module, server}, address, resource, proof, ttl_ms),
    do: module.put(server, address, resource, proof, ttl_ms)

  defp storage_put(module, address, resource, proof, ttl_ms),
    do: module.put(address, resource, proof, ttl_ms)

  @spec storage_delete(storage(), String.t(), String.t()) :: :ok
  defp storage_delete({module, server}, address, resource),
    do: module.delete(server, address, resource)

  defp storage_delete(module, address, resource), do: module.delete(address, resource)
end
