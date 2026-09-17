defmodule X402.RateLimiter do
  @options_schema [
    limit: [
      type: :pos_integer,
      required: true,
      doc: "Maximum hits per window."
    ],
    window_ms: [
      type: :pos_integer,
      required: true,
      doc: "Window length in milliseconds."
    ],
    key: [
      type: {:or, [{:in, [:payer, :ip]}, {:fun, 1}]},
      default: :payer,
      doc: """
      What is being limited: `:payer` (the verified payer address, falling
      back to the remote IP when neither the facilitator nor the payload
      names one), `:ip` (the remote IP), or a 1-arity function of the
      request context (`%{conn: conn, payer: payer, payment_payload:
      payload, requirements: requirements}`) returning any term — `nil`
      exempts the request.
      """
    ],
    store: [
      type: {:custom, __MODULE__, :validate_store, []},
      default: X402.RateLimiter.ETS,
      doc: """
      A module implementing `X402.RateLimiter`, or a `{module, ref}` tuple
      where `ref` is passed as the first argument of `c:hit/4`. A bare
      module is called with itself as the ref — for the default
      `X402.RateLimiter.ETS` that is the table name.
      """
    ],
    on_error: [
      type: {:in, [:allow, :deny]},
      default: :allow,
      doc: """
      What to do when the store returns `{:error, _}` or raises: `:allow`
      lets the request through (the limiter degrades to a no-op with a
      logged warning), `:deny` answers 429 with a one-second `Retry-After`.
      """
    ]
  ]

  @moduledoc """
  Behaviour and option handling for per-wallet request rate limiting.

  `X402.Plug.PaymentGate` consults a rate limiter after a payment has been
  verified and before it is settled, so the key is derived from an
  authenticated payer: the `from` of an unverified payload is whatever the
  sender typed, and counting it earlier would let anyone exhaust a victim
  wallet's allowance with forged proofs. The limit therefore bounds how many
  *verified* payments a wallet can spend per window; it is not a substitute
  for an edge/IP limiter against unauthenticated floods. A store implements
  `c:hit/4`; `X402.RateLimiter.ETS` ships a per-node fixed-window
  implementation and any shared store (Redis, a database) can be plugged in
  through the same callback.

  ## Options

  The gate's `:rate_limit` option is validated with `validate_options/1`:

  #{NimbleOptions.docs(@options_schema)}

  ## Implementing a store

      defmodule MyApp.RedisRateLimiter do
        @behaviour X402.RateLimiter

        @impl true
        def hit(conn_name, key, limit, window_ms) do
          # INCR + PEXPIRE on "rl:" <> inspect(key), then compare with limit
        end
      end

  `c:hit/4` must count the hit atomically and report either the remaining
  allowance or how long the caller should wait. It should not raise for
  store failures — return `{:error, reason}` and let `:on_error` decide.
  """

  require Logger

  alias X402.Utils

  @typedoc "Store reference passed as the first argument of `c:hit/4`."
  @type store_ref :: term()

  @typedoc "The value being rate limited."
  @type key :: term()

  @typedoc "Result of a hit."
  @type result ::
          {:allow, remaining :: non_neg_integer()}
          | {:deny, retry_after_ms :: pos_integer()}
          | {:error, term()}

  @typedoc "Request context handed to a `:key` function."
  @type context :: %{
          conn: term(),
          payer: String.t() | nil,
          payment_payload: map(),
          requirements: map()
        }

  @typedoc "Validated `:rate_limit` configuration."
  @type config :: %{
          limit: pos_integer(),
          window_ms: pos_integer(),
          key: :payer | :ip | (context() -> term()),
          store: {module(), store_ref()},
          on_error: :allow | :deny
        }

  @doc """
  Records one hit for `key` and reports whether it is within `limit` per `window_ms`.
  """
  @callback hit(store_ref(), key(), limit :: pos_integer(), window_ms :: pos_integer()) ::
              result()

  @doc since: "0.9.0"
  @doc """
  Validates a `:rate_limit` option value into a `t:config/0` map.

  Usable as a `NimbleOptions` custom type. `nil` disables limiting.

  ## Examples

      iex> X402.RateLimiter.validate_options(nil)
      {:ok, nil}

      iex> {:ok, config} = X402.RateLimiter.validate_options(limit: 10, window_ms: 60_000)
      iex> config
      %{limit: 10, window_ms: 60_000, key: :payer, store: {X402.RateLimiter.ETS, X402.RateLimiter.ETS}, on_error: :allow}

      iex> {:error, message} = X402.RateLimiter.validate_options(limit: 0, window_ms: 1)
      iex> message =~ ":limit"
      true

      iex> X402.RateLimiter.validate_options(:nope)
      {:error, "expected nil or a keyword list of rate limit options"}
  """
  @spec validate_options(term()) :: {:ok, config() | nil} | {:error, String.t()}
  def validate_options(nil), do: {:ok, nil}

  def validate_options(opts) when is_list(opts) do
    case NimbleOptions.validate(opts, @options_schema) do
      {:ok, validated} ->
        {:ok,
         %{
           limit: Keyword.fetch!(validated, :limit),
           window_ms: Keyword.fetch!(validated, :window_ms),
           key: Keyword.fetch!(validated, :key),
           store: Keyword.fetch!(validated, :store),
           on_error: Keyword.fetch!(validated, :on_error)
         }}

      {:error, %NimbleOptions.ValidationError{} = error} ->
        {:error, Exception.message(error)}
    end
  end

  def validate_options(_other),
    do: {:error, "expected nil or a keyword list of rate limit options"}

  @doc false
  @spec validate_store(term()) :: {:ok, {module(), store_ref()}} | {:error, String.t()}
  def validate_store({module, ref}) when is_atom(module), do: validate_store_module(module, ref)
  def validate_store(module) when is_atom(module), do: validate_store_module(module, module)

  def validate_store(_other),
    do: {:error, "expected a module implementing X402.RateLimiter or a {module, ref} tuple"}

  defp validate_store_module(module, ref) do
    if X402.Behaviour.implements?(module, hit: 4) do
      {:ok, {module, ref}}
    else
      {:error, "expected #{inspect(module)} to implement X402.RateLimiter (hit/4)"}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Resolves the rate-limit key for a request, or `:skip` when it is exempt.

  `:payer` uses the payer address (lower-cased when it is a `0x` address)
  and falls back to `{:ip, remote_ip}` when the payload carries none;
  `:ip` uses the remote IP; a function receives the whole context.

  ## Examples

      iex> context = %{conn: %{remote_ip: {127, 0, 0, 1}}, payer: "0xABC", payment_payload: %{}, requirements: %{}}
      iex> X402.RateLimiter.resolve_key(%{key: :payer}, context)
      {:payer, "0xabc"}

      iex> context = %{conn: %{remote_ip: {127, 0, 0, 1}}, payer: nil, payment_payload: %{}, requirements: %{}}
      iex> X402.RateLimiter.resolve_key(%{key: :payer}, context)
      {:ip, {127, 0, 0, 1}}

      iex> context = %{conn: %{remote_ip: {10, 0, 0, 2}}, payer: "0xabc", payment_payload: %{}, requirements: %{}}
      iex> X402.RateLimiter.resolve_key(%{key: :ip}, context)
      {:ip, {10, 0, 0, 2}}

      iex> context = %{conn: %{remote_ip: {10, 0, 0, 2}}, payer: "0xabc", payment_payload: %{}, requirements: %{}}
      iex> X402.RateLimiter.resolve_key(%{key: fn _context -> nil end}, context)
      :skip
  """
  @spec resolve_key(
          %{required(:key) => :payer | :ip | (context() -> term()), optional(atom()) => term()},
          context()
        ) :: key() | :skip
  def resolve_key(%{key: :payer}, %{payer: payer}) when is_binary(payer) and payer != "" do
    {:payer, normalize_payer(payer)}
  end

  def resolve_key(%{key: :payer}, context), do: resolve_key(%{key: :ip}, context)

  def resolve_key(%{key: :ip}, %{conn: conn}), do: {:ip, remote_ip(conn)}

  def resolve_key(%{key: fun}, context) when is_function(fun, 1) do
    case fun.(context) do
      nil -> :skip
      key -> key
    end
  end

  defp normalize_payer(<<prefix::binary-size(2), _rest::binary>> = payer)
       when prefix in ["0x", "0X"],
       do: String.downcase(payer)

  defp normalize_payer(payer), do: payer

  defp remote_ip(%{remote_ip: ip}), do: ip
  defp remote_ip(_conn), do: nil

  @doc since: "0.9.0"
  @doc """
  Recovers the verified payer address of a payment.

  Prefers the `payer` the facilitator reported in its verify response
  (`verify_response` is the response map or its body), and otherwise reads
  the EIP-3009 `authorization.from` or the Permit2
  `permit2Authorization.from` of the scheme payload — a signer the
  facilitator has just authenticated. Returns `nil` when neither is
  present (for example a Solana transaction verified by a facilitator that
  omits `payer`).

  The payload's `from` is attacker-controlled until verification succeeds;
  call this with a verified payment only.

  ## Examples

      iex> X402.RateLimiter.payer(%{"payload" => %{"authorization" => %{"from" => "0xabc"}}})
      "0xabc"

      iex> X402.RateLimiter.payer(%{"payload" => %{"permit2Authorization" => %{"from" => "0xdef"}}})
      "0xdef"

      iex> payload = %{"payload" => %{"authorization" => %{"from" => "0xabc"}}}
      iex> X402.RateLimiter.payer(payload, %{status: 200, body: %{"isValid" => true, "payer" => "0x123"}})
      "0x123"

      iex> X402.RateLimiter.payer(%{"payload" => %{"transaction" => "AQID"}}, %{"isValid" => true})
      nil
  """
  @spec payer(map(), map() | nil) :: String.t() | nil
  def payer(payment_payload, verify_response \\ nil) when is_map(payment_payload) do
    [
      verified_payer(verify_response),
      Utils.nested_map_value(payment_payload, [
        {"payload", :payload},
        {"authorization", :authorization},
        {"from", :from}
      ]),
      Utils.nested_map_value(payment_payload, [
        {"payload", :payload},
        {"permit2Authorization", :permit2Authorization},
        {"from", :from}
      ])
    ]
    |> Utils.first_present()
    |> case do
      from when is_binary(from) and from != "" -> from
      _other -> nil
    end
  end

  defp verified_payer(%{body: body}) when is_map(body), do: verified_payer(body)

  defp verified_payer(body) when is_map(body) do
    case Utils.map_value(body, {"payer", :payer}) do
      payer when is_binary(payer) and payer != "" -> payer
      _missing -> nil
    end
  end

  defp verified_payer(_none), do: nil

  @doc since: "0.9.0"
  @doc """
  Records a hit for `key` against the configured store.

  Store errors and exceptions never propagate: they are logged and resolved
  according to `:on_error` (`:allow` reports the full `limit` as remaining;
  `:deny` reports a one-second retry).
  """
  @spec check(config(), key()) :: {:allow, non_neg_integer()} | {:deny, pos_integer()}
  def check(%{store: {module, ref}, limit: limit, window_ms: window_ms} = config, key) do
    case safe_hit(module, ref, key, limit, window_ms) do
      {:allow, remaining} when is_integer(remaining) and remaining >= 0 ->
        {:allow, remaining}

      {:deny, retry_after_ms} when is_integer(retry_after_ms) and retry_after_ms > 0 ->
        {:deny, retry_after_ms}

      {:error, reason} ->
        store_error(config, module, reason)

      other ->
        store_error(config, module, {:invalid_return, other})
    end
  end

  defp safe_hit(module, ref, key, limit, window_ms) do
    module.hit(ref, key, limit, window_ms)
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp store_error(%{on_error: on_error, limit: limit}, module, reason) do
    Logger.warning(
      "[X402.RateLimiter] store #{inspect(module)} failed (#{inspect(reason)}); " <>
        "#{on_error_description(on_error)}"
    )

    case on_error do
      :allow -> {:allow, limit}
      :deny -> {:deny, 1_000}
    end
  end

  defp on_error_description(:allow), do: "allowing the request"
  defp on_error_description(:deny), do: "denying the request"

  @doc since: "0.9.0"
  @doc """
  Converts a retry delay in milliseconds to whole seconds, rounded up, for `Retry-After`.

  ## Examples

      iex> X402.RateLimiter.retry_after_seconds(1)
      1

      iex> X402.RateLimiter.retry_after_seconds(1_000)
      1

      iex> X402.RateLimiter.retry_after_seconds(1_001)
      2

      iex> X402.RateLimiter.retry_after_seconds(0)
      1
  """
  @spec retry_after_seconds(non_neg_integer()) :: pos_integer()
  def retry_after_seconds(retry_after_ms) when is_integer(retry_after_ms) do
    max(div(retry_after_ms + 999, 1_000), 1)
  end
end
