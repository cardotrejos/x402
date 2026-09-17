defmodule X402.Facilitator.Failover do
  @moduledoc """
  Multi-endpoint failover policy for `X402.Facilitator`.

  A facilitator client may be started with `:fallbacks` — additional
  endpoints tried in order when the primary fails — and a `:failover`
  policy. Each endpoint carries its own URL, auth, and transport settings;
  a per-endpoint circuit breaker (kept in the facilitator process) skips
  endpoints that recently failed for `:cooldown_ms`, so a dead primary does
  not add a timeout to every call until it recovers.

  ## What fails over

  * `verify`, `supported`, `list_resources`, and `search_resources` fail
    over on transport errors, timeouts, and 5xx responses. They never fail
    over on 4xx or on a facilitator that answered (a verification failure
    is an answer, not an outage).
  * `settle` fails over **only** when the request provably never reached
    the endpoint: connection refused, DNS resolution failure, unreachable
    host or network, or a TLS handshake failure. It never fails over on a
    timeout, a closed connection, or a 5xx — the facilitator may have
    broadcast the settlement before the failure, and retrying elsewhere
    could settle the same authorization twice (or, for nonce-consuming
    schemes, surface a confusing "already used" error while the money has
    moved). Callers that need at-least-once settlement should retry the
    same endpoint and reconcile through the pending-settlement flow.

  Every failover emits `[:x402, :facilitator, :failover]` with metadata
  `:operation`, `:from` and `:to` (endpoint URLs), `:reason` (the
  `X402.Facilitator.Error` type), and `:status`.
  """

  alias X402.Facilitator.Error

  @default_cooldown_ms 30_000

  @endpoint_schema [
    url: [
      type: :string,
      required: true,
      doc: "Fallback facilitator base URL."
    ],
    auth: [
      type: {:custom, X402.Facilitator, :validate_auth, []},
      default: nil,
      doc: "Request authentication for this endpoint (same forms as the primary `:auth`)."
    ],
    finch: [
      type: :any,
      doc: "Finch pool for this endpoint. Defaults to the primary's."
    ],
    max_retries: [
      type: :non_neg_integer,
      doc: "Per-endpoint retry count. Defaults to the primary's."
    ],
    retry_backoff_ms: [
      type: :non_neg_integer,
      doc: "Per-endpoint initial retry backoff. Defaults to the primary's."
    ],
    receive_timeout_ms: [
      type: :non_neg_integer,
      doc: "Per-endpoint HTTP receive timeout. Defaults to the primary's."
    ]
  ]

  @policy_schema [
    max_attempts: [
      type: :pos_integer,
      doc: "Maximum endpoints tried per operation. Defaults to the number of endpoints."
    ],
    cooldown_ms: [
      type: :non_neg_integer,
      default: @default_cooldown_ms,
      doc: "How long an endpoint that failed over is skipped before being tried again."
    ]
  ]

  @typedoc "One facilitator endpoint (the primary or a fallback)."
  @type endpoint :: %{
          url: String.t(),
          finch: term(),
          auth: term(),
          max_retries: non_neg_integer(),
          retry_backoff_ms: non_neg_integer(),
          receive_timeout_ms: non_neg_integer()
        }

  @typedoc "Validated failover policy."
  @type policy :: %{max_attempts: pos_integer() | nil, cooldown_ms: non_neg_integer()}

  @typedoc "Open circuits: endpoint URL to the monotonic millisecond it reopens."
  @type breaker :: %{optional(String.t()) => integer()}

  @typedoc "Facilitator operation names."
  @type operation :: :verify | :settle | :supported | :list_resources | :search_resources

  @doc false
  @spec endpoint_schema() :: keyword()
  def endpoint_schema, do: @endpoint_schema

  @doc false
  @spec policy_schema() :: keyword()
  def policy_schema, do: @policy_schema

  @doc false
  @spec validate_fallbacks(term()) :: {:ok, [keyword()]} | {:error, String.t()}
  def validate_fallbacks(fallbacks) when is_list(fallbacks) do
    fallbacks
    |> Enum.reduce_while({:ok, []}, fn fallback, {:ok, acc} ->
      with true <- Keyword.keyword?(fallback),
           {:ok, validated} <- NimbleOptions.validate(fallback, @endpoint_schema) do
        {:cont, {:ok, [validated | acc]}}
      else
        false -> {:halt, {:error, "expected each fallback to be a keyword list"}}
        {:error, error} -> {:halt, {:error, Exception.message(error)}}
      end
    end)
    |> case do
      {:ok, validated} -> {:ok, Enum.reverse(validated)}
      {:error, message} -> {:error, message}
    end
  end

  def validate_fallbacks(_fallbacks), do: {:error, "expected a list of fallback endpoints"}

  @doc false
  @spec validate_policy(term()) :: {:ok, policy()} | {:error, String.t()}
  def validate_policy(%{max_attempts: _max_attempts, cooldown_ms: _cooldown_ms} = policy),
    do: {:ok, policy}

  def validate_policy(policy) when is_list(policy) do
    case NimbleOptions.validate(policy, @policy_schema) do
      {:ok, validated} ->
        {:ok,
         %{
           max_attempts: Keyword.get(validated, :max_attempts),
           cooldown_ms: Keyword.fetch!(validated, :cooldown_ms)
         }}

      {:error, error} ->
        {:error, Exception.message(error)}
    end
  end

  def validate_policy(_policy), do: {:error, "expected a keyword list of failover options"}

  @doc since: "0.9.0"
  @doc """
  Builds the fallback endpoint list, inheriting unset transport settings from `primary`.

  ## Examples

      iex> primary = %{url: "https://a", finch: F, auth: nil, max_retries: 2, retry_backoff_ms: 100, receive_timeout_ms: 5_000}
      iex> X402.Facilitator.Failover.build_endpoints(primary, [[url: "https://b", auth: nil, receive_timeout_ms: 1_000]])
      [%{url: "https://b", finch: F, auth: nil, max_retries: 2, retry_backoff_ms: 100, receive_timeout_ms: 1_000}]
  """
  @spec build_endpoints(endpoint(), [keyword()]) :: [endpoint()]
  def build_endpoints(primary, fallbacks) when is_map(primary) and is_list(fallbacks) do
    Enum.map(fallbacks, fn fallback ->
      %{
        url: Keyword.fetch!(fallback, :url),
        finch: Keyword.get(fallback, :finch, primary.finch),
        auth: Keyword.get(fallback, :auth),
        max_retries: Keyword.get(fallback, :max_retries, primary.max_retries),
        retry_backoff_ms: Keyword.get(fallback, :retry_backoff_ms, primary.retry_backoff_ms),
        receive_timeout_ms: Keyword.get(fallback, :receive_timeout_ms, primary.receive_timeout_ms)
      }
    end)
  end

  @doc since: "0.9.0"
  @doc """
  Orders endpoints for an attempt: healthy ones first, then those in cooldown.

  Endpoints whose circuit is open are still tried — last — so an outage of
  every endpoint degrades to the plain single-endpoint behaviour rather
  than failing without a request. The list is capped at
  `policy.max_attempts`.

  ## Examples

      iex> endpoints = [%{url: "https://a"}, %{url: "https://b"}, %{url: "https://c"}]
      iex> breaker = %{"https://a" => 1_000}
      iex> policy = %{max_attempts: nil, cooldown_ms: 100}
      iex> X402.Facilitator.Failover.order(endpoints, breaker, policy, 500) |> Enum.map(& &1.url)
      ["https://b", "https://c", "https://a"]

      iex> endpoints = [%{url: "https://a"}, %{url: "https://b"}]
      iex> X402.Facilitator.Failover.order(endpoints, %{"https://a" => 1_000}, %{max_attempts: nil, cooldown_ms: 100}, 2_000) |> Enum.map(& &1.url)
      ["https://a", "https://b"]

      iex> endpoints = [%{url: "https://a"}, %{url: "https://b"}, %{url: "https://c"}]
      iex> X402.Facilitator.Failover.order(endpoints, %{}, %{max_attempts: 2, cooldown_ms: 100}, 0) |> Enum.map(& &1.url)
      ["https://a", "https://b"]
  """
  @spec order([endpoint()], breaker(), policy(), integer()) :: [endpoint()]
  def order(endpoints, breaker, policy, now_ms)
      when is_list(endpoints) and is_map(breaker) and is_map(policy) do
    {open, healthy} =
      Enum.split_with(endpoints, fn %{url: url} ->
        case Map.get(breaker, url) do
          nil -> false
          reopen_at -> now_ms < reopen_at
        end
      end)

    Enum.take(healthy ++ open, policy.max_attempts || length(endpoints))
  end

  @doc since: "0.9.0"
  @doc """
  Whether `error` from `operation` should be retried on the next endpoint.

  ## Examples

      iex> alias X402.Facilitator.Error
      iex> X402.Facilitator.Failover.failover?(:verify, %Error{type: :http_error, status: 503})
      true
      iex> X402.Facilitator.Failover.failover?(:verify, %Error{type: :http_error, status: 400})
      false
      iex> X402.Facilitator.Failover.failover?(:verify, %Error{type: :timeout})
      true
      iex> X402.Facilitator.Failover.failover?(:settle, %Error{type: :timeout})
      false
      iex> X402.Facilitator.Failover.failover?(:settle, %Error{type: :http_error, status: 502})
      false
      iex> X402.Facilitator.Failover.failover?(:settle, %Error{type: :transport_error, reason: %{reason: :econnrefused}})
      true
      iex> X402.Facilitator.Failover.failover?(:verify, {:hook_halted, :before_verify, :nope})
      false
  """
  @spec failover?(operation(), term()) :: boolean()
  def failover?(:settle, %Error{type: :transport_error, reason: reason}), do: undelivered?(reason)
  def failover?(:settle, _error), do: false

  def failover?(_operation, %Error{type: type}) when type in [:transport_error, :timeout],
    do: true

  def failover?(_operation, %Error{type: :http_error, status: status}) when is_integer(status),
    do: status >= 500

  def failover?(_operation, _error), do: false

  @undelivered_reasons [:econnrefused, :nxdomain, :ehostunreach, :enetunreach, :ehostdown]

  @doc since: "0.9.0"
  @doc """
  Whether a transport error reason proves the request never reached the server.

  Accepts the bare POSIX/DNS reason, a `{:tls_alert, _}` handshake failure,
  or a transport error struct (`Mint.TransportError`) wrapping one.

  ## Examples

      iex> X402.Facilitator.Failover.undelivered?(:econnrefused)
      true
      iex> X402.Facilitator.Failover.undelivered?(%{reason: :nxdomain})
      true
      iex> X402.Facilitator.Failover.undelivered?(%{reason: {:tls_alert, {:handshake_failure, ~c"bad"}}})
      true
      iex> X402.Facilitator.Failover.undelivered?(:timeout)
      false
      iex> X402.Facilitator.Failover.undelivered?(%{reason: :closed})
      false
      iex> X402.Facilitator.Failover.undelivered?(:econnreset)
      false
  """
  @spec undelivered?(term()) :: boolean()
  def undelivered?(reason) when reason in @undelivered_reasons, do: true
  def undelivered?({:tls_alert, _alert}), do: true
  def undelivered?({:options, _options}), do: true
  def undelivered?(%{reason: reason}), do: undelivered?(reason)
  def undelivered?(_reason), do: false

  @doc since: "0.9.0"
  @doc """
  Runs `request` against each candidate endpoint in turn.

  `request` receives an endpoint and returns `{:ok, result} | {:error, reason}`.
  The first success, or the first error that is not eligible for failover
  (`failover?/2`), is returned; an eligible error trips the endpoint's
  breaker through `trip` and is retried on the next candidate. The last
  candidate's error is returned as-is. With a single endpoint the request
  runs exactly once.
  """
  @spec run(
          [endpoint()],
          operation(),
          (endpoint() -> {:ok, term()} | {:error, term()}),
          (String.t() -> :ok)
        ) :: {:ok, term()} | {:error, term()}
  def run([endpoint], _operation, request, _trip), do: request.(endpoint)
  def run(endpoints, operation, request, trip), do: attempt(endpoints, operation, request, trip)

  defp attempt([endpoint | rest], operation, request, trip) do
    case request.(endpoint) do
      {:ok, _result} = ok ->
        ok

      {:error, error} = failure ->
        if failover?(operation, error) do
          trip.(endpoint.url)
          next(rest, operation, request, trip, endpoint.url, error, failure)
        else
          failure
        end
    end
  end

  defp next([], _operation, _request, _trip, _from, _error, failure), do: failure

  defp next([next_endpoint | _rest] = rest, operation, request, trip, from, error, _failure) do
    emit(operation, from, next_endpoint.url, error)
    attempt(rest, operation, request, trip)
  end

  defp emit(operation, from, to, %Error{} = error) do
    :telemetry.execute([:x402, :facilitator, :failover], %{count: 1}, %{
      operation: operation,
      from: from,
      to: to,
      reason: error.type,
      status: error.status
    })
  end
end
