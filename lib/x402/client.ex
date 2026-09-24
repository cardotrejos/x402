defmodule X402.Client do
  @moduledoc """
  Transport-agnostic payer client for x402 v2 payments.

  Pure functions covering the client half of the protocol: selecting a
  payment option from a server's `PAYMENT-REQUIRED` response, signing it
  through the `X402.Signer` behaviour, assembling the v2 `PaymentPayload`
  envelope, and encoding it to a `PAYMENT-SIGNATURE` header value. Bring your
  own HTTP client, or use `X402.Client.Finch` for a ready-made
  402 → sign → retry flow.

  Signing dispatches through `X402.Scheme.Registry`: out of the box this
  client signs the `exact` scheme on EVM (`eip155:*`) networks via EIP-3009
  (`X402.Scheme.ExactEVM`), on Solana (`solana:*`) networks via a
  partially signed v0 transaction (`X402.Scheme.ExactSVM`), and the
  `upto` scheme on EVM networks via Permit2 (`X402.Scheme.UptoEVM`);
  other scheme/network combinations return
  `{:error, {:unsupported_kind, scheme, network}}` unless a matching
  `X402.Scheme` module is passed with the `:schemes` option.

  ## Example

      {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_KEY"))

      with {:ok, payment_required} <- X402.PaymentRequired.decode(header_value),
           {:ok, payload} <- X402.Client.build_payment(payment_required, signer),
           {:ok, header} <- X402.Client.encode_payment(payload) do
        # retry the request with {"payment-signature", header}
      end
  """

  alias X402.Client.Hooks
  alias X402.Client.Hooks.Context
  alias X402.EIP3009
  alias X402.PaymentRequirements
  alias X402.Scheme
  alias X402.Signer
  alias X402.Telemetry
  alias X402.Utils

  require Logger

  @select_opts_schema [
    network: [
      type: :string,
      doc: """
      Only select requirements on this CAIP-2 network. A trailing `*` acts as
      a prefix wildcard (for example `"eip155:*"`).
      """
    ],
    scheme: [
      type: :string,
      doc: "Only select requirements using this scheme (for example `\"exact\"`)."
    ],
    asset: [
      type: :string,
      doc: "Only select requirements paying with this asset (compared case-insensitively)."
    ],
    max_amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: """
      Only select requirements whose `amount` (in atomic units) does not
      exceed this value — the budget guard for automated payers.
      """
    ],
    policies: [
      type: {:list, {:fun, 2}},
      default: [],
      doc: """
      Selection policies, each a function of the candidate requirements and
      the `PaymentRequired` map (`nil` for a bare list) returning `true` to
      accept, `false` to skip the entry, or `{:error, reason}` to abort
      selection with that error. Every policy must accept an entry for it
      to be selected — see `X402.Client.Policy` for ready-made ones.
      """
    ],
    schemes: [
      type: {:list, {:custom, Scheme, :validate_module, []}},
      default: [],
      doc: """
      Additional `X402.Scheme` modules consulted (before the built-ins) when
      deciding which requirements this client can sign and how to sign
      them — see `X402.Scheme.Registry`.
      """
    ]
  ]

  @build_opts_schema @select_opts_schema ++
                       [
                         auth_capture: [
                           type: {:custom, X402.Scheme.AuthCaptureEVM, :validate_options, []},
                           default: [],
                           doc: "Auth-capture signing options (`:now`, `:salt`, `:salt_nonce`)."
                         ],
                         hooks: [
                           type: {:custom, Hooks, :validate_module, []},
                           default: Hooks.Default,
                           doc: """
                           Module implementing `X402.Client.Hooks`, run around
                           payment creation.
                           """
                         ],
                         valid_after_buffer: [
                           type: :non_neg_integer,
                           default: 60,
                           doc: """
                           Seconds subtracted from the current time for the EVM
                           authorization's `validAfter` (clock-skew tolerance).
                           """
                         ],
                         extensions: [
                           type: {:list, {:fun, 2}},
                           default: [],
                           doc: """
                           Client extension enrichers applied, in order, to the
                           assembled payload. Each function receives the payload
                           and the original `PaymentRequired` map (`nil` when
                           building from a bare requirements map) and returns
                           `{:ok, payload}` or `{:error, reason}` — see
                           `X402.Extensions.EIP2612GasSponsoring.enricher/2` and
                           `X402.Extensions.ERC20ApprovalGasSponsoring.enricher/1`.
                           """
                         ],
                         svm_blockhash: [
                           type: :string,
                           doc: """
                           Base58 recent blockhash for SVM (Solana) payments,
                           used when the server's `extra.recentBlockhash` hint
                           is absent — see `X402.Scheme.ExactSVM`.
                           """
                         ],
                         svm_blockhash_fetcher: [
                           type: {:fun, 1},
                           doc: """
                           1-arity fun receiving the CAIP-2 network and
                           returning `{:ok, blockhash}` for SVM payments (for
                           example a wrapper around an RPC client's
                           `getLatestBlockhash`).
                           """
                         ],
                         svm_decimals: [
                           type: :non_neg_integer,
                           doc: """
                           The SVM asset's decimals for `TransferChecked`,
                           for mints outside `X402.Scheme.ExactSVM`'s
                           known-asset table.
                           """
                         ],
                         svm_token_program: [
                           type: :string,
                           doc: """
                           The SVM asset's owning token program (SPL Token or
                           Token-2022 address), for mints outside
                           `X402.Scheme.ExactSVM`'s known-asset table.
                           """
                         ]
                       ]

  @typedoc "Selection options — see `select_requirements/2`."
  @type select_opts :: [
          network: String.t(),
          scheme: String.t(),
          asset: String.t(),
          max_amount: String.t() | non_neg_integer(),
          policies: [X402.Client.Policy.t()],
          schemes: [module()]
        ]

  @type select_error ::
          :no_acceptable_requirements
          | :invalid_payment_required
          | {:invalid_policy_result, term()}
          | term()

  # Escrow is recognized only for its dedicated auth-capture signer.
  @recognized_payment_flows ["authorization"]

  @type build_error ::
          select_error()
          | Hooks.hook_error()
          | {:unsupported_kind, term(), term()}
          | EIP3009.domain_error()
          | EIP3009.encode_error()
          | term()

  @doc since: "0.6.0"
  @doc """
  Selects one payment requirements entry from a `PAYMENT-REQUIRED` payload.

  Accepts a decoded `PaymentRequired` map (its `accepts` list is used) or a
  bare list of requirements maps. Returns the first entry that passes the
  option filters **and** that this client can sign: structurally valid per
  `X402.PaymentRequirements.validate/1` and resolved by
  `X402.Scheme.Registry` to a scheme module with a sign callback — by
  default `exact` on an `eip155:*` network via `X402.Scheme.ExactEVM`
  (which additionally requires the EIP-712 domain fields `extra.name` /
  `extra.version`) and `upto` on an `eip155:*` network via
  `X402.Scheme.UptoEVM` (which requires `extra.facilitatorAddress`). Pass
  additional schemes with the `:schemes` option.

  Entries whose `extra.paymentFlow` names a flow this client does not
  recognize are skipped: the protocol requires clients never to construct
  a payment for an unknown flow (spec §6.1). Only the default
  `"authorization"` flow (explicit or omitted) is recognized; `upfront` and
  `escrow` entries settle before the resource executes and are not selected.

  `:policies` run last, on the signable candidates in order: the first entry
  every policy accepts is selected. A policy returning `{:error, reason}`
  aborts with `{:error, reason}` (for example a budget policy refusing to
  continue); any other non-boolean return aborts with
  `{:error, {:invalid_policy_result, value}}`.

  The selected entry is returned exactly as the server sent it, so it can be
  echoed verbatim as the payload's `accepted` value.

  ## Options

  #{NimbleOptions.docs(@select_opts_schema)}

  ## Examples

      iex> requirements = %{
      ...>   "scheme" => "exact",
      ...>   "network" => "eip155:84532",
      ...>   "amount" => "10000",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "maxTimeoutSeconds" => 60,
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> }
      iex> {:ok, selected} =
      ...>   X402.Client.select_requirements(%{"x402Version" => 2, "accepts" => [requirements]})
      iex> selected == requirements
      true

      iex> X402.Client.select_requirements(%{"x402Version" => 2, "accepts" => []})
      {:error, :no_acceptable_requirements}

      iex> requirements = %{
      ...>   "scheme" => "exact",
      ...>   "network" => "eip155:84532",
      ...>   "amount" => "10000",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "maxTimeoutSeconds" => 60,
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> }
      iex> X402.Client.select_requirements([requirements], policies: [X402.Client.Policy.max_amount("100")])
      {:error, :no_acceptable_requirements}
  """
  @spec select_requirements(map() | [map()], select_opts()) ::
          {:ok, map()} | {:error, select_error()}
  def select_requirements(payment_required, opts \\ []) do
    opts = NimbleOptions.validate!(opts, @select_opts_schema)
    schemes = Keyword.fetch!(opts, :schemes)
    policies = Keyword.fetch!(opts, :policies)

    with {:ok, accepts} <- fetch_accepts(payment_required) do
      accepts
      |> Enum.filter(&(is_map(&1) and matches_filters?(&1, opts) and supported?(&1, schemes)))
      |> first_accepted(policies, payment_required_map(payment_required))
      |> case do
        {:error, reason} = error ->
          Telemetry.emit(:client, :select, :error, %{reason: reason})
          error

        {:ok, selected} = ok ->
          Telemetry.emit(:client, :select, :ok, %{
            scheme: Utils.map_value(selected, {"scheme", :scheme}),
            network: Utils.map_value(selected, {"network", :network})
          })

          ok
      end
    end
  end

  @doc since: "0.6.0"
  @doc """
  Builds a complete v2 `PaymentPayload` for a payment-required response.

  Accepts either a decoded `PaymentRequired` map — in which case one entry is
  chosen via `select_requirements/2` and the server's `resource` and
  `extensions` are echoed — or a single requirements map, which skips
  selection (and carries no `resource`/`extensions` echo).

  The chosen requirements are echoed in full (including `extra`) as
  `accepted`, and server-advertised `extensions` are echoed unchanged,
  following the spec's append-only rule: the client must preserve every
  advertised value and may only add to them. `:extensions` enrichers run
  after assembly and may add extension data on top of the echo — for
  example `X402.Extensions.EIP2612GasSponsoring.enricher/2` for
  gas-sponsored Permit2 approvals.

  Signing dispatches on the scheme and network of the chosen requirements
  through `X402.Scheme.Registry`; out of the box this supports `exact` on
  `eip155:*` networks (EIP-3009) and on `solana:*` networks (partially
  signed v0 transactions), plus `upto` on `eip155:*` networks (Permit2).
  Other combinations return
  `{:error, {:unsupported_kind, scheme, network}}` unless a matching
  module is passed with the `:schemes` option. Scheme modules receive the
  validated build options, so options like `:valid_after_buffer` (EVM) and
  `:svm_blockhash` (SVM) reach `c:X402.Scheme.sign/3`.

  ## Lifecycle hooks

  The `:hooks` module (`X402.Client.Hooks`, default
  `X402.Client.Hooks.Default`) runs `before_payment/2` once requirements
  are selected — it may replace them or halt — `after_payment/2` once the
  payload is built — it may replace the payload — and
  `on_payment_failure/2` when signing or enrichment fails — it may replace
  the error or recover with a payload. Selection failures return before
  any hook runs.

  ## Options

  #{NimbleOptions.docs(@build_opts_schema)}
  """
  @spec build_payment(map() | [map()], Signer.t(), keyword()) ::
          {:ok, map()} | {:error, build_error()}
  def build_payment(payment_required_or_requirements, signer, opts \\ []) do
    opts = NimbleOptions.validate!(opts, @build_opts_schema)
    hooks = Keyword.fetch!(opts, :hooks)

    result =
      with {:ok, requirements, envelope} <-
             resolve_requirements(payment_required_or_requirements, opts),
           context = Context.new(envelope.payment_required, requirements, opts),
           {:ok, context} <- run_before_hook(hooks, context) do
        create_payload(hooks, context, envelope, signer, opts)
      end

    case result do
      {:ok, _payload} = ok ->
        Telemetry.emit(:client, :build, :ok, %{})
        ok

      {:error, reason} = error ->
        Telemetry.emit(:client, :build, :error, %{reason: reason})
        error
    end
  end

  @doc false
  @spec warn_no_spend_limit_once(module()) :: :ok
  def warn_no_spend_limit_once(driver) do
    key = {__MODULE__, :no_spend_limit_warned}

    unless :persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "[#{inspect(driver)}] no spend limit is configured: this client will sign any " <>
          "amount a server asks for. Pass `max_amount:`, `policies:` " <>
          "(see X402.Client.Policy), or `budget:` (see X402.Client.Budget) to cap payments."
      )
    end

    :ok
  end

  @doc since: "0.6.0"
  @doc """
  Encodes a `PaymentPayload` map to a `PAYMENT-SIGNATURE` header value.

  The header value is Base64-encoded JSON, compatible with
  `X402.PaymentSignature.decode/1` on the validation side.

  ## Examples

      iex> payload = %{"x402Version" => 2, "accepted" => %{"scheme" => "exact"}, "payload" => %{}}
      iex> {:ok, header} = X402.Client.encode_payment(payload)
      iex> X402.PaymentSignature.decode(header)
      {:ok, payload}

      iex> X402.Client.encode_payment(nil)
      {:error, :invalid_payload}
  """
  @spec encode_payment(map()) :: {:ok, String.t()} | {:error, :invalid_payload | :invalid_json}
  def encode_payment(payload) when is_map(payload) do
    case Jason.encode(payload) do
      {:ok, json} -> {:ok, Base.encode64(json)}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  def encode_payment(_payload), do: {:error, :invalid_payload}

  # -- Selection --------------------------------------------------------------

  @spec fetch_accepts(term()) :: {:ok, [term()]} | {:error, :invalid_payment_required}
  defp fetch_accepts(accepts) when is_list(accepts), do: {:ok, accepts}

  defp fetch_accepts(payment_required) when is_map(payment_required) do
    case Utils.map_value(payment_required, {"accepts", :accepts}) do
      accepts when is_list(accepts) -> {:ok, accepts}
      _accepts -> {:error, :invalid_payment_required}
    end
  end

  defp fetch_accepts(_payment_required), do: {:error, :invalid_payment_required}

  @spec payment_required_map(term()) :: map() | nil
  defp payment_required_map(payment_required) when is_map(payment_required), do: payment_required
  defp payment_required_map(_accepts), do: nil

  @spec first_accepted([map()], [X402.Client.Policy.t()], map() | nil) ::
          {:ok, map()} | {:error, select_error()}
  defp first_accepted([], _policies, _payment_required), do: {:error, :no_acceptable_requirements}

  defp first_accepted([candidate | rest], policies, payment_required) do
    case apply_policies(policies, candidate, payment_required) do
      :accept -> {:ok, candidate}
      :skip -> first_accepted(rest, policies, payment_required)
      {:error, _reason} = error -> error
    end
  end

  @spec apply_policies([X402.Client.Policy.t()], map(), map() | nil) ::
          :accept | :skip | {:error, term()}
  defp apply_policies([], _candidate, _payment_required), do: :accept

  defp apply_policies([policy | policies], candidate, payment_required) do
    case policy.(candidate, payment_required) do
      true -> apply_policies(policies, candidate, payment_required)
      false -> :skip
      {:error, _reason} = error -> error
      other -> {:error, {:invalid_policy_result, other}}
    end
  end

  @spec matches_filters?(map(), keyword()) :: boolean()
  defp matches_filters?(requirements, opts) do
    Enum.all?(opts, fn
      {:network, network} ->
        matches_network?(network, Utils.map_value(requirements, {"network", :network}))

      {:scheme, scheme} ->
        Utils.map_value(requirements, {"scheme", :scheme}) == scheme

      {:asset, asset} ->
        matches_asset?(asset, Utils.map_value(requirements, {"asset", :asset}))

      {:max_amount, max_amount} ->
        within_max_amount?(Utils.map_value(requirements, {"amount", :amount}), max_amount)

      {_key, _value} ->
        true
    end)
  end

  @spec matches_network?(String.t(), term()) :: boolean()
  defp matches_network?(_filter, network) when not is_binary(network), do: false

  defp matches_network?(filter, network) do
    case String.split_at(filter, -1) do
      {prefix, "*"} -> String.starts_with?(network, prefix)
      _exact -> filter == network
    end
  end

  @spec matches_asset?(String.t(), term()) :: boolean()
  defp matches_asset?(filter, asset) when is_binary(asset),
    do: String.downcase(filter) == String.downcase(asset)

  defp matches_asset?(_filter, _asset), do: false

  @spec within_max_amount?(term(), String.t() | non_neg_integer()) :: boolean()
  defp within_max_amount?(amount, max_amount) do
    with {:ok, amount_decimal} <- Utils.parse_decimal(amount),
         {:ok, max_decimal} <- Utils.parse_decimal(max_amount) do
      Utils.compare_decimal(amount_decimal, max_decimal) != :gt
    else
      :error -> false
    end
  end

  @spec supported?(map(), [module()]) :: boolean()
  defp supported?(requirements, schemes) do
    recognized_payment_flow?(requirements) and
      PaymentRequirements.validate(requirements) == :ok and
      case resolve_scheme(requirements, schemes) do
        {:ok, module} -> Scheme.signs?(module) and Scheme.signable?(module, requirements)
        :error -> false
      end
  end

  @spec recognized_payment_flow?(map()) :: boolean()
  defp recognized_payment_flow?(requirements) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      extra when is_map(extra) ->
        case Utils.map_value(extra, {"paymentFlow", :paymentFlow}) do
          nil -> true
          "escrow" -> Utils.map_value(requirements, {"scheme", :scheme}) == "auth-capture"
          flow -> flow in @recognized_payment_flows
        end

      _extra ->
        true
    end
  end

  @spec resolve_scheme(map(), [module()]) :: {:ok, module()} | :error
  defp resolve_scheme(requirements, schemes) do
    Scheme.Registry.resolve(
      schemes,
      Utils.map_value(requirements, {"scheme", :scheme}),
      Utils.map_value(requirements, {"network", :network})
    )
  end

  # -- Payload assembly -------------------------------------------------------

  @spec resolve_requirements(term(), keyword()) ::
          {:ok, map(), %{resource: term(), extensions: term(), payment_required: map() | nil}}
          | {:error, select_error()}
  defp resolve_requirements(%{} = payment_required_or_requirements, opts) do
    if payment_required?(payment_required_or_requirements) do
      with {:ok, requirements} <-
             select_requirements(payment_required_or_requirements, select_opts(opts)) do
        {:ok, requirements,
         %{
           resource: Utils.map_value(payment_required_or_requirements, {"resource", :resource}),
           extensions:
             Utils.map_value(payment_required_or_requirements, {"extensions", :extensions}),
           payment_required: payment_required_or_requirements
         }}
      end
    else
      {:ok, payment_required_or_requirements,
       %{resource: nil, extensions: nil, payment_required: nil}}
    end
  end

  defp resolve_requirements(_other, _opts), do: {:error, :invalid_payment_required}

  @spec payment_required?(map()) :: boolean()
  defp payment_required?(map), do: is_list(Utils.map_value(map, {"accepts", :accepts}))

  @spec select_opts(keyword()) :: keyword()
  defp select_opts(opts), do: Keyword.take(opts, Keyword.keys(@select_opts_schema))

  @spec create_payload(module(), Context.t(), map(), Signer.t(), keyword()) ::
          {:ok, map()} | {:error, build_error()}
  defp create_payload(
         hooks,
         %Context{requirements: requirements} = context,
         envelope,
         signer,
         opts
       ) do
    result =
      with {:ok, scheme_payload} <- sign_for_kind(requirements, signer, opts) do
        requirements
        |> assemble_payload(scheme_payload, envelope)
        |> apply_extensions(envelope.payment_required, Keyword.fetch!(opts, :extensions))
      end

    case result do
      {:ok, payload} -> run_after_hook(hooks, %{context | payload: payload})
      {:error, reason} -> run_failure_hook(hooks, %{context | error: reason}, reason)
    end
  end

  # -- Lifecycle hooks --------------------------------------------------------

  @spec run_before_hook(module(), Context.t()) ::
          {:ok, Context.t()} | {:error, Hooks.hook_error()}
  defp run_before_hook(hooks, context) do
    case invoke_hook(hooks, :before_payment, context) do
      {:ok, {:cont, %Context{requirements: requirements} = next}} when is_map(requirements) ->
        {:ok, next}

      {:ok, {:halt, reason}} ->
        {:error, {:hook_halted, :before_payment, reason}}

      {:ok, invalid_return} ->
        {:error, {:hook_invalid_return, :before_payment, invalid_return}}

      {:error, reason} ->
        {:error, {:hook_callback_failed, :before_payment, reason}}
    end
  end

  @spec run_after_hook(module(), Context.t()) :: {:ok, map()} | {:error, Hooks.hook_error()}
  defp run_after_hook(hooks, context) do
    case invoke_hook(hooks, :after_payment, context) do
      {:ok, {:cont, %Context{payload: payload}}} when is_map(payload) ->
        {:ok, payload}

      {:ok, invalid_return} ->
        {:error, {:hook_invalid_return, :after_payment, invalid_return}}

      {:error, reason} ->
        {:error, {:hook_callback_failed, :after_payment, reason}}
    end
  end

  @spec run_failure_hook(module(), Context.t(), term()) ::
          {:ok, map()} | {:error, build_error()}
  defp run_failure_hook(hooks, context, original_error) do
    case invoke_hook(hooks, :on_payment_failure, context) do
      {:ok, {:cont, %Context{error: nil}}} ->
        {:error, original_error}

      {:ok, {:cont, %Context{error: error}}} ->
        {:error, error}

      {:ok, {:recover, payload}} when is_map(payload) ->
        {:ok, payload}

      {:ok, {:recover, invalid_payload}} ->
        {:error,
         {:hook_invalid_return, :on_payment_failure, {:invalid_recovery_result, invalid_payload}}}

      {:ok, invalid_return} ->
        {:error, {:hook_invalid_return, :on_payment_failure, invalid_return}}

      {:error, reason} ->
        {:error, {:hook_callback_failed, :on_payment_failure, reason}}
    end
  end

  @spec invoke_hook(module(), Hooks.callback_name(), Context.t()) ::
          {:ok, term()} | {:error, term()}
  defp invoke_hook(hooks, callback, %Context{requirements: requirements} = context) do
    metadata = %{
      operation: :build_payment,
      hook_module: hooks,
      scheme: Utils.map_value(requirements, {"scheme", :scheme}),
      network: Utils.map_value(requirements, {"network", :network})
    }

    {:ok, apply(hooks, callback, [context, metadata])}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  @spec sign_for_kind(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, build_error()}
  defp sign_for_kind(requirements, signer, opts) do
    scheme = Utils.map_value(requirements, {"scheme", :scheme})
    network = Utils.map_value(requirements, {"network", :network})

    with true <- recognized_payment_flow?(requirements),
         {:ok, module} <- resolve_scheme(requirements, Keyword.fetch!(opts, :schemes)),
         true <- Scheme.signs?(module) do
      case module.sign(requirements, signer, opts) do
        {:ok, scheme_payload} when is_map(scheme_payload) ->
          Telemetry.emit(:client, :sign, :ok, %{scheme: scheme, network: network})
          {:ok, scheme_payload}

        {:error, reason} = error ->
          Telemetry.emit(:client, :sign, :error, %{
            reason: reason,
            scheme: scheme,
            network: network
          })

          error

        other ->
          reason = {:invalid_scheme_payload, other}

          Telemetry.emit(:client, :sign, :error, %{
            reason: reason,
            scheme: scheme,
            network: network
          })

          {:error, reason}
      end
    else
      _unsupported ->
        Telemetry.emit(:client, :sign, :error, %{
          reason: :unsupported_kind,
          scheme: scheme,
          network: network
        })

        {:error, {:unsupported_kind, scheme, network}}
    end
  end

  @spec assemble_payload(map(), map(), %{
          resource: term(),
          extensions: term(),
          payment_required: map() | nil
        }) :: map()
  defp assemble_payload(requirements, scheme_payload, envelope) do
    %{
      "x402Version" => 2,
      "accepted" => requirements,
      "payload" => scheme_payload
    }
    |> maybe_put("resource", envelope.resource)
    |> maybe_put("extensions", envelope.extensions)
  end

  @spec apply_extensions(map(), map() | nil, [(map(), map() | nil -> term())]) ::
          {:ok, map()} | {:error, term()}
  defp apply_extensions(payload, _payment_required, []), do: {:ok, payload}

  defp apply_extensions(payload, payment_required, [enricher | enrichers]) do
    case enricher.(payload, payment_required) do
      {:ok, enriched} when is_map(enriched) ->
        apply_extensions(enriched, payment_required, enrichers)

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:invalid_extension_result, other}}
    end
  end

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(payload, _key, nil), do: payload
  defp maybe_put(payload, key, value) when is_map(value), do: Map.put(payload, key, value)
  defp maybe_put(payload, _key, _value), do: payload
end
