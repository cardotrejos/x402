defmodule X402.Client do
  @moduledoc """
  Transport-agnostic payer client for x402 v2 payments.

  Pure functions covering the client half of the protocol: selecting a
  payment option from a server's `PAYMENT-REQUIRED` response, signing it
  through the `X402.Signer` behaviour, assembling the v2 `PaymentPayload`
  envelope, and encoding it to a `PAYMENT-SIGNATURE` header value. Bring your
  own HTTP client, or use `X402.Client.Finch` for a ready-made
  402 → sign → retry flow.

  This release signs the `exact` scheme on EVM (`eip155:*`) networks via
  EIP-3009 (`X402.EIP3009`); other scheme/network combinations return
  `{:error, {:unsupported_kind, scheme, network}}`.

  ## Example

      {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_KEY"))

      with {:ok, payment_required} <- X402.PaymentRequired.decode(header_value),
           {:ok, payload} <- X402.Client.build_payment(payment_required, signer),
           {:ok, header} <- X402.Client.encode_payment(payload) do
        # retry the request with {"payment-signature", header}
      end
  """

  alias X402.EIP3009
  alias X402.PaymentRequirements
  alias X402.Signer
  alias X402.Telemetry
  alias X402.Utils

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
    ]
  ]

  @build_opts_schema @select_opts_schema ++
                       [
                         valid_after_buffer: [
                           type: :non_neg_integer,
                           default: 60,
                           doc: """
                           Seconds subtracted from the current time for the EVM
                           authorization's `validAfter` (clock-skew tolerance).
                           """
                         ]
                       ]

  @typedoc "Selection options — see `select_requirements/2`."
  @type select_opts :: [
          network: String.t(),
          scheme: String.t(),
          asset: String.t(),
          max_amount: String.t() | non_neg_integer()
        ]

  @type select_error :: :no_acceptable_requirements | :invalid_payment_required

  @type build_error ::
          select_error()
          | {:unsupported_kind, term(), term()}
          | EIP3009.domain_error()
          | EIP3009.encode_error()
          | term()

  @doc since: "0.6.0"
  @doc """
  Selects one payment requirements entry from a `PAYMENT-REQUIRED` payload.

  Accepts a decoded `PaymentRequired` map (its `accepts` list is used) or a
  bare list of requirements maps. Returns the first entry that passes the
  option filters **and** that this client can sign: `exact` scheme on an
  `eip155:*` network, structurally valid per
  `X402.PaymentRequirements.validate/1`, with the EIP-712 domain fields
  (`extra.name` / `extra.version`) present.

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
  """
  @spec select_requirements(map() | [map()], select_opts()) ::
          {:ok, map()} | {:error, select_error()}
  def select_requirements(payment_required, opts \\ []) do
    opts = NimbleOptions.validate!(opts, @select_opts_schema)

    with {:ok, accepts} <- fetch_accepts(payment_required) do
      accepts
      |> Enum.filter(&(is_map(&1) and matches_filters?(&1, opts)))
      |> Enum.find(&supported?/1)
      |> case do
        nil ->
          Telemetry.emit(:client, :select, :error, %{reason: :no_acceptable_requirements})
          {:error, :no_acceptable_requirements}

        selected ->
          Telemetry.emit(:client, :select, :ok, %{
            scheme: Utils.map_value(selected, {"scheme", :scheme}),
            network: Utils.map_value(selected, {"network", :network})
          })

          {:ok, selected}
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
  advertised value and may only add to them.

  Signing dispatches on the scheme and network of the chosen requirements;
  this release supports `exact` on `eip155:*` networks (EIP-3009). Other
  combinations return `{:error, {:unsupported_kind, scheme, network}}`.

  ## Options

  #{NimbleOptions.docs(@build_opts_schema)}
  """
  @spec build_payment(map() | [map()], Signer.t(), keyword()) ::
          {:ok, map()} | {:error, build_error()}
  def build_payment(payment_required_or_requirements, signer, opts \\ []) do
    opts = NimbleOptions.validate!(opts, @build_opts_schema)

    result =
      with {:ok, requirements, envelope} <-
             resolve_requirements(payment_required_or_requirements, opts),
           {:ok, scheme_payload} <- sign_for_kind(requirements, signer, opts) do
        {:ok, assemble_payload(requirements, scheme_payload, envelope)}
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

  @spec supported?(map()) :: boolean()
  defp supported?(requirements) do
    PaymentRequirements.validate(requirements) == :ok and
      supported_kind?(
        Utils.map_value(requirements, {"scheme", :scheme}),
        Utils.map_value(requirements, {"network", :network})
      ) and
      match?({:ok, _domain}, EIP3009.domain(requirements))
  end

  @spec supported_kind?(term(), term()) :: boolean()
  defp supported_kind?("exact", "eip155:" <> _chain_id), do: true
  defp supported_kind?(_scheme, _network), do: false

  # -- Payload assembly -------------------------------------------------------

  @spec resolve_requirements(term(), keyword()) ::
          {:ok, map(), %{resource: term(), extensions: term()}} | {:error, select_error()}
  defp resolve_requirements(%{} = payment_required_or_requirements, opts) do
    if payment_required?(payment_required_or_requirements) do
      with {:ok, requirements} <-
             select_requirements(payment_required_or_requirements, select_opts(opts)) do
        {:ok, requirements,
         %{
           resource: Utils.map_value(payment_required_or_requirements, {"resource", :resource}),
           extensions:
             Utils.map_value(payment_required_or_requirements, {"extensions", :extensions})
         }}
      end
    else
      {:ok, payment_required_or_requirements, %{resource: nil, extensions: nil}}
    end
  end

  defp resolve_requirements(_other, _opts), do: {:error, :invalid_payment_required}

  @spec payment_required?(map()) :: boolean()
  defp payment_required?(map), do: is_list(Utils.map_value(map, {"accepts", :accepts}))

  @spec select_opts(keyword()) :: keyword()
  defp select_opts(opts), do: Keyword.take(opts, Keyword.keys(@select_opts_schema))

  @spec sign_for_kind(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, build_error()}
  defp sign_for_kind(requirements, signer, opts) do
    scheme = Utils.map_value(requirements, {"scheme", :scheme})
    network = Utils.map_value(requirements, {"network", :network})

    if supported_kind?(scheme, network) do
      case EIP3009.sign(requirements, signer, valid_after_buffer: opts[:valid_after_buffer]) do
        {:ok, scheme_payload} ->
          Telemetry.emit(:client, :sign, :ok, %{scheme: scheme, network: network})
          {:ok, scheme_payload}

        {:error, reason} = error ->
          Telemetry.emit(:client, :sign, :error, %{
            reason: reason,
            scheme: scheme,
            network: network
          })

          error
      end
    else
      Telemetry.emit(:client, :sign, :error, %{
        reason: :unsupported_kind,
        scheme: scheme,
        network: network
      })

      {:error, {:unsupported_kind, scheme, network}}
    end
  end

  @spec assemble_payload(map(), map(), %{resource: term(), extensions: term()}) :: map()
  defp assemble_payload(requirements, scheme_payload, envelope) do
    %{
      "x402Version" => 2,
      "accepted" => requirements,
      "payload" => scheme_payload
    }
    |> maybe_put("resource", envelope.resource)
    |> maybe_put("extensions", envelope.extensions)
  end

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(payload, _key, nil), do: payload
  defp maybe_put(payload, key, value) when is_map(value), do: Map.put(payload, key, value)
  defp maybe_put(payload, _key, _value), do: payload
end
