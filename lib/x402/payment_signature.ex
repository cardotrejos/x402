defmodule X402.PaymentSignature do
  @moduledoc """
  Decodes and validates x402 v2 `PAYMENT-SIGNATURE` header values.

  The header value is Base64-encoded JSON carrying the v2 `PaymentPayload`
  envelope (`x402Version: 2`). `accepted` must be a complete
  `X402.PaymentRequirements` object and `payload` must contain the
  scheme-specific signed data. When requirements are passed to `validate/2`,
  every core field is matched and advertised `extra` values must be preserved.

  Payloads that declare `x402Version: 1` — or omit the version entirely, which
  x402 v1 clients do — are rejected with
  `{:error, {:unsupported_x402_version, version}}`. This SDK does not speak the
  v1 wire format (v1 payments arrive in the `X-PAYMENT` header, which
  `X402.Plug.PaymentGate` never reads); rejecting explicitly is safer than the
  false interop of validating a shape no facilitator settles.

  Scheme-specific structural validation (for example the `upto` ceiling
  check) dispatches through `X402.Scheme.Registry`; pass additional
  `X402.Scheme` modules with the `:schemes` option of `validate/3` or
  `decode_and_validate/3`. Kinds with no registered scheme module pass
  through with `:ok` — the facilitator remains the authority.
  """

  alias X402.PaymentRequirements
  alias X402.Scheme
  alias X402.Telemetry
  alias X402.Utils

  # Single source of truth for the 8 KB decode guard — see X402.Header.
  @max_header_bytes X402.Header.max_header_bytes()

  @validate_opts_schema [
    schemes: [
      type: {:list, {:custom, Scheme, :validate_module, []}},
      default: [],
      doc: """
      Additional `X402.Scheme` modules consulted (before the built-ins) for
      scheme-specific payload validation — see `X402.Scheme.Registry`.
      """
    ]
  ]

  @type decode_error :: :invalid_base64 | :invalid_json | :payload_too_large

  @typedoc "See `t:X402.Scheme.UptoEVM.validation_error/0`."
  @type upto_validation_error :: X402.Scheme.UptoEVM.validation_error()

  @type validate_error ::
          :invalid_payload
          | :invalid_payment_requirements
          | :invalid_x402_version
          | :no_matching_requirements
          | {:unsupported_x402_version, 1 | nil}
          | {:missing_fields, [String.t()]}
          | {:invalid_fields, [String.t()]}
          | {:invalid_upto_payment, upto_validation_error()}

  @type decode_and_validate_error :: decode_error() | validate_error()

  @doc since: "0.1.0", group: :headers
  @doc """
  Returns the canonical x402 header name.

  ## Examples

      iex> X402.PaymentSignature.header_name()
      "PAYMENT-SIGNATURE"
  """
  @spec header_name() :: String.t()
  def header_name, do: "PAYMENT-SIGNATURE"

  @doc since: "0.1.0", group: :headers
  @doc """
  Decodes a Base64 `PAYMENT-SIGNATURE` value to a map.

  ## Examples

      iex> payload = %{"x402Version" => 2, "accepted" => %{"scheme" => "exact"}, "payload" => %{}}
      iex> value = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentSignature.decode(value)
      {:ok, payload}

      iex> X402.PaymentSignature.decode("not-base64")
      {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, map()} | {:error, decode_error()}
  def decode(value) when is_binary(value) do
    if byte_size(value) > @max_header_bytes do
      Telemetry.emit(:payment_signature, :decode, :error, %{
        reason: :payload_too_large,
        header: header_name()
      })

      {:error, :payload_too_large}
    else
      do_decode(value)
    end
  end

  def decode(_value) do
    Telemetry.emit(:payment_signature, :decode, :error, %{
      reason: :invalid_base64,
      header: header_name()
    })

    {:error, :invalid_base64}
  end

  defp do_decode(value) do
    with {:ok, json} <- Utils.decode_base64(value),
         {:ok, decoded} <- Jason.decode(json),
         true <- is_map(decoded) do
      result = {:ok, decoded}
      Telemetry.emit(:payment_signature, :decode, :ok, %{header: header_name()})
      result
    else
      {:error, :invalid_base64} = error ->
        Telemetry.emit(:payment_signature, :decode, :error, %{
          reason: :invalid_base64,
          header: header_name()
        })

        error

      {:error, %Jason.DecodeError{}} ->
        Telemetry.emit(:payment_signature, :decode, :error, %{
          reason: :invalid_json,
          header: header_name()
        })

        {:error, :invalid_json}

      false ->
        Telemetry.emit(:payment_signature, :decode, :error, %{
          reason: :invalid_json,
          header: header_name()
        })

        {:error, :invalid_json}
    end
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Validates a decoded v2 `PAYMENT-SIGNATURE` payload.

  Payloads with `x402Version: 2` are validated against the v2
  `PaymentPayload` structure. Payloads declaring version `1` — or omitting the
  version, as v1 clients do — return
  `{:error, {:unsupported_x402_version, version}}`; any other version returns
  `{:error, :invalid_x402_version}`.

  ## Examples

      iex> payload = %{
      ...>   "x402Version" => 2,
      ...>   "accepted" => %{
      ...>     "scheme" => "exact",
      ...>     "network" => "eip155:8453",
      ...>     "amount" => "10000",
      ...>     "asset" => "0xasset",
      ...>     "payTo" => "0xreceiver",
      ...>     "maxTimeoutSeconds" => 60,
      ...>     "extra" => %{}
      ...>   },
      ...>   "payload" => %{"signature" => "0xsignature"}
      ...> }
      iex> X402.PaymentSignature.validate(payload)
      {:ok, payload}

      iex> X402.PaymentSignature.validate(%{"x402Version" => 2})
      {:error, :invalid_payload}
  """
  @spec validate(map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(payload) when is_map(payload), do: do_validate(payload, %{}, [])

  def validate(_payload) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Validates a decoded `PAYMENT-SIGNATURE` payload against payment requirements.

  For v2, this matches the complete `accepted` object. For the `"upto"` scheme,
  it also ensures the signed maximum does not exceed the advertised `amount`.
  """
  @spec validate(map(), map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(payload, requirements) when is_map(payload) and is_map(requirements) do
    do_validate(payload, requirements, [])
  end

  def validate(_payload, _requirements) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.6.0", group: :verification
  @doc """
  Validates a decoded `PAYMENT-SIGNATURE` payload with custom schemes.

  Behaves like `validate/2`, additionally consulting the given
  `X402.Scheme` modules (before the built-ins) for scheme-specific payload
  validation — see `X402.Scheme.Registry` for the resolution rules.

  ## Options

  #{NimbleOptions.docs(@validate_opts_schema)}
  """
  @spec validate(map(), map(), keyword()) ::
          {:ok, map()} | {:error, validate_error() | term()}
  def validate(payload, requirements, opts)
      when is_map(payload) and is_map(requirements) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @validate_opts_schema)
    do_validate(payload, requirements, Keyword.fetch!(opts, :schemes))
  end

  def validate(_payload, _requirements, _opts) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @spec do_validate(map(), map(), [module()]) ::
          {:ok, map()} | {:error, validate_error() | term()}
  defp do_validate(payload, requirements, schemes) do
    case Utils.map_value(payload, {"x402Version", :x402Version}) do
      2 -> validate_v2(payload, requirements, schemes)
      version when version in [nil, 1] -> validation_error({:unsupported_x402_version, version})
      _version -> validation_error(:invalid_x402_version)
    end
  end

  @spec validate_v2(map(), map(), [module()]) ::
          {:ok, map()} | {:error, validate_error() | term()}
  defp validate_v2(payload, requirements, schemes) do
    accepted = Utils.map_value(payload, {"accepted", :accepted})
    scheme_payload = Utils.map_value(payload, {"payload", :payload})
    resource = Utils.map_value(payload, {"resource", :resource})
    extensions = Utils.map_value(payload, {"extensions", :extensions})

    with true <- is_map(accepted),
         true <- is_map(scheme_payload),
         true <- is_nil(resource) or is_map(resource),
         true <- is_nil(extensions) or is_map(extensions),
         :ok <- PaymentRequirements.validate(accepted),
         :ok <- match_v2_requirements(requirements, accepted),
         :ok <-
           validate_scheme(payload, effective_requirements(requirements, accepted), schemes) do
      validation_success(payload)
    else
      false -> validation_error(:invalid_payload)
      {:error, reason} -> validation_error(reason)
    end
  end

  @spec match_v2_requirements(map(), map()) :: :ok | {:error, :no_matching_requirements}
  defp match_v2_requirements(requirements, _accepted) when map_size(requirements) == 0, do: :ok

  defp match_v2_requirements(requirements, accepted) do
    case PaymentRequirements.match?(requirements, accepted) do
      true -> :ok
      false -> {:error, :no_matching_requirements}
    end
  end

  @spec effective_requirements(map(), map()) :: map()
  defp effective_requirements(requirements, accepted) when map_size(requirements) == 0,
    do: accepted

  defp effective_requirements(requirements, _accepted), do: requirements

  @spec validation_success(map()) :: {:ok, map()}
  defp validation_success(payload) do
    Telemetry.emit(:payment_signature, :validate, :ok, %{x402_version: 2})
    {:ok, payload}
  end

  @spec validation_error(validate_error() | term()) :: {:error, validate_error() | term()}
  defp validation_error(reason) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: reason})
    {:error, reason}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header in one step.

  ## Examples

      iex> payload = %{"x402Version" => 2, "accepted" => %{"scheme" => "exact", "network" => "eip155:8453", "amount" => "1", "asset" => "asset", "payTo" => "receiver", "maxTimeoutSeconds" => 60, "extra" => %{}}, "payload" => %{}}
      iex> value = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentSignature.decode_and_validate(value)
      {:ok, payload}
  """
  @spec decode_and_validate(String.t()) :: {:ok, map()} | {:error, decode_and_validate_error()}
  def decode_and_validate(value), do: decode_and_validate(value, %{})

  @doc since: "0.1.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header against requirements.
  """
  @spec decode_and_validate(String.t(), map()) ::
          {:ok, map()} | {:error, decode_and_validate_error()}
  def decode_and_validate(value, requirements) when is_map(requirements) do
    decode_and_validate(value, requirements, [])
  end

  def decode_and_validate(_value, _requirements) do
    Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.6.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header with custom schemes.

  Behaves like `decode_and_validate/2`; `opts` are passed to `validate/3`.
  """
  @spec decode_and_validate(String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, decode_and_validate_error() | term()}
  def decode_and_validate(value, requirements, opts)
      when is_map(requirements) and is_list(opts) do
    with {:ok, decoded} <- decode(value),
         {:ok, validated} <- validate(decoded, requirements, opts) do
      result = {:ok, validated}
      Telemetry.emit(:payment_signature, :decode_and_validate, :ok, %{})
      result
    else
      {:error, reason} = error ->
        Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: reason})
        error
    end
  end

  def decode_and_validate(_value, _requirements, _opts) do
    Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  # Scheme-specific structural validation dispatches through the scheme
  # registry. Kinds with no registered scheme module pass through with :ok —
  # the historical behavior for unknown schemes.
  @spec validate_scheme(map(), map(), [module()]) :: :ok | {:error, term()}
  defp validate_scheme(payload, requirements, schemes) do
    scheme = effective_scheme(payload, requirements)
    network = effective_network(payload, requirements)

    case Scheme.Registry.resolve(schemes, scheme, network) do
      {:ok, module} -> Scheme.validate_payload(module, payload, requirements, [])
      :error -> :ok
    end
  end

  @spec effective_scheme(map(), map()) :: String.t() | atom() | nil
  defp effective_scheme(payload, requirements) do
    Utils.map_value(requirements, {"scheme", :scheme}) ||
      Utils.map_value(payload, {"scheme", :scheme}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"scheme", :scheme}])
  end

  @spec effective_network(map(), map()) :: String.t() | atom() | nil
  defp effective_network(payload, requirements) do
    Utils.map_value(requirements, {"network", :network}) ||
      Utils.map_value(payload, {"network", :network}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"network", :network}])
  end
end
