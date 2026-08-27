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
  """

  alias X402.PaymentRequirements
  alias X402.Telemetry
  alias X402.Utils

  # Single source of truth for the 8 KB decode guard — see X402.Header.
  @max_header_bytes X402.Header.max_header_bytes()

  @type decode_error :: :invalid_base64 | :invalid_json | :payload_too_large
  @type upto_validation_error ::
          :missing_max_price
          | :missing_payment_value
          | :invalid_max_price
          | :invalid_payment_value
          | :payment_value_exceeds_max_price

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
  def validate(payload) when is_map(payload), do: do_validate(payload, %{})

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
    do_validate(payload, requirements)
  end

  def validate(_payload, _requirements) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @spec do_validate(map(), map()) :: {:ok, map()} | {:error, validate_error()}
  defp do_validate(payload, requirements) do
    case Utils.map_value(payload, {"x402Version", :x402Version}) do
      2 -> validate_v2(payload, requirements)
      version when version in [nil, 1] -> validation_error({:unsupported_x402_version, version})
      _version -> validation_error(:invalid_x402_version)
    end
  end

  @spec validate_v2(map(), map()) :: {:ok, map()} | {:error, validate_error()}
  defp validate_v2(payload, requirements) do
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
         :ok <- validate_scheme(payload, effective_requirements(requirements, accepted)) do
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

  @spec validation_error(validate_error()) :: {:error, validate_error()}
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
    with {:ok, decoded} <- decode(value),
         {:ok, validated} <- validate(decoded, requirements) do
      result = {:ok, validated}
      Telemetry.emit(:payment_signature, :decode_and_validate, :ok, %{})
      result
    else
      {:error, reason} = error ->
        Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: reason})
        error
    end
  end

  def decode_and_validate(_value, _requirements) do
    Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @spec validate_scheme(map(), map()) ::
          :ok | {:error, {:invalid_upto_payment, upto_validation_error()}}
  defp validate_scheme(payload, requirements) do
    case effective_scheme(payload, requirements) do
      "upto" ->
        with {:ok, max_price} <- extract_max_price(payload, requirements),
             {:ok, payment_value} <- extract_payment_value(payload) do
          ensure_not_exceeds(payment_value, max_price)
        end

      _scheme ->
        :ok
    end
  end

  @spec effective_scheme(map(), map()) :: String.t() | atom() | nil
  defp effective_scheme(payload, requirements) do
    Utils.map_value(requirements, {"scheme", :scheme}) ||
      Utils.map_value(payload, {"scheme", :scheme}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"scheme", :scheme}])
  end

  @spec extract_max_price(map(), map()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:invalid_upto_payment, upto_validation_error()}}
  defp extract_max_price(payload, requirements) do
    value =
      Utils.first_present([
        Utils.map_value(requirements, {"amount", :amount}),
        Utils.map_value(requirements, {"maxPrice", :maxPrice}),
        Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired}),
        Utils.nested_map_value(payload, [{"accepted", :accepted}, {"amount", :amount}]),
        Utils.map_value(payload, {"maxPrice", :maxPrice}),
        Utils.map_value(payload, {"maxAmountRequired", :maxAmountRequired})
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_max_price}}

      max_price ->
        case Utils.parse_decimal(max_price) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_max_price}}
        end
    end
  end

  @spec extract_payment_value(map()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:invalid_upto_payment, upto_validation_error()}}
  defp extract_payment_value(payload) do
    value =
      Utils.first_present([
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"maxAmount", :maxAmount}]),
        Utils.map_value(payload, {"maxAmount", :maxAmount}),
        Utils.map_value(payload, {"value", :value}),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"value", :value}]),
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"authorization", :authorization},
          {"value", :value}
        ]),
        Utils.nested_map_value(payload, [{"authorization", :authorization}, {"value", :value}])
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_payment_value}}

      payment_value ->
        case Utils.parse_decimal(payment_value) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_payment_value}}
        end
    end
  end

  @spec ensure_not_exceeds(
          {non_neg_integer(), non_neg_integer()},
          {non_neg_integer(), non_neg_integer()}
        ) :: :ok | {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
  defp ensure_not_exceeds(payment_value, max_price) do
    case Utils.compare_decimal(payment_value, max_price) do
      :gt -> {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
      _comparison -> :ok
    end
  end
end
