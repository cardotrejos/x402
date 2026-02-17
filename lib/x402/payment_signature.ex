defmodule X402.PaymentSignature do
  @moduledoc """
  Decodes and validates x402 `PAYMENT-SIGNATURE` header values.

  The header value is Base64-encoded JSON. After decoding, this module validates
  the required x402 signature fields:

  - `"transactionHash"`
  - `"network"`
  - `"scheme"`
  - `"payerWallet"`

  For `"upto"` scheme payments, validation also enforces that the payment value
  does not exceed the configured maximum price.
  """

  alias X402.Telemetry

  @required_fields ~w(transactionHash network scheme payerWallet)
  @decimal_pattern ~r/^\d+(?:\.\d+)?$/

  @type scheme :: :exact | :upto | "exact" | "upto"
  @type decode_error :: :invalid_base64 | :invalid_json
  @type validate_error ::
          :invalid_payload
          | {:missing_fields, [String.t()]}
          | {:value_exceeds_max_price, String.t(), String.t()}
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

      iex> payload = %{"transactionHash" => "0xabc", "network" => "eip155:8453", "scheme" => "exact", "payerWallet" => "0x1111111111111111111111111111111111111111"}
      iex> value = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentSignature.decode(value)
      {:ok, payload}

      iex> X402.PaymentSignature.decode("not-base64")
      {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, map()} | {:error, decode_error()}
  def decode(value) when is_binary(value) do
    with {:ok, json} <- decode_base64(value),
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

  def decode(_value) do
    Telemetry.emit(:payment_signature, :decode, :error, %{
      reason: :invalid_base64,
      header: header_name()
    })

    {:error, :invalid_base64}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Validates that all required signature fields are present and non-empty.

  For `"upto"` payments, pass the requirement map as the optional second
  argument so this function can enforce `value <= maxPrice`.

  ## Examples

      iex> payload = %{
      ...>   "transactionHash" => "0xabc",
      ...>   "network" => "eip155:8453",
      ...>   "scheme" => "exact",
      ...>   "payerWallet" => "0x1111111111111111111111111111111111111111"
      ...> }
      iex> X402.PaymentSignature.validate(payload)
      {:ok, payload}

      iex> X402.PaymentSignature.validate(%{"network" => "eip155:8453"})
      {:error, {:missing_fields, ["payerWallet", "scheme", "transactionHash"]}}

      iex> upto_payload = %{
      ...>   "transactionHash" => "0xabc",
      ...>   "network" => "eip155:8453",
      ...>   "scheme" => "upto",
      ...>   "payerWallet" => "0x1111111111111111111111111111111111111111",
      ...>   "value" => "9"
      ...> }
      iex> X402.PaymentSignature.validate(upto_payload, %{"maxPrice" => "10"})
      {:ok, upto_payload}
  """
  @spec validate(map()) :: {:ok, map()} | {:error, validate_error()}
  @spec validate(map(), map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(payload, requirements \\ %{})

  def validate(payload, requirements) when is_map(payload) and is_map(requirements) do
    missing = missing_fields(payload)

    case missing do
      [] ->
        case validate_scheme_constraints(payload, requirements) do
          :ok ->
            result = {:ok, payload}

            Telemetry.emit(:payment_signature, :validate, :ok, %{
              required_fields: @required_fields
            })

            result

          {:error, reason} = error ->
            Telemetry.emit(:payment_signature, :validate, :error, %{reason: reason})
            error
        end

      _ ->
        Telemetry.emit(:payment_signature, :validate, :error, %{
          reason: :missing_fields,
          fields: missing
        })

        {:error, {:missing_fields, missing}}
    end
  end

  def validate(_payload, _requirements) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header in one step.

  For `"upto"` scheme payments, pass the optional requirement map as the
  second argument to enforce `value <= maxPrice`.

  ## Examples

      iex> payload = %{"transactionHash" => "0xabc", "network" => "eip155:8453", "scheme" => "exact", "payerWallet" => "0x1111111111111111111111111111111111111111"}
      iex> value = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentSignature.decode_and_validate(value)
      {:ok, payload}
  """
  @spec decode_and_validate(String.t()) ::
          {:ok, map()} | {:error, decode_and_validate_error()}
  @spec decode_and_validate(String.t(), map()) ::
          {:ok, map()} | {:error, decode_and_validate_error()}
  def decode_and_validate(value, requirements \\ %{})

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

  @spec validate_scheme_constraints(map(), map()) ::
          :ok | {:error, {:value_exceeds_max_price, String.t(), String.t()} | :invalid_payload}
  defp validate_scheme_constraints(payload, requirements) do
    case normalize_scheme(map_value(payload, "scheme", :scheme)) do
      "upto" -> validate_upto_amount(payload, requirements)
      _ -> :ok
    end
  end

  @spec validate_upto_amount(map(), map()) ::
          :ok | {:error, {:value_exceeds_max_price, String.t(), String.t()} | :invalid_payload}
  defp validate_upto_amount(payload, requirements) do
    with {:ok, payment_value} <- extract_payment_value(payload),
         {:ok, max_price} <- extract_max_price(requirements, payload),
         comparison when comparison in [:lt, :eq, :gt] <-
           compare_decimal_values(payment_value, max_price) do
      case comparison do
        :gt -> {:error, {:value_exceeds_max_price, payment_value, max_price}}
        _ -> :ok
      end
    else
      :error -> {:error, :invalid_payload}
    end
  end

  @spec extract_payment_value(map()) :: {:ok, String.t()} | :error
  defp extract_payment_value(payload) do
    value =
      first_present_value(payload, ["value", :value, "amount", :amount]) ||
        get_in(payload, ["payload", "value"]) ||
        get_in(payload, [:payload, :value]) ||
        get_in(payload, ["payload", "authorization", "value"]) ||
        get_in(payload, [:payload, :authorization, :value]) ||
        get_in(payload, ["authorization", "value"]) ||
        get_in(payload, [:authorization, :value])

    to_amount_string(value)
  end

  @spec extract_max_price(map(), map()) :: {:ok, String.t()} | :error
  defp extract_max_price(requirements, payload) do
    value =
      first_present_value(requirements, [
        "maxPrice",
        :maxPrice,
        :max_price,
        "price",
        :price,
        "maxAmountRequired",
        :maxAmountRequired
      ]) ||
        first_present_value(payload, [
          "maxPrice",
          :maxPrice,
          :max_price,
          "maxAmountRequired",
          :maxAmountRequired
        ])

    to_amount_string(value)
  end

  @spec to_amount_string(term()) :: {:ok, String.t()} | :error
  defp to_amount_string(value) when is_binary(value) do
    trimmed = String.trim(value)

    case trimmed do
      "" -> :error
      _ -> {:ok, trimmed}
    end
  end

  defp to_amount_string(value) when is_integer(value) and value >= 0 do
    {:ok, Integer.to_string(value)}
  end

  defp to_amount_string(_value), do: :error

  @spec compare_decimal_values(String.t(), String.t()) :: :lt | :eq | :gt | :error
  defp compare_decimal_values(left, right) do
    with {:ok, normalized_left} <- normalize_decimal(left),
         {:ok, normalized_right} <- normalize_decimal(right) do
      compare_normalized_decimals(normalized_left, normalized_right)
    end
  end

  @spec normalize_decimal(String.t()) :: {:ok, {String.t(), String.t()}} | :error
  defp normalize_decimal(value) when is_binary(value) do
    case Regex.match?(@decimal_pattern, value) do
      true ->
        [integer, fractional] =
          case String.split(value, ".", parts: 2) do
            [left, right] -> [left, right]
            [left] -> [left, ""]
          end

        normalized_integer =
          case String.trim_leading(integer, "0") do
            "" -> "0"
            non_empty -> non_empty
          end

        normalized_fractional = String.trim_trailing(fractional, "0")
        {:ok, {normalized_integer, normalized_fractional}}

      false ->
        :error
    end
  end

  defp normalize_decimal(_value), do: :error

  @spec compare_normalized_decimals({String.t(), String.t()}, {String.t(), String.t()}) ::
          :lt | :eq | :gt
  defp compare_normalized_decimals(
         {left_integer, left_fractional},
         {right_integer, right_fractional}
       ) do
    cond do
      byte_size(left_integer) < byte_size(right_integer) ->
        :lt

      byte_size(left_integer) > byte_size(right_integer) ->
        :gt

      left_integer < right_integer ->
        :lt

      left_integer > right_integer ->
        :gt

      true ->
        compare_fractional_parts(left_fractional, right_fractional)
    end
  end

  @spec compare_fractional_parts(String.t(), String.t()) :: :lt | :eq | :gt
  defp compare_fractional_parts(left_fractional, right_fractional) do
    size = max(byte_size(left_fractional), byte_size(right_fractional))
    left = String.pad_trailing(left_fractional, size, "0")
    right = String.pad_trailing(right_fractional, size, "0")

    cond do
      left < right -> :lt
      left > right -> :gt
      true -> :eq
    end
  end

  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  defp decode_base64(""), do: {:error, :invalid_base64}

  defp decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end

  @spec missing_fields(map()) :: [String.t()]
  defp missing_fields(payload) do
    @required_fields
    |> Enum.reject(&required_field_present?(payload, &1))
    |> Enum.sort()
  end

  @spec required_field_present?(map(), String.t()) :: boolean()
  defp required_field_present?(payload, "transactionHash") do
    non_empty_binary?(map_value(payload, "transactionHash", :transactionHash))
  end

  defp required_field_present?(payload, "network") do
    non_empty_binary?(map_value(payload, "network", :network))
  end

  defp required_field_present?(payload, "scheme") do
    case map_value(payload, "scheme", :scheme) do
      value when is_binary(value) and value != "" -> true
      :exact -> true
      :upto -> true
      _ -> false
    end
  end

  defp required_field_present?(payload, "payerWallet") do
    non_empty_binary?(map_value(payload, "payerWallet", :payerWallet))
  end

  @spec non_empty_binary?(term()) :: boolean()
  defp non_empty_binary?(value) when is_binary(value), do: value != ""
  defp non_empty_binary?(_value), do: false

  @spec map_value(map(), String.t(), atom()) :: term() | nil
  defp map_value(map, string_key, atom_key) do
    cond do
      Map.has_key?(map, string_key) -> Map.get(map, string_key)
      Map.has_key?(map, atom_key) -> Map.get(map, atom_key)
      true -> nil
    end
  end

  @spec normalize_scheme(term()) :: "exact" | "upto" | nil
  defp normalize_scheme("exact"), do: "exact"
  defp normalize_scheme("upto"), do: "upto"
  defp normalize_scheme(:exact), do: "exact"
  defp normalize_scheme(:upto), do: "upto"
  defp normalize_scheme(_value), do: nil

  @spec first_present_value(map(), [atom() | String.t()]) :: term() | nil
  defp first_present_value(map, keys) do
    Enum.find_value(keys, fn key ->
      case Map.fetch(map, key) do
        {:ok, value} -> value
        :error -> nil
      end
    end)
  end
end
