defmodule X402.PaymentSignature do
  @moduledoc """
  Decodes and validates x402 `PAYMENT-SIGNATURE` header values.

  The header value is Base64-encoded JSON. After decoding, this module validates
  the required x402 signature fields:

  - `"transactionHash"`
  - `"network"`
  - `"scheme"`
  - `"payerWallet"`
  """

  alias X402.Telemetry

  @required_fields ~w(transactionHash network scheme payerWallet)

  @type decode_error :: :invalid_base64 | :invalid_json
  @type validate_error :: :invalid_payload | {:missing_fields, [String.t()]}
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
  """
  @spec validate(map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(payload) when is_map(payload) do
    missing = missing_fields(payload)

    case missing do
      [] ->
        result = {:ok, payload}
        Telemetry.emit(:payment_signature, :validate, :ok, %{required_fields: @required_fields})
        result

      _ ->
        Telemetry.emit(:payment_signature, :validate, :error, %{
          reason: :missing_fields,
          fields: missing
        })

        {:error, {:missing_fields, missing}}
    end
  end

  def validate(_payload) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header in one step.

  ## Examples

      iex> payload = %{"transactionHash" => "0xabc", "network" => "eip155:8453", "scheme" => "exact", "payerWallet" => "0x1111111111111111111111111111111111111111"}
      iex> value = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentSignature.decode_and_validate(value)
      {:ok, payload}
  """
  @spec decode_and_validate(String.t()) :: {:ok, map()} | {:error, decode_and_validate_error()}
  def decode_and_validate(value) do
    with {:ok, decoded} <- decode(value),
         {:ok, validated} <- validate(decoded) do
      result = {:ok, validated}
      Telemetry.emit(:payment_signature, :decode_and_validate, :ok, %{})
      result
    else
      {:error, reason} = error ->
        Telemetry.emit(:payment_signature, :decode_and_validate, :error, %{reason: reason})
        error
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
    payload_keys = Map.keys(payload)

    @required_fields
    |> Enum.reject(fn field ->
      value = Map.get(payload, field)
      field in payload_keys and is_binary(value) and value != ""
    end)
    |> Enum.sort()
  end
end
