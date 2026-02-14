defmodule X402.PaymentRequired do
  @moduledoc """
  Encodes and decodes the x402 `PAYMENT-REQUIRED` header value.

  The header value is Base64-encoded JSON. This module provides safe conversion
  functions that return tagged tuples instead of raising.
  """

  alias X402.Telemetry

  @type encode_error :: :invalid_payload | :invalid_json
  @type decode_error :: :invalid_base64 | :invalid_json

  @doc since: "0.1.0", group: :headers
  @doc """
  Returns the canonical x402 header name.

  ## Examples

      iex> X402.PaymentRequired.header_name()
      "PAYMENT-REQUIRED"
  """
  @spec header_name() :: String.t()
  def header_name, do: "PAYMENT-REQUIRED"

  @doc since: "0.1.0", group: :headers
  @doc """
  Encodes a payment requirement payload to a Base64 header value.

  ## Examples

      iex> {:ok, value} = X402.PaymentRequired.encode(%{"scheme" => "exact", "maxAmountRequired" => "10"})
      iex> {:ok, decoded} = X402.PaymentRequired.decode(value)
      iex> decoded["maxAmountRequired"]
      "10"

      iex> X402.PaymentRequired.encode(nil)
      {:error, :invalid_payload}
  """
  @spec encode(map()) :: {:ok, String.t()} | {:error, encode_error()}
  def encode(payload) when is_map(payload) do
    case Jason.encode(payload) do
      {:ok, json} ->
        result = {:ok, Base.encode64(json)}
        Telemetry.emit(:payment_required, :encode, :ok, %{header: header_name()})
        result

      {:error, _reason} ->
        Telemetry.emit(:payment_required, :encode, :error, %{
          reason: :invalid_json,
          header: header_name()
        })

        {:error, :invalid_json}
    end
  end

  def encode(_payload) do
    Telemetry.emit(:payment_required, :encode, :error, %{
      reason: :invalid_payload,
      header: header_name()
    })

    {:error, :invalid_payload}
  end

  @doc since: "0.1.0", group: :headers
  @doc """
  Decodes a Base64 `PAYMENT-REQUIRED` value to a map.

  Returns `{:error, :invalid_base64}` when the value cannot be Base64-decoded.
  Returns `{:error, :invalid_json}` when JSON cannot be decoded to a map.

  ## Examples

      iex> {:ok, encoded} = X402.PaymentRequired.encode(%{"scheme" => "exact"})
      iex> X402.PaymentRequired.decode(encoded)
      {:ok, %{"scheme" => "exact"}}

      iex> X402.PaymentRequired.decode("%%%")
      {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, map()} | {:error, decode_error()}
  def decode(value) when is_binary(value) do
    with {:ok, json} <- decode_base64(value),
         {:ok, decoded} <- Jason.decode(json),
         true <- is_map(decoded) do
      result = {:ok, decoded}
      Telemetry.emit(:payment_required, :decode, :ok, %{header: header_name()})
      result
    else
      {:error, :invalid_base64} = error ->
        Telemetry.emit(:payment_required, :decode, :error, %{
          reason: :invalid_base64,
          header: header_name()
        })

        error

      {:error, %Jason.DecodeError{}} ->
        Telemetry.emit(:payment_required, :decode, :error, %{
          reason: :invalid_json,
          header: header_name()
        })

        {:error, :invalid_json}

      false ->
        Telemetry.emit(:payment_required, :decode, :error, %{
          reason: :invalid_json,
          header: header_name()
        })

        {:error, :invalid_json}
    end
  end

  def decode(_value) do
    Telemetry.emit(:payment_required, :decode, :error, %{
      reason: :invalid_base64,
      header: header_name()
    })

    {:error, :invalid_base64}
  end

  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  defp decode_base64(""), do: {:error, :invalid_base64}

  defp decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end
end
