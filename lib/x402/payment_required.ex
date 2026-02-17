defmodule X402.PaymentRequired do
  @moduledoc """
  Encodes and decodes the x402 `PAYMENT-REQUIRED` header value.

  The header value is Base64-encoded JSON. This module provides safe conversion
  functions that return tagged tuples instead of raising, including scheme-aware
  normalization for `"exact"` and `"upto"` payment requirements.
  """

  alias X402.Telemetry

  @type scheme :: :exact | :upto | "exact" | "upto"
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

  `"exact"` requirements are normalized to use `"maxAmountRequired"`.
  `"upto"` requirements are normalized to use `"maxPrice"`.

  ## Examples

      iex> {:ok, value} = X402.PaymentRequired.encode(%{"scheme" => "exact", "maxAmountRequired" => "10"})
      iex> {:ok, decoded} = X402.PaymentRequired.decode(value)
      iex> decoded["maxAmountRequired"]
      "10"

      iex> {:ok, value} = X402.PaymentRequired.encode(%{"scheme" => "upto", "maxPrice" => "10"})
      iex> {:ok, decoded} = X402.PaymentRequired.decode(value)
      iex> decoded["maxPrice"]
      "10"

      iex> X402.PaymentRequired.encode(nil)
      {:error, :invalid_payload}
  """
  @spec encode(map()) :: {:ok, String.t()} | {:error, encode_error()}
  def encode(payload) when is_map(payload) do
    normalized_payload = normalize_payload(payload)

    case Jason.encode(normalized_payload) do
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
  Returns `{:error, :invalid_json}` when JSON cannot be decoded to a map. On
  successful decode, `"exact"` and `"upto"` requirements are normalized to
  their canonical amount keys.

  ## Examples

      iex> {:ok, encoded} = X402.PaymentRequired.encode(%{"scheme" => "exact"})
      iex> X402.PaymentRequired.decode(encoded)
      {:ok, %{"scheme" => "exact"}}

      iex> payload = %{"scheme" => "upto", "maxAmountRequired" => "10"}
      iex> encoded = payload |> Jason.encode!() |> Base.encode64()
      iex> X402.PaymentRequired.decode(encoded)
      {:ok, %{"maxPrice" => "10", "scheme" => "upto"}}

      iex> X402.PaymentRequired.decode("%%%")
      {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, map()} | {:error, decode_error()}
  def decode(value) when is_binary(value) do
    with {:ok, json} <- decode_base64(value),
         {:ok, decoded} <- Jason.decode(json),
         true <- is_map(decoded) do
      result = {:ok, normalize_payload(decoded)}
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

  @spec normalize_payload(map()) :: map()
  defp normalize_payload(payload) do
    payload
    |> normalize_accepts()
    |> normalize_accept_entry()
  end

  @spec normalize_accepts(map()) :: map()
  defp normalize_accepts(payload) do
    case fetch_map_value(payload, "accepts", :accepts) do
      {:ok, accepts} when is_list(accepts) ->
        normalized_accepts =
          Enum.map(accepts, fn
            entry when is_map(entry) -> normalize_accept_entry(entry)
            other -> other
          end)

        payload
        |> Map.put("accepts", normalized_accepts)
        |> Map.delete(:accepts)

      _ ->
        payload
    end
  end

  @spec normalize_accept_entry(map()) :: map()
  defp normalize_accept_entry(entry) do
    case normalize_scheme(map_value(entry, "scheme", :scheme)) do
      "exact" ->
        entry
        |> Map.put("scheme", "exact")
        |> Map.delete(:scheme)
        |> normalize_exact_amount()

      "upto" ->
        entry
        |> Map.put("scheme", "upto")
        |> Map.delete(:scheme)
        |> normalize_upto_amount()

      nil ->
        entry
    end
  end

  @spec normalize_exact_amount(map()) :: map()
  defp normalize_exact_amount(entry) do
    amount =
      first_present_value(entry, [
        "maxAmountRequired",
        :maxAmountRequired,
        "price",
        :price,
        "maxPrice",
        :maxPrice
      ])

    entry =
      entry
      |> Map.delete(:maxAmountRequired)
      |> Map.delete("price")
      |> Map.delete(:price)
      |> Map.delete("maxPrice")
      |> Map.delete(:maxPrice)

    case amount do
      nil -> entry
      value -> Map.put(entry, "maxAmountRequired", value)
    end
  end

  @spec normalize_upto_amount(map()) :: map()
  defp normalize_upto_amount(entry) do
    amount =
      first_present_value(entry, [
        "maxPrice",
        :maxPrice,
        "price",
        :price,
        "maxAmountRequired",
        :maxAmountRequired
      ])

    entry =
      entry
      |> Map.delete(:maxPrice)
      |> Map.delete("price")
      |> Map.delete(:price)
      |> Map.delete("maxAmountRequired")
      |> Map.delete(:maxAmountRequired)

    case amount do
      nil -> entry
      value -> Map.put(entry, "maxPrice", value)
    end
  end

  @spec normalize_scheme(term()) :: "exact" | "upto" | nil
  defp normalize_scheme("exact"), do: "exact"
  defp normalize_scheme("upto"), do: "upto"
  defp normalize_scheme(:exact), do: "exact"
  defp normalize_scheme(:upto), do: "upto"
  defp normalize_scheme(_value), do: nil

  @spec fetch_map_value(map(), String.t(), atom()) :: {:ok, term()} | :error
  defp fetch_map_value(map, string_key, atom_key) do
    cond do
      Map.has_key?(map, string_key) -> {:ok, Map.get(map, string_key)}
      Map.has_key?(map, atom_key) -> {:ok, Map.get(map, atom_key)}
      true -> :error
    end
  end

  @spec map_value(map(), String.t(), atom()) :: term() | nil
  defp map_value(map, string_key, atom_key) do
    case fetch_map_value(map, string_key, atom_key) do
      {:ok, value} -> value
      :error -> nil
    end
  end

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
