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
  alias X402.Utils

  @required_fields ~w(transactionHash network scheme payerWallet)

  # EIP-55 Ethereum address: 0x followed by exactly 40 hex characters (case-insensitive).
  # We accept mixed-case (checksummed) and lower-case (normalised) addresses.
  @eth_address_regex ~r/^0x[0-9a-fA-F]{40}$/

  # Transaction hash: 0x followed by exactly 64 hex characters (256-bit hash).
  # Solana tx IDs are base58, 87-88 chars — we detect them by absence of "0x" prefix.
  @eth_tx_hash_regex ~r/^0x[0-9a-fA-F]{64}$/

  # Solana base-58 transaction signature (87–88 characters of base58 alphabet).
  @solana_tx_sig_regex ~r/^[1-9A-HJ-NP-Za-km-z]{87,88}$/

  # Solana wallet address: base58, 32-44 characters.
  @solana_address_regex ~r/^[1-9A-HJ-NP-Za-km-z]{43,44}$/

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
          | {:missing_fields, [String.t()]}
          | {:invalid_upto_payment, upto_validation_error()}
          | {:invalid_format, [{field :: String.t(), reason :: atom()}]}

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

      iex> payload = %{"transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "network" => "eip155:8453", "scheme" => "exact", "payerWallet" => "0x1111111111111111111111111111111111111111"}
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
  Validates that all required signature fields are present and non-empty.

  ## Examples

      iex> payload = %{
      ...>   "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
  def validate(payload) when is_map(payload), do: validate(payload, %{})

  def validate(_payload) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Validates a decoded `PAYMENT-SIGNATURE` payload against payment requirements.

  For the `"upto"` scheme, this ensures the payment value is less than or equal
  to `maxPrice`.
  """
  @spec validate(map(), map()) :: {:ok, map()} | {:error, validate_error()}
  def validate(payload, requirements) when is_map(payload) and is_map(requirements) do
    with :ok <- check_missing_fields(payload),
         :ok <- check_field_formats(payload) do
      case validate_scheme(payload, requirements) do
        :ok ->
          Telemetry.emit(:payment_signature, :validate, :ok, %{required_fields: @required_fields})
          {:ok, payload}

        {:error, {:invalid_upto_payment, reason}} = error ->
          Telemetry.emit(:payment_signature, :validate, :error, %{
            reason: :invalid_upto_payment,
            detail: reason
          })

          error
      end
    end
  end

  def validate(_payload, _requirements) do
    Telemetry.emit(:payment_signature, :validate, :error, %{reason: :invalid_payload})
    {:error, :invalid_payload}
  end

  defp check_missing_fields(payload) do
    case missing_fields(payload) do
      [] ->
        :ok

      missing ->
        Telemetry.emit(:payment_signature, :validate, :error, %{
          reason: :missing_fields,
          fields: missing
        })

        {:error, {:missing_fields, missing}}
    end
  end

  defp check_field_formats(payload) do
    case validate_field_formats(payload) do
      [] ->
        :ok

      format_errors ->
        Telemetry.emit(:payment_signature, :validate, :error, %{
          reason: :invalid_format,
          fields: Enum.map(format_errors, &elem(&1, 0))
        })

        {:error, {:invalid_format, format_errors}}
    end
  end

  @doc since: "0.1.0", group: :verification
  @doc """
  Decodes and validates a `PAYMENT-SIGNATURE` header in one step.

  ## Examples

      iex> payload = %{"transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "network" => "eip155:8453", "scheme" => "exact", "payerWallet" => "0x1111111111111111111111111111111111111111"}
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

  # Validates the format of fields that have known structural constraints:
  #   - transactionHash: EVM 0x+64hex OR Solana base58 87-88 chars
  #   - payerWallet: EVM 0x+40hex OR Solana base58 32-44 chars
  #
  # We intentionally do NOT validate `network` and `scheme` here — those fields
  # are validated downstream by the facilitator / scheme validators which have
  # the authoritative list of supported values.
  #
  # Returns a list of {field, reason} tuples for each invalid field; empty list = ok.
  @spec validate_field_formats(map()) :: [{String.t(), atom()}]
  defp validate_field_formats(payload) do
    [
      validate_transaction_hash(Map.get(payload, "transactionHash")),
      validate_payer_wallet(Map.get(payload, "payerWallet"))
    ]
    |> Enum.reject(&is_nil/1)
  end

  @spec validate_transaction_hash(String.t() | nil) :: {String.t(), atom()} | nil
  defp validate_transaction_hash(nil), do: nil

  defp validate_transaction_hash(hash) when is_binary(hash) do
    cond do
      Regex.match?(@eth_tx_hash_regex, hash) -> nil
      Regex.match?(@solana_tx_sig_regex, hash) -> nil
      true -> {"transactionHash", :invalid_format}
    end
  end

  defp validate_transaction_hash(_), do: {"transactionHash", :invalid_format}

  @spec validate_payer_wallet(String.t() | nil) :: {String.t(), atom()} | nil
  defp validate_payer_wallet(nil), do: nil

  defp validate_payer_wallet(wallet) when is_binary(wallet) do
    cond do
      Regex.match?(@eth_address_regex, wallet) -> nil
      Regex.match?(@solana_address_regex, wallet) -> nil
      true -> {"payerWallet", :invalid_format}
    end
  end

  defp validate_payer_wallet(_), do: {"payerWallet", :invalid_format}

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
      Utils.map_value(payload, {"scheme", :scheme})
  end

  @spec extract_max_price(map(), map()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:invalid_upto_payment, upto_validation_error()}}
  defp extract_max_price(payload, requirements) do
    value =
      Utils.first_present([
        Utils.map_value(requirements, {"maxPrice", :maxPrice}),
        Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired}),
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
