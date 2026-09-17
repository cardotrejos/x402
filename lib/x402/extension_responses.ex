defmodule X402.ExtensionResponses do
  @moduledoc """
  Encodes and decodes the `EXTENSION-RESPONSES` facilitator sidechannel.

  Facilitators may report extension-specific processing outcomes on
  `/verify` and `/settle` responses through a transport sidechannel that is
  not part of the JSON body (x402 v2 §7.2.1). On HTTP that sidechannel is
  the `EXTENSION-RESPONSES` header: Base64-encoded JSON keyed by extension
  name, each value being that extension's outcome object — for example the
  bazaar extension reports `{"bazaar": {"status": "success"}}`.

  The sidechannel is for the resource server only and is **never forwarded
  to the buyer**: `X402.Facilitator` surfaces it as the `:extension_responses`
  key of verify/settle results, and `X402.Plug.PaymentGate` keeps it out of
  the `PAYMENT-RESPONSE` header.

  Decoding is lenient by design at the call sites: the sidechannel is
  advisory, so a malformed header is logged and dropped rather than failing
  the payment. The functions here still report structured errors so callers
  can make that choice.
  """

  alias X402.Telemetry
  alias X402.Utils

  @max_header_bytes X402.Header.max_header_bytes()

  @typedoc "Extension outcomes keyed by extension name."
  @type t :: %{optional(String.t()) => map()}

  @type encode_error :: :invalid_responses | :invalid_json
  @type decode_error :: :invalid_base64 | :invalid_json | :invalid_responses | :payload_too_large

  @doc since: "0.7.0", group: :headers
  @doc """
  Returns the canonical sidechannel header name.

  ## Examples

      iex> X402.ExtensionResponses.header_name()
      "EXTENSION-RESPONSES"
  """
  @spec header_name() :: String.t()
  def header_name, do: "EXTENSION-RESPONSES"

  @doc since: "0.7.0", group: :headers
  @doc """
  Encodes extension outcomes to a Base64 header value.

  The argument must be a map from extension name to an outcome map.

  ## Examples

      iex> {:ok, value} = X402.ExtensionResponses.encode(%{"bazaar" => %{"status" => "success"}})
      iex> value
      "eyJiYXphYXIiOnsic3RhdHVzIjoic3VjY2VzcyJ9fQ=="

      iex> X402.ExtensionResponses.encode(%{"bazaar" => "success"})
      {:error, :invalid_responses}
  """
  @spec encode(t()) :: {:ok, String.t()} | {:error, encode_error()}
  def encode(responses) when is_map(responses) do
    if outcomes?(responses) do
      case Jason.encode(responses) do
        {:ok, json} -> {:ok, Base.encode64(json)}
        {:error, _reason} -> {:error, :invalid_json}
      end
    else
      {:error, :invalid_responses}
    end
  end

  def encode(_responses), do: {:error, :invalid_responses}

  @doc since: "0.7.0", group: :headers
  @doc """
  Decodes a Base64 `EXTENSION-RESPONSES` value to a map of outcomes.

  Returns `{:error, :payload_too_large}` above 8 KB, `{:error, :invalid_base64}`
  or `{:error, :invalid_json}` for undecodable values, and
  `{:error, :invalid_responses}` when the JSON is not an object of objects.

  ## Examples

      iex> X402.ExtensionResponses.decode("eyJiYXphYXIiOnsic3RhdHVzIjoic3VjY2VzcyJ9fQ==")
      {:ok, %{"bazaar" => %{"status" => "success"}}}

      iex> X402.ExtensionResponses.decode(Base.encode64(~s({"bazaar":"success"})))
      {:error, :invalid_responses}

      iex> X402.ExtensionResponses.decode("%%%")
      {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, t()} | {:error, decode_error()}
  def decode(value) when is_binary(value) and byte_size(value) > @max_header_bytes,
    do: {:error, :payload_too_large}

  def decode(value) when is_binary(value) do
    with {:ok, json} <- Utils.decode_base64(value),
         {:ok, decoded} <- decode_json(json) do
      if is_map(decoded) and outcomes?(decoded),
        do: {:ok, decoded},
        else: {:error, :invalid_responses}
    end
  end

  def decode(_value), do: {:error, :invalid_base64}

  @doc since: "0.7.0", group: :headers
  @doc """
  Extracts and decodes the sidechannel from a list of response headers.

  Header names are matched case-insensitively. Returns `{:ok, nil}` when
  the header is absent.

  ## Examples

      iex> X402.ExtensionResponses.from_headers([{"content-type", "application/json"}])
      {:ok, nil}

      iex> X402.ExtensionResponses.from_headers([
      ...>   {"extension-responses", "eyJiYXphYXIiOnsic3RhdHVzIjoic3VjY2VzcyJ9fQ=="}
      ...> ])
      {:ok, %{"bazaar" => %{"status" => "success"}}}

      iex> X402.ExtensionResponses.from_headers([{"EXTENSION-RESPONSES", "%%%"}])
      {:error, :invalid_base64}
  """
  @spec from_headers([{String.t(), String.t()}]) :: {:ok, t() | nil} | {:error, decode_error()}
  def from_headers(headers) when is_list(headers) do
    case Enum.find(headers, &header_match?/1) do
      nil -> {:ok, nil}
      {_name, value} -> decode(value)
    end
  end

  def from_headers(_headers), do: {:ok, nil}

  @doc since: "0.7.0", group: :headers
  @doc """
  Decodes the sidechannel from response headers, dropping malformed values.

  The advisory nature of the sidechannel means a malformed header must not
  fail the payment: this returns the decoded outcomes, or `nil` when the
  header is absent or invalid, emitting a
  `[:x402, :extension_responses, :decode]` telemetry event with
  `status: :error` and the `:reason` in the latter case.

  ## Examples

      iex> X402.ExtensionResponses.from_headers_lenient([{"extension-responses", "%%%"}])
      nil
  """
  @spec from_headers_lenient([{String.t(), String.t()}]) :: t() | nil
  def from_headers_lenient(headers) do
    case from_headers(headers) do
      {:ok, responses} ->
        responses

      {:error, reason} ->
        Telemetry.emit(:extension_responses, :decode, :error, %{
          reason: reason,
          header: header_name()
        })

        nil
    end
  end

  @spec header_match?(term()) :: boolean()
  defp header_match?({name, value}) when is_binary(name) and is_binary(value),
    do: String.downcase(name) == "extension-responses"

  defp header_match?(_header), do: false

  @spec outcomes?(map()) :: boolean()
  defp outcomes?(responses) do
    Enum.all?(responses, fn
      {name, outcome} -> is_binary(name) and is_map(outcome)
    end)
  end

  @spec decode_json(binary()) :: {:ok, term()} | {:error, :invalid_json}
  defp decode_json(json) do
    case Jason.decode(json) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end
end
