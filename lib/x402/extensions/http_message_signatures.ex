defmodule X402.Extensions.HTTPMessageSignatures do
  @moduledoc """
  The x402 `http-message-signatures` extension: identity through RFC 9421.

  Implements the
  [http-message-signatures extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/http-message-signatures.md).
  A network that authenticates paying agents with HTTP Message
  Signatures tells clients, in `PaymentRequired.extensions`, where to
  register their signature agent, which algorithms it accepts and which
  signature `tag` values it validates:

      %{
        "http-message-signatures" => %{
          "info" => %{
            "registrationUrl" => "https://network.example.com/signature-agents",
            "signatureSchemes" => ["ed25519"],
            "tags" => ["web-bot-auth"]
          },
          "schema" => %{...}
        }
      }

  The client hosts its keys at `/.well-known/http-message-signatures-directory`
  (`X402.HTTPSignature.directory/1`, `X402.Plug.HTTPSignatureDirectory`),
  registers the directory URL at `registrationUrl`, and signs its
  requests with `X402.HTTPSignature.sign/3` using one of the advertised
  algorithms and tags. Servers may sign their responses the same way to
  give `PAYMENT-REQUIRED` and `PAYMENT-RESPONSE` integrity.

  `schema` may be omitted from the advertisement to keep the header
  small (`extension/1` with `include_schema: false`); `decode/1` accepts
  both shapes.
  """

  alias X402.Utils

  @extension_key "http-message-signatures"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"

  @schema %{
    "$schema" => @schema_uri,
    "type" => "object",
    "properties" => %{
      "registrationUrl" => %{
        "type" => "string",
        "format" => "uri",
        "description" => "URL to the network's setup endpoint and documentation"
      },
      "signatureSchemes" => %{
        "type" => "array",
        "items" => %{"type" => "string"},
        "description" => "Supported cryptographic signature algorithms"
      },
      "tags" => %{
        "type" => "array",
        "items" => %{"type" => "string"},
        "description" => "Supported signature tags for validation"
      }
    },
    "required" => ["registrationUrl", "signatureSchemes"]
  }

  @extension_opts_schema [
    registration_url: [
      type: {:custom, __MODULE__, :validate_url, []},
      required: true,
      doc: "Where signature agents register their key directory (`info.registrationUrl`)."
    ],
    signature_schemes: [
      type: {:custom, __MODULE__, :validate_strings, ["signature scheme"]},
      required: true,
      doc:
        "Accepted algorithms (`info.signatureSchemes`), at least one, for example `[\"ed25519\"]`."
    ],
    tags: [
      type: {:custom, __MODULE__, :validate_strings, ["tag"]},
      default: [],
      doc: "Accepted signature tags (`info.tags`), for example `[\"web-bot-auth\"]`."
    ],
    include_schema: [
      type: :boolean,
      default: true,
      doc: "Whether to advertise the JSON schema alongside `info`."
    ]
  ]

  @typedoc "The decoded extension info."
  @type info :: %{
          registration_url: String.t(),
          signature_schemes: [String.t()],
          tags: [String.t()]
        }

  @type error :: :invalid_http_message_signatures_extension | {:missing_field, String.t()}

  @doc since: "0.9.0"
  @doc """
  Returns the extension key on the wire.

  ## Examples

      iex> X402.Extensions.HTTPMessageSignatures.extension_key()
      "http-message-signatures"
  """
  @spec extension_key() :: String.t()
  def extension_key, do: @extension_key

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema the server advertises for the extension.

  ## Examples

      iex> schema = X402.Extensions.HTTPMessageSignatures.schema()
      iex> schema["required"]
      ["registrationUrl", "signatureSchemes"]
      iex> schema["properties"]["registrationUrl"]["format"]
      "uri"
  """
  @spec schema() :: map()
  def schema, do: @schema

  @doc since: "0.9.0"
  @doc """
  Builds the server-side advertisement for `PaymentRequired.extensions`.

  Raises `NimbleOptions.ValidationError` for invalid options: a malformed
  declaration is a configuration error.

  ## Options

  #{NimbleOptions.docs(@extension_opts_schema)}

  ## Examples

      iex> extension = X402.Extensions.HTTPMessageSignatures.extension(
      ...>   registration_url: "https://network.example.com/signature-agents",
      ...>   signature_schemes: ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"],
      ...>   tags: ["web-bot-auth", "agent-browser-auth"]
      ...> )
      iex> extension["info"]
      %{
        "registrationUrl" => "https://network.example.com/signature-agents",
        "signatureSchemes" => ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"],
        "tags" => ["web-bot-auth", "agent-browser-auth"]
      }
      iex> extension["schema"] == X402.Extensions.HTTPMessageSignatures.schema()
      true

      iex> X402.Extensions.HTTPMessageSignatures.extension(
      ...>   registration_url: "https://network.example.com/signature-agents",
      ...>   signature_schemes: ["ed25519"],
      ...>   include_schema: false
      ...> )
      %{"info" => %{"registrationUrl" => "https://network.example.com/signature-agents", "signatureSchemes" => ["ed25519"], "tags" => []}}
  """
  @spec extension(keyword()) :: map()
  def extension(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @extension_opts_schema)

    info = %{
      "registrationUrl" => Keyword.fetch!(opts, :registration_url),
      "signatureSchemes" => Keyword.fetch!(opts, :signature_schemes),
      "tags" => Keyword.fetch!(opts, :tags)
    }

    case Keyword.fetch!(opts, :include_schema) do
      true -> %{"info" => info, "schema" => @schema}
      false -> %{"info" => info}
    end
  end

  @doc false
  @spec validate_url(term()) :: {:ok, String.t()} | {:error, String.t()}
  def validate_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, url}

      _other ->
        {:error, "expected an http(s) URL, got: #{inspect(url)}"}
    end
  end

  def validate_url(other), do: {:error, "expected an http(s) URL, got: #{inspect(other)}"}

  @doc false
  @spec validate_strings(term(), String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def validate_strings(values, _label) when is_list(values) and values != [] do
    case Enum.all?(values, &(is_binary(&1) and &1 != "")) do
      true -> {:ok, values}
      false -> {:error, "expected a list of non-empty strings, got: #{inspect(values)}"}
    end
  end

  def validate_strings([], "tag"), do: {:ok, []}

  def validate_strings(other, label),
    do: {:error, "expected a non-empty list of #{label}s, got: #{inspect(other)}"}

  @doc since: "0.9.0"
  @doc """
  Validates the value advertised under the extension key and extracts
  its info.

  Accepts the `%{"info" => ...}` envelope with or without `schema`, or a
  bare info map. `tags` defaults to `[]`.

  ## Examples

      iex> extension = X402.Extensions.HTTPMessageSignatures.extension(
      ...>   registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"], tags: ["web-bot-auth"])
      iex> X402.Extensions.HTTPMessageSignatures.validate(extension)
      {:ok, %{registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"], tags: ["web-bot-auth"]}}

      iex> X402.Extensions.HTTPMessageSignatures.validate(%{"info" => %{"registrationUrl" => "https://n.example/r"}})
      {:error, {:missing_field, "signatureSchemes"}}

      iex> X402.Extensions.HTTPMessageSignatures.validate(%{"info" => %{"registrationUrl" => "https://n.example/r", "signatureSchemes" => "ed25519"}})
      {:error, :invalid_http_message_signatures_extension}

      iex> X402.Extensions.HTTPMessageSignatures.validate("nope")
      {:error, :invalid_http_message_signatures_extension}
  """
  @spec validate(term()) :: {:ok, info()} | {:error, error()}
  def validate(value) when is_map(value) do
    info =
      case Utils.map_value(value, {"info", :info}) do
        %{} = info -> info
        _absent -> value
      end

    with {:ok, url} <- fetch_string(info, "registrationUrl", :registrationUrl),
         {:ok, schemes} <- fetch_strings(info, "signatureSchemes", :signatureSchemes),
         {:ok, tags} <- fetch_tags(info) do
      {:ok, %{registration_url: url, signature_schemes: schemes, tags: tags}}
    end
  end

  def validate(_value), do: {:error, :invalid_http_message_signatures_extension}

  @spec fetch_string(map(), String.t(), atom()) :: {:ok, String.t()} | {:error, error()}
  defp fetch_string(info, field, key) do
    case Utils.map_value(info, {field, key}) do
      value when is_binary(value) and value != "" -> {:ok, value}
      nil -> {:error, {:missing_field, field}}
      _other -> {:error, :invalid_http_message_signatures_extension}
    end
  end

  @spec fetch_strings(map(), String.t(), atom()) :: {:ok, [String.t()]} | {:error, error()}
  defp fetch_strings(info, field, key) do
    case Utils.map_value(info, {field, key}) do
      values when is_list(values) ->
        case Enum.all?(values, &is_binary/1) do
          true -> {:ok, values}
          false -> {:error, :invalid_http_message_signatures_extension}
        end

      nil ->
        {:error, {:missing_field, field}}

      _other ->
        {:error, :invalid_http_message_signatures_extension}
    end
  end

  @spec fetch_tags(map()) :: {:ok, [String.t()]} | {:error, error()}
  defp fetch_tags(info) do
    case fetch_strings(info, "tags", :tags) do
      {:error, {:missing_field, "tags"}} -> {:ok, []}
      result -> result
    end
  end

  @doc since: "0.9.0"
  @doc """
  Decodes the extension from a `PaymentRequired` map (or its
  `extensions` map).

  Returns `{:ok, nil}` when the extension is absent.

  ## Examples

      iex> extension = X402.Extensions.HTTPMessageSignatures.extension(
      ...>   registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"], include_schema: false)
      iex> payment_required = %{"accepts" => [], "extensions" => %{"http-message-signatures" => extension}}
      iex> X402.Extensions.HTTPMessageSignatures.decode(payment_required)
      {:ok, %{registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"], tags: []}}

      iex> X402.Extensions.HTTPMessageSignatures.decode(%{"accepts" => []})
      {:ok, nil}

      iex> X402.Extensions.HTTPMessageSignatures.decode(%{"extensions" => %{"http-message-signatures" => %{"info" => %{}}}})
      {:error, {:missing_field, "registrationUrl"}}
  """
  @spec decode(term()) :: {:ok, info() | nil} | {:error, error()}
  def decode(payment_required) when is_map(payment_required) do
    extensions =
      case Utils.map_value(payment_required, {"extensions", :extensions}) do
        %{} = extensions -> extensions
        _other -> payment_required
      end

    case Utils.map_value(extensions, {@extension_key, :"http-message-signatures"}) do
      nil -> {:ok, nil}
      value -> validate(value)
    end
  end

  def decode(_payment_required), do: {:error, :invalid_http_message_signatures_extension}
end
