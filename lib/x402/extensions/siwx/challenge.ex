defmodule X402.Extensions.SIWX.Challenge do
  @moduledoc """
  Server-side Sign-In-With-X challenge advertisements.

  A challenge is the value a server places under
  `PaymentRequired.extensions["sign-in-with-x"]`: the CAIP-122 message
  metadata (`info`), the chains it accepts proofs from (`supportedChains`),
  and the JSON schema of the proof (`schema`). `build/1` produces one with a
  fresh nonce and timestamps; `X402.Extensions.SIWX.challenge/1` is the
  public entry point.
  """

  alias X402.Extensions.SIWX.Message
  alias X402.Utils

  @version "1"
  @default_expiration_seconds 300
  @nonce_bytes 16
  @schema_uri "https://json-schema.org/draft/2020-12/schema"
  @signature_schemes ["eip191", "eip1271", "eip6492", "siws"]

  @schema %{
    "$schema" => @schema_uri,
    "type" => "object",
    "properties" => %{
      "domain" => %{"type" => "string"},
      "address" => %{"type" => "string"},
      "statement" => %{"type" => "string"},
      "uri" => %{"type" => "string", "format" => "uri"},
      "version" => %{"type" => "string"},
      "chainId" => %{"type" => "string"},
      "type" => %{"type" => "string"},
      "nonce" => %{"type" => "string"},
      "issuedAt" => %{"type" => "string", "format" => "date-time"},
      "expirationTime" => %{"type" => "string", "format" => "date-time"},
      "notBefore" => %{"type" => "string", "format" => "date-time"},
      "requestId" => %{"type" => "string"},
      "resources" => %{
        "type" => "array",
        "items" => %{"type" => "string", "format" => "uri"}
      },
      "signature" => %{"type" => "string"}
    },
    "required" => [
      "domain",
      "address",
      "uri",
      "version",
      "chainId",
      "type",
      "nonce",
      "issuedAt",
      "signature"
    ]
  }

  @opts_schema [
    domain: [
      type: :string,
      required: true,
      doc: "The server's public host (`info.domain`), e.g. `\"api.example.com\"`."
    ],
    uri: [
      type: :string,
      required: true,
      doc: "The URI the proof is bound to (`info.uri`), e.g. `\"https://api.example.com\"`."
    ],
    supported_chains: [
      type: {:custom, __MODULE__, :validate_supported_chains, []},
      required: true,
      doc: """
      Chains proofs are accepted from: a list of maps or keyword lists with
      `:chain_id` (CAIP-2, `eip155:*` or `solana:*`), an optional `:type`
      (`"eip191"` for `eip155`, `"ed25519"` for `solana`; derived from the
      chain when omitted), and an optional `:signature_scheme` hint
      (`"eip191"`, `"eip1271"`, `"eip6492"`, or `"siws"`).
      """
    ],
    statement: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Human-readable purpose shown by the wallet (`info.statement`)."
    ],
    resources: [
      type: {:list, :string},
      default: [],
      doc: "URIs associated with the request (`info.resources`); omitted when empty."
    ],
    version: [
      type: :string,
      default: @version,
      doc: "CAIP-122 version. Always `\"1\"`."
    ],
    nonce: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Explicit nonce; a fresh `generate_nonce/0` value when omitted."
    ],
    issued_at: [
      type: {:or, [{:struct, DateTime}, nil]},
      default: nil,
      doc: "Challenge creation time; `DateTime.utc_now/0` when omitted."
    ],
    expiration_seconds: [
      type: :pos_integer,
      default: @default_expiration_seconds,
      doc: "Seconds after `issued_at` at which the challenge expires (`info.expirationTime`)."
    ],
    not_before: [
      type: {:or, [{:struct, DateTime}, nil]},
      default: nil,
      doc: "Optional `info.notBefore`."
    ],
    request_id: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Optional correlation id (`info.requestId`)."
    ]
  ]

  @typedoc "A normalized `supportedChains` entry."
  @type supported_chain :: %{
          required(String.t()) => String.t()
        }

  @doc false
  @spec opts_schema() :: keyword()
  def opts_schema, do: @opts_schema

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema advertised under `schema`.

  ## Examples

      iex> X402.Extensions.SIWX.Challenge.schema()["required"]
      ["domain", "address", "uri", "version", "chainId", "type", "nonce", "issuedAt", "signature"]
  """
  @spec schema() :: map()
  def schema, do: @schema

  @doc since: "0.9.0"
  @doc """
  Generates a nonce: 32 lowercase hex characters from 16 random bytes.

  ## Examples

      iex> nonce = X402.Extensions.SIWX.Challenge.generate_nonce()
      iex> Regex.match?(~r/\\A[a-f0-9]{32}\\z/, nonce)
      true
  """
  @spec generate_nonce() :: String.t()
  def generate_nonce do
    @nonce_bytes |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
  end

  @doc since: "0.9.0"
  @doc """
  Builds the `sign-in-with-x` advertisement map.

  Raises `NimbleOptions.ValidationError` for invalid options (programmer
  error). Timestamps are rendered in ISO 8601 with millisecond precision.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}

  ## Examples

      iex> challenge = X402.Extensions.SIWX.Challenge.build(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "eip155:8453"}],
      ...>   nonce: "a1b2c3d4e5f67890a1b2c3d4e5f67890",
      ...>   issued_at: ~U[2024-01-15 10:30:00Z]
      ...> )
      iex> challenge["info"]
      %{
        "domain" => "api.example.com",
        "uri" => "https://api.example.com",
        "version" => "1",
        "nonce" => "a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "issuedAt" => "2024-01-15T10:30:00.000Z",
        "expirationTime" => "2024-01-15T10:35:00.000Z"
      }
      iex> challenge["supportedChains"]
      [%{"chainId" => "eip155:8453", "type" => "eip191"}]
  """
  @spec build(keyword()) :: map()
  def build(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @opts_schema)
    issued_at = Keyword.fetch!(opts, :issued_at) || DateTime.utc_now()
    expiration = DateTime.add(issued_at, Keyword.fetch!(opts, :expiration_seconds), :second)

    info =
      %{
        "domain" => Keyword.fetch!(opts, :domain),
        "uri" => Keyword.fetch!(opts, :uri),
        "version" => Keyword.fetch!(opts, :version),
        "nonce" => Keyword.fetch!(opts, :nonce) || generate_nonce(),
        "issuedAt" => format_datetime(issued_at),
        "expirationTime" => format_datetime(expiration)
      }
      |> maybe_put("statement", Keyword.fetch!(opts, :statement))
      |> maybe_put("notBefore", format_optional_datetime(Keyword.fetch!(opts, :not_before)))
      |> maybe_put("requestId", Keyword.fetch!(opts, :request_id))
      |> maybe_put_resources(Keyword.fetch!(opts, :resources))

    %{
      "info" => info,
      "supportedChains" => Keyword.fetch!(opts, :supported_chains),
      "schema" => @schema
    }
  end

  @doc since: "0.9.0"
  @doc """
  Formats a `DateTime` as ISO 8601 UTC with millisecond precision.

  ## Examples

      iex> X402.Extensions.SIWX.Challenge.format_datetime(~U[2024-01-15 10:30:00Z])
      "2024-01-15T10:30:00.000Z"

      iex> X402.Extensions.SIWX.Challenge.format_datetime(~U[2024-01-15 10:30:00.123456Z])
      "2024-01-15T10:30:00.123Z"
  """
  @spec format_datetime(DateTime.t()) :: String.t()
  def format_datetime(%DateTime{microsecond: {microseconds, _precision}} = datetime) do
    datetime
    |> DateTime.shift_zone!("Etc/UTC")
    |> Map.put(:microsecond, {div(microseconds, 1000) * 1000, 3})
    |> DateTime.to_iso8601()
  end

  @doc false
  @spec validate_supported_chains(term()) ::
          {:ok, [supported_chain()]} | {:error, String.t()}
  def validate_supported_chains(chains) when is_list(chains) and chains != [] do
    Enum.reduce_while(chains, {:ok, []}, fn chain, {:ok, acc} ->
      case normalize_chain(chain) do
        {:ok, normalized} -> {:cont, {:ok, acc ++ [normalized]}}
        {:error, message} -> {:halt, {:error, message}}
      end
    end)
  end

  def validate_supported_chains(_chains),
    do: {:error, "expected a non-empty list of supported chains"}

  @spec normalize_chain(term()) :: {:ok, supported_chain()} | {:error, String.t()}
  defp normalize_chain(chain) when is_list(chain) do
    case Keyword.keyword?(chain) do
      true -> normalize_chain(Map.new(chain))
      false -> {:error, "expected a supported chain map or keyword list"}
    end
  end

  defp normalize_chain(chain) when is_map(chain) do
    chain_id = Utils.map_value(chain, {"chainId", :chain_id})

    with {:ok, family} <- chain_family(chain_id),
         {:ok, type} <- chain_type(family, Utils.map_value(chain, {"type", :type})),
         {:ok, scheme} <-
           signature_scheme(Utils.map_value(chain, {"signatureScheme", :signature_scheme})) do
      {:ok,
       %{"chainId" => chain_id, "type" => type}
       |> maybe_put("signatureScheme", scheme)}
    end
  end

  defp normalize_chain(_chain), do: {:error, "expected a supported chain map or keyword list"}

  @spec chain_family(term()) :: {:ok, Message.family()} | {:error, String.t()}
  defp chain_family(chain_id) when is_binary(chain_id) do
    case Message.family(chain_id) do
      {:ok, family} -> {:ok, family}
      {:error, _reason} -> {:error, "unsupported chain id #{inspect(chain_id)}"}
    end
  end

  defp chain_family(chain_id),
    do: {:error, "expected a CAIP-2 chain id, got: #{inspect(chain_id)}"}

  @spec chain_type(Message.family(), term()) :: {:ok, String.t()} | {:error, String.t()}
  defp chain_type(family, nil), do: {:ok, Message.signature_type(family)}

  defp chain_type(family, type) do
    expected = Message.signature_type(family)

    case type == expected do
      true ->
        {:ok, type}

      false ->
        {:error, "expected type #{inspect(expected)} for #{family} chains, got: #{inspect(type)}"}
    end
  end

  @spec signature_scheme(term()) :: {:ok, String.t() | nil} | {:error, String.t()}
  defp signature_scheme(nil), do: {:ok, nil}
  defp signature_scheme(scheme) when scheme in @signature_schemes, do: {:ok, scheme}

  defp signature_scheme(scheme),
    do:
      {:error,
       "expected signatureScheme in #{inspect(@signature_schemes)}, got: #{inspect(scheme)}"}

  @spec format_optional_datetime(DateTime.t() | nil) :: String.t() | nil
  defp format_optional_datetime(nil), do: nil
  defp format_optional_datetime(datetime), do: format_datetime(datetime)

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @spec maybe_put_resources(map(), [String.t()]) :: map()
  defp maybe_put_resources(map, []), do: map
  defp maybe_put_resources(map, resources), do: Map.put(map, "resources", resources)
end
