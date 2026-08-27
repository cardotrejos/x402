defmodule X402.Extensions.Bazaar do
  @moduledoc """
  Bazaar discovery extension for x402 v2: extension builder and discovery client.

  ## Discovery extension builder

  Resource servers advertise their endpoint specification by placing the
  extension under `extensions.bazaar` in a `PAYMENT-REQUIRED` response. The
  extension carries the actual discovery data (`info`) together with a JSON
  Schema (Draft 2020-12) that validates it (`schema`).

  `info.input` is a discriminated union selected by the `type` field:

    * `"http"` — an HTTP endpoint. Query methods (`GET`, `HEAD`, `DELETE`)
      describe example query parameters; body methods (`POST`, `PUT`, `PATCH`)
      add a `bodyType` and an example `body`.
    * `"mcp"` — a Model Context Protocol tool, identified by `toolName` and
      described by a JSON Schema `inputSchema` for its arguments.

  `info.output` describes the expected response format. It is always present
  (defaulting to a `"json"` content type). The schema's `output` property
  declares `type` (and optionally `format`) as strings and infers the JSON
  type of `example`, optionally refined by the `:schema` option.

  The factory returns a plain, string-keyed map ready for JSON encoding:

      extensions = %{"bazaar" => X402.Extensions.Bazaar.build_extension(method: :get)}

  ## Discovery client

  `list_resources/2` queries a facilitator's `GET /discovery/resources`
  through `X402.Facilitator.list_resources/2` and parses each discovered
  entry into a well-typed map (see `t:resource/0`). Parsing is fail-closed:
  a structurally invalid entry returns
  `{:error, %X402.Facilitator.Error{type: :malformed_facilitator_response}}`
  identifying the offending entry, rather than partial data. Use
  `X402.Facilitator.list_resources/2` directly and `parse_resource/1`
  per-entry to build a lenient listing instead.

  The pure filter helpers `filter_by_network/2`, `filter_by_scheme/2`, and
  `filter_by_max_price/2` narrow a parsed listing client-side:

      {:ok, %{items: items}} = X402.Extensions.Bazaar.list_resources(MyFacilitator)

      items
      |> X402.Extensions.Bazaar.filter_by_network("eip155:8453")
      |> X402.Extensions.Bazaar.filter_by_max_price("100000")

  See the
  [bazaar extension spec](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).
  """

  alias X402.Facilitator
  alias X402.Facilitator.Error
  alias X402.Utils

  @query_methods ["GET", "HEAD", "DELETE"]
  @body_methods ["POST", "PUT", "PATCH"]
  @http_methods @query_methods ++ @body_methods
  @body_types ["json", "form-data", "text"]
  @transports ["streamable-http", "sse"]
  @default_body_type "json"
  @default_output_type "json"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"

  @output_schema [
    type: [type: :string, default: @default_output_type],
    format: [type: :string],
    example: [type: :any],
    schema: [type: {:custom, __MODULE__, :validate_map, []}]
  ]

  @http_schema [
    method: [type: :any],
    input: [type: :any],
    input_schema: [type: {:custom, __MODULE__, :validate_map, []}],
    body_type: [type: :string],
    headers: [type: {:custom, __MODULE__, :validate_map, []}],
    path_params: [type: {:custom, __MODULE__, :validate_map, []}],
    path_params_schema: [type: {:custom, __MODULE__, :validate_map, []}],
    output: [type: {:custom, __MODULE__, :validate_output, []}]
  ]

  @mcp_schema [
    tool_name: [type: :string, required: true],
    description: [type: :string],
    transport: [type: :string],
    input_schema: [type: {:custom, __MODULE__, :validate_map, []}, required: true],
    example: [type: :any],
    output: [type: {:custom, __MODULE__, :validate_output, []}]
  ]

  @typedoc "A built `extensions.bazaar` discovery extension payload."
  @type t :: %{binary() => map()}

  @typedoc """
  A discovered x402 resource parsed from `GET /discovery/resources`.

  `:accepts` entries are the raw, string-keyed `PaymentRequirements` maps
  from the wire. `:last_updated` is either a Unix timestamp (per the v2
  specification) or an ISO 8601 string (as emitted by some facilitators).
  """
  @type resource :: %{
          resource: String.t(),
          type: String.t(),
          x402_version: integer(),
          accepts: [map()],
          last_updated: integer() | String.t(),
          description: String.t() | nil,
          mime_type: String.t() | nil,
          metadata: map() | nil,
          extensions: map() | nil
        }

  @typedoc "Parsed response of `list_resources/2`."
  @type discovery_response :: %{
          x402_version: integer() | nil,
          items: [resource()],
          pagination: Facilitator.discovery_pagination() | nil
        }

  @doc since: "0.5.0"
  @doc """
  Builds a `bazaar` discovery extension payload (`info` + `schema`).

  Accepts either an HTTP endpoint config or an MCP tool config.

  ## HTTP options

    * `:method` — (required) HTTP method: `:get`, `:head`, `:delete`,
      `:post`, `:put`, `:patch` (or the uppercase string). Query methods
      produce a read-only signature; body methods add `bodyType` and `body`.
    * `:input` — example input values (a map of query parameters for query
      methods, a map for `"json"` / `"form-data"` bodies, or a string for
      `"text"` bodies).
    * `:input_schema` — JSON Schema merged into the schema's `queryParams`
      or `body` property.
    * `:body_type` — request body content type for body methods: `"json"`
      (default), `"form-data"`, or `"text"`.
    * `:headers` — example custom header values.
    * `:path_params` — concrete path parameter values (dynamic routes).
    * `:path_params_schema` — JSON Schema for path parameters.

  ## MCP options

    * `:tool_name` — (required) MCP tool name.
    * `:input_schema` — (required) JSON Schema for the tool's `arguments`.
    * `:description` — human-readable tool description.
    * `:transport` — MCP transport: `"streamable-http"` (default) or `"sse"`.
    * `:example` — example `arguments` object.

  ## Output options (`:output`)

  A keyword list or map describing the expected response:

    * `:type` — response content type (default `"json"`).
    * `:format` — additional format information.
    * `:example` — example response value.
    * `:schema` — JSON Schema merged into the schema's `example` property.

  ## Examples

      iex> ext = X402.Extensions.Bazaar.build_extension(method: :get, input: %{"city" => "San Francisco"})
      iex> ext["info"]["input"]["type"]
      "http"
      iex> ext["info"]["input"]["method"]
      "GET"
      iex> ext["info"]["input"]["queryParams"]
      %{"city" => "San Francisco"}

      iex> ext = X402.Extensions.Bazaar.build_extension(method: :post, input: %{"query" => "example"})
      iex> ext["info"]["input"]["bodyType"]
      "json"

      iex> ext = X402.Extensions.Bazaar.build_extension(
      ...>   tool_name: "financial_analysis",
      ...>   input_schema: %{"type" => "object", "properties" => %{"ticker" => %{"type" => "string"}}, "required" => ["ticker"]}
      ...> )
      iex> ext["info"]["input"]["type"]
      "mcp"
      iex> ext["info"]["input"]["toolName"]
      "financial_analysis"
  """
  @spec build_extension(keyword()) :: t()
  def build_extension(opts) when is_list(opts) do
    if Keyword.has_key?(opts, :tool_name) do
      opts = NimbleOptions.validate!(opts, @mcp_schema)
      build_mcp_extension(opts)
    else
      opts = NimbleOptions.validate!(opts, @http_schema)
      build_http_extension(opts)
    end
  end

  def build_extension(opts) do
    raise ArgumentError, "expected options as a keyword list, got: #{inspect(opts)}"
  end

  @doc false
  @spec validate_output(term()) :: {:ok, keyword()} | {:error, String.t()}
  def validate_output(value) when is_list(value) do
    case NimbleOptions.validate(value, @output_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, %NimbleOptions.ValidationError{} = error} -> {:error, Exception.message(error)}
    end
  end

  def validate_output(%{} = map) do
    case output_to_keyword(map) do
      {:ok, keyword} -> validate_output(keyword)
      {:error, message} -> {:error, message}
    end
  end

  def validate_output(value),
    do: {:error, "expected a keyword list or map, got: #{inspect(value)}"}

  @doc false
  @spec validate_map(term()) :: {:ok, map()} | {:error, String.t()}
  def validate_map(value) when is_map(value), do: {:ok, value}

  def validate_map(value),
    do: {:error, "expected a map with string or atom keys, got: #{inspect(value)}"}

  # --- discovery client ---

  @doc """
  Lists discoverable x402 resources from a facilitator's bazaar as typed maps.

  Queries `GET /discovery/resources` through
  `X402.Facilitator.list_resources/2` (accepting the same filter and
  pagination parameters) and parses every discovered entry with
  `parse_resource/1`. Parsing is fail-closed: a structurally invalid entry
  returns `{:error, %X402.Facilitator.Error{type:
  :malformed_facilitator_response, reason: {:invalid_resource, index,
  reason}}}` instead of partial data.

  When called with just a keyword list — `list_resources(limit: 20)` — the
  parameters apply to the default `X402.Facilitator` process name.

  ## Examples

      {:ok, %{items: items, pagination: pagination}} =
        X402.Extensions.Bazaar.list_resources(MyFacilitator,
          network: "eip155:8453",
          limit: 20
        )

      Enum.map(items, & &1.resource)
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec list_resources(Facilitator.server() | keyword(), keyword()) ::
          {:ok, discovery_response()}
          | {:error, Error.t() | NimbleOptions.ValidationError.t() | term()}
  def list_resources(server_or_params \\ Facilitator, params \\ [])

  def list_resources(params, []) when is_list(params) do
    list_resources(Facilitator, params)
  end

  def list_resources(server, params) when is_list(params) do
    with {:ok, response} <- Facilitator.list_resources(server, params),
         {:ok, items} <- parse_resources(response.items) do
      {:ok, %{response | items: items}}
    end
  end

  @doc """
  Parses one raw discovered-resource map into a typed map.

  Validates the required fields from the v2 specification (§8.3): `resource`,
  `type`, `x402Version`, `accepts` (a list of `PaymentRequirements` maps),
  and `lastUpdated` (Unix timestamp or ISO 8601 string). Optional
  `description`, `mimeType`, `metadata`, and `extensions` fields default to
  `nil` when absent and are rejected when mistyped.

  ## Examples

      iex> {:ok, parsed} = X402.Extensions.Bazaar.parse_resource(%{
      ...>   "resource" => "https://api.example.com/premium-data",
      ...>   "type" => "http",
      ...>   "x402Version" => 2,
      ...>   "accepts" => [%{"scheme" => "exact", "network" => "eip155:8453", "amount" => "10000"}],
      ...>   "lastUpdated" => 1_703_123_456
      ...> })
      iex> {parsed.resource, parsed.x402_version, parsed.last_updated}
      {"https://api.example.com/premium-data", 2, 1703123456}

      iex> X402.Extensions.Bazaar.parse_resource(%{"type" => "http"})
      {:error, {:missing_field, "resource"}}

      iex> X402.Extensions.Bazaar.parse_resource(%{
      ...>   "resource" => "https://api.example.com",
      ...>   "type" => "http",
      ...>   "x402Version" => 2,
      ...>   "accepts" => "exact",
      ...>   "lastUpdated" => 1
      ...> })
      {:error, {:invalid_field, "accepts"}}
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec parse_resource(term()) :: {:ok, resource()} | {:error, term()}
  def parse_resource(item) when is_map(item) do
    with {:ok, resource} <- fetch_string(item, "resource"),
         {:ok, type} <- fetch_string(item, "type"),
         {:ok, x402_version} <- fetch_integer(item, "x402Version"),
         {:ok, accepts} <- fetch_accepts(item),
         {:ok, last_updated} <- fetch_last_updated(item),
         {:ok, description} <- fetch_optional_string(item, "description"),
         {:ok, mime_type} <- fetch_optional_string(item, "mimeType"),
         {:ok, metadata} <- fetch_optional_map(item, "metadata"),
         {:ok, extensions} <- fetch_optional_map(item, "extensions") do
      {:ok,
       %{
         resource: resource,
         type: type,
         x402_version: x402_version,
         accepts: accepts,
         last_updated: last_updated,
         description: description,
         mime_type: mime_type,
         metadata: metadata,
         extensions: extensions
       }}
    end
  end

  def parse_resource(item), do: {:error, {:invalid_resource_entry, item}}

  @doc """
  Keeps the resources that accept payment on the given CAIP-2 network.

  ## Examples

      iex> resources = [
      ...>   %{resource: "https://a.example", accepts: [%{"scheme" => "exact", "network" => "eip155:8453"}]},
      ...>   %{resource: "https://b.example", accepts: [%{"scheme" => "exact", "network" => "solana:mainnet"}]}
      ...> ]
      iex> resources
      ...> |> X402.Extensions.Bazaar.filter_by_network("eip155:8453")
      ...> |> Enum.map(& &1.resource)
      ["https://a.example"]
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec filter_by_network([resource()], String.t()) :: [resource()]
  def filter_by_network(resources, network) when is_list(resources) and is_binary(network) do
    filter_by_requirement(resources, {"network", :network}, network)
  end

  @doc """
  Keeps the resources that accept payment with the given scheme.

  ## Examples

      iex> resources = [
      ...>   %{resource: "https://a.example", accepts: [%{"scheme" => "exact", "network" => "eip155:8453"}]},
      ...>   %{resource: "https://b.example", accepts: [%{"scheme" => "upto", "network" => "eip155:8453"}]}
      ...> ]
      iex> resources
      ...> |> X402.Extensions.Bazaar.filter_by_scheme("upto")
      ...> |> Enum.map(& &1.resource)
      ["https://b.example"]
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec filter_by_scheme([resource()], String.t()) :: [resource()]
  def filter_by_scheme(resources, scheme) when is_list(resources) and is_binary(scheme) do
    filter_by_requirement(resources, {"scheme", :scheme}, scheme)
  end

  @doc """
  Keeps the resources with at least one payment option at or below a price.

  The price is compared in atomic token units against each accepted
  `PaymentRequirements` entry's `amount` (falling back to the legacy
  `maxAmountRequired`). Entries without a parsable amount never match.
  Raises `ArgumentError` when `max_price` itself is not a non-negative
  integer or decimal string, since that is a programmer error.

  ## Examples

      iex> resources = [
      ...>   %{resource: "https://a.example", accepts: [%{"scheme" => "exact", "amount" => "10000"}]},
      ...>   %{resource: "https://b.example", accepts: [%{"scheme" => "exact", "amount" => "250000"}]}
      ...> ]
      iex> resources
      ...> |> X402.Extensions.Bazaar.filter_by_max_price("100000")
      ...> |> Enum.map(& &1.resource)
      ["https://a.example"]
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec filter_by_max_price([resource()], String.t() | non_neg_integer()) :: [resource()]
  def filter_by_max_price(resources, max_price) when is_list(resources) do
    case Utils.parse_decimal(max_price) do
      {:ok, max} ->
        Enum.filter(resources, &affordable?(&1, max))

      :error ->
        raise ArgumentError,
              "expected max_price to be a non-negative integer or decimal string, " <>
                "got: #{inspect(max_price)}"
    end
  end

  @spec parse_resources([map()]) :: {:ok, [resource()]} | {:error, Error.t()}
  defp parse_resources(items) do
    items
    |> Enum.with_index()
    |> Enum.reduce_while([], fn {item, index}, acc ->
      case parse_resource(item) do
        {:ok, parsed} -> {:cont, [parsed | acc]}
        {:error, reason} -> {:halt, {:error, invalid_resource_error(index, reason)}}
      end
    end)
    |> case do
      {:error, error} -> {:error, error}
      parsed -> {:ok, Enum.reverse(parsed)}
    end
  end

  @spec invalid_resource_error(non_neg_integer(), term()) :: Error.t()
  defp invalid_resource_error(index, reason) do
    %Error{
      type: :malformed_facilitator_response,
      reason: {:invalid_resource, index, reason},
      retryable: false,
      attempt: nil
    }
  end

  @spec filter_by_requirement([resource()], {String.t(), atom()}, String.t()) :: [resource()]
  defp filter_by_requirement(resources, key, value) do
    Enum.filter(resources, fn %{accepts: accepts} ->
      Enum.any?(accepts, &(is_map(&1) and Utils.map_value(&1, key) == value))
    end)
  end

  @spec affordable?(resource(), {non_neg_integer(), non_neg_integer()}) :: boolean()
  defp affordable?(%{accepts: accepts}, max) do
    Enum.any?(accepts, fn requirements ->
      case requirements_amount(requirements) do
        {:ok, amount} -> Utils.compare_decimal(amount, max) != :gt
        :error -> false
      end
    end)
  end

  @spec requirements_amount(term()) :: {:ok, {non_neg_integer(), non_neg_integer()}} | :error
  defp requirements_amount(requirements) when is_map(requirements) do
    value =
      Utils.first_present([
        Utils.map_value(requirements, {"amount", :amount}),
        Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired})
      ])

    case value do
      nil -> :error
      amount -> Utils.parse_decimal(amount)
    end
  end

  defp requirements_amount(_requirements), do: :error

  @spec fetch_string(map(), String.t()) :: {:ok, String.t()} | {:error, term()}
  defp fetch_string(item, field) do
    case Map.fetch(item, field) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, _invalid} -> {:error, {:invalid_field, field}}
      :error -> {:error, {:missing_field, field}}
    end
  end

  @spec fetch_integer(map(), String.t()) :: {:ok, integer()} | {:error, term()}
  defp fetch_integer(item, field) do
    case Map.fetch(item, field) do
      {:ok, value} when is_integer(value) -> {:ok, value}
      {:ok, _invalid} -> {:error, {:invalid_field, field}}
      :error -> {:error, {:missing_field, field}}
    end
  end

  @spec fetch_accepts(map()) :: {:ok, [map()]} | {:error, term()}
  defp fetch_accepts(item) do
    case Map.fetch(item, "accepts") do
      {:ok, accepts} when is_list(accepts) ->
        if Enum.all?(accepts, &is_map/1) do
          {:ok, accepts}
        else
          {:error, {:invalid_field, "accepts"}}
        end

      {:ok, _invalid} ->
        {:error, {:invalid_field, "accepts"}}

      :error ->
        {:error, {:missing_field, "accepts"}}
    end
  end

  @spec fetch_last_updated(map()) :: {:ok, integer() | String.t()} | {:error, term()}
  defp fetch_last_updated(item) do
    case Map.fetch(item, "lastUpdated") do
      {:ok, value} when is_integer(value) or is_binary(value) -> {:ok, value}
      {:ok, _invalid} -> {:error, {:invalid_field, "lastUpdated"}}
      :error -> {:error, {:missing_field, "lastUpdated"}}
    end
  end

  @spec fetch_optional_string(map(), String.t()) :: {:ok, String.t() | nil} | {:error, term()}
  defp fetch_optional_string(item, field) do
    case Map.fetch(item, field) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, nil} -> {:ok, nil}
      {:ok, _invalid} -> {:error, {:invalid_field, field}}
      :error -> {:ok, nil}
    end
  end

  @spec fetch_optional_map(map(), String.t()) :: {:ok, map() | nil} | {:error, term()}
  defp fetch_optional_map(item, field) do
    case Map.fetch(item, field) do
      {:ok, value} when is_map(value) -> {:ok, value}
      {:ok, nil} -> {:ok, nil}
      {:ok, _invalid} -> {:error, {:invalid_field, field}}
      :error -> {:ok, nil}
    end
  end

  # --- HTTP ---

  @spec build_http_extension(keyword()) :: t()
  defp build_http_extension(opts) do
    method = method!(opts)
    validate_http_input!(method, opts)

    info_input =
      %{"type" => "http", "method" => method}
      |> put_http_input(method, opts)
      |> maybe_put("headers", Keyword.get(opts, :headers))
      |> maybe_put("pathParams", Keyword.get(opts, :path_params))

    info = %{"input" => info_input}

    %{
      "info" => put_output(info, Keyword.get(opts, :output)),
      "schema" => build_http_schema(method, opts)
    }
  end

  @spec put_http_input(map(), String.t(), keyword()) :: map()
  defp put_http_input(info_input, method, opts) when method in @body_methods do
    body_type = body_type!(opts)

    body =
      case Keyword.get(opts, :input) do
        nil -> default_body(body_type)
        input -> input
      end

    info_input
    |> Map.put("bodyType", body_type)
    |> Map.put("body", body)
  end

  defp put_http_input(info_input, _method, opts) do
    case Keyword.get(opts, :input) do
      nil -> info_input
      input -> Map.put(info_input, "queryParams", input)
    end
  end

  @spec build_http_schema(String.t(), keyword()) :: map()
  defp build_http_schema(method, opts) do
    input_properties =
      if method in @body_methods do
        %{
          "type" => %{"type" => "string", "const" => "http"},
          "method" => %{"type" => "string", "enum" => @body_methods},
          "bodyType" => %{"type" => "string", "enum" => @body_types},
          "body" => body_schema(opts),
          "queryParams" => %{"type" => "object", "additionalProperties" => %{"type" => "string"}},
          "headers" => %{"type" => "object", "additionalProperties" => %{"type" => "string"}}
        }
      else
        %{
          "type" => %{"type" => "string", "const" => "http"},
          "method" => %{"type" => "string", "enum" => @query_methods},
          "queryParams" => query_params_schema(opts),
          "headers" => %{"type" => "object", "additionalProperties" => %{"type" => "string"}}
        }
      end

    input_properties = put_path_params_schema(input_properties, opts)

    input =
      %{
        "type" => "object",
        "properties" => input_properties,
        "additionalProperties" => false
      }
      |> Map.put("required", http_required(method))

    schema = base_schema()
    schema = put_in(schema, ["properties", "input"], input)
    put_output_schema(schema, Keyword.get(opts, :output))
  end

  @spec http_required(String.t()) :: [String.t()]
  defp http_required(method) when method in @body_methods,
    do: ["type", "method", "bodyType", "body"]

  defp http_required(_method), do: ["type", "method"]

  @spec query_params_schema(keyword()) :: map()
  defp query_params_schema(opts) do
    Map.merge(%{"type" => "object"}, Keyword.get(opts, :input_schema, %{}))
  end

  @spec body_schema(keyword()) :: map()
  defp body_schema(opts) do
    case Keyword.get(opts, :input_schema) do
      nil -> default_body_schema(body_type!(opts))
      schema -> schema
    end
  end

  @spec put_path_params_schema(map(), keyword()) :: map()
  defp put_path_params_schema(properties, opts) do
    if Keyword.has_key?(opts, :path_params_schema) or Keyword.has_key?(opts, :path_params) do
      schema =
        Map.merge(%{"type" => "object"}, Keyword.get(opts, :path_params_schema, %{}))

      Map.put(properties, "pathParams", schema)
    else
      properties
    end
  end

  # --- MCP ---

  @spec build_mcp_extension(keyword()) :: t()
  defp build_mcp_extension(opts) do
    info_input =
      %{
        "type" => "mcp",
        "toolName" => Keyword.fetch!(opts, :tool_name),
        "inputSchema" => Keyword.fetch!(opts, :input_schema)
      }
      |> maybe_put("description", Keyword.get(opts, :description))
      |> maybe_put("transport", transport(opts))
      |> maybe_put("example", Keyword.get(opts, :example))

    info = %{"input" => info_input}

    %{
      "info" => put_output(info, Keyword.get(opts, :output)),
      "schema" => build_mcp_schema(opts)
    }
  end

  @spec build_mcp_schema(keyword()) :: map()
  defp build_mcp_schema(opts) do
    input =
      %{
        "type" => "object",
        "properties" => %{
          "type" => %{"type" => "string", "const" => "mcp"},
          "toolName" => %{"type" => "string"},
          "description" => %{"type" => "string"},
          "transport" => %{"type" => "string", "enum" => @transports},
          "inputSchema" => %{"type" => "object"},
          "example" => %{"type" => "object"}
        },
        "required" => ["type", "toolName", "inputSchema"],
        "additionalProperties" => false
      }

    schema = base_schema()
    schema = put_in(schema, ["properties", "input"], input)
    put_output_schema(schema, Keyword.get(opts, :output))
  end

  # --- output ---

  @spec put_output(map(), keyword() | nil) :: map()
  defp put_output(info, nil) do
    Map.put(info, "output", %{"type" => @default_output_type})
  end

  defp put_output(info, output) do
    base = %{"type" => Keyword.fetch!(output, :type)}

    base =
      base
      |> maybe_put_any("format", Keyword.get(output, :format))
      |> maybe_put_any("example", Keyword.get(output, :example))

    Map.put(info, "output", base)
  end

  @spec put_output_schema(map(), keyword() | nil) :: map()
  defp put_output_schema(schema, nil) do
    put_output_schema(schema, type: @default_output_type)
  end

  defp put_output_schema(schema, output) do
    properties =
      %{"type" => %{"type" => "string"}}
      |> maybe_put_any("format", format_schema(Keyword.get(output, :format)))
      |> Map.put("example", output_example_schema(output))

    output_property = %{
      "type" => "object",
      "properties" => properties,
      "required" => ["type"]
    }

    put_in(schema, ["properties", "output"], output_property)
  end

  @spec format_schema(term() | nil) :: map() | nil
  defp format_schema(nil), do: nil
  defp format_schema(_format), do: %{"type" => "string"}

  @spec output_example_schema(keyword()) :: map()
  defp output_example_schema(output) do
    example = Keyword.get(output, :example)
    custom_schema = Keyword.get(output, :schema)

    example
    |> inferred_example_schema(custom_schema)
    |> Map.merge(custom_schema || %{})
  end

  # --- option accessors ---

  @spec method!(keyword()) :: String.t()
  defp method!(opts) do
    case Keyword.fetch(opts, :method) do
      :error ->
        raise ArgumentError, "expected :method option for HTTP input"

      {:ok, method} when is_atom(method) and not is_nil(method) ->
        normalize_method!(method |> Atom.to_string() |> String.upcase())

      {:ok, method} when is_binary(method) ->
        normalize_method!(String.upcase(method))

      {:ok, nil} ->
        raise ArgumentError, "expected :method option for HTTP input"

      {:ok, value} ->
        raise ArgumentError, "invalid :method #{inspect(value)}"
    end
  end

  @spec normalize_method!(String.t()) :: String.t()
  defp normalize_method!(method) do
    if method in @http_methods do
      method
    else
      raise ArgumentError,
            "invalid :method #{inspect(method)}; expected one of #{Enum.join(@http_methods, ", ")}"
    end
  end

  @spec body_type!(keyword()) :: String.t()
  defp body_type!(opts) do
    value = Keyword.get(opts, :body_type, @default_body_type)

    if value in @body_types do
      value
    else
      raise ArgumentError,
            "invalid :body_type #{inspect(value)}; expected one of #{Enum.join(@body_types, ", ")}"
    end
  end

  @spec validate_http_input!(String.t(), keyword()) :: :ok
  defp validate_http_input!(method, opts) when method in @query_methods do
    if Keyword.has_key?(opts, :body_type) do
      raise ArgumentError, ":body_type is only supported for POST, PUT, and PATCH inputs"
    end

    case Keyword.get(opts, :input) do
      nil -> :ok
      input when is_map(input) -> :ok
      input -> raise ArgumentError, "expected query :input to be a map, got: #{inspect(input)}"
    end
  end

  defp validate_http_input!(method, opts) when method in @body_methods do
    body_type = body_type!(opts)

    case {body_type, Keyword.get(opts, :input)} do
      {_body_type, nil} ->
        :ok

      {"text", input} when is_binary(input) ->
        :ok

      {body_type, input} when body_type in ["json", "form-data"] and is_map(input) ->
        :ok

      {"text", input} ->
        raise ArgumentError, "expected text :input to be a string, got: #{inspect(input)}"

      {body_type, input} ->
        raise ArgumentError,
              "expected #{body_type} :input to be a map, got: #{inspect(input)}"
    end
  end

  @spec default_body(String.t()) :: map() | String.t()
  defp default_body("text"), do: ""
  defp default_body(_body_type), do: %{}

  @spec default_body_schema(String.t()) :: map()
  defp default_body_schema("text"), do: %{"type" => "string"}
  defp default_body_schema(_body_type), do: %{"type" => "object"}

  @spec inferred_example_schema(term(), map() | nil) :: map()
  defp inferred_example_schema(nil, nil), do: %{}
  defp inferred_example_schema(nil, _custom_schema), do: %{"type" => "object"}

  defp inferred_example_schema(example, _custom_schema) when is_map(example),
    do: %{"type" => "object"}

  defp inferred_example_schema(example, _custom_schema) when is_list(example),
    do: %{"type" => "array"}

  defp inferred_example_schema(example, _custom_schema) when is_binary(example),
    do: %{"type" => "string"}

  defp inferred_example_schema(example, _custom_schema) when is_boolean(example),
    do: %{"type" => "boolean"}

  defp inferred_example_schema(example, _custom_schema) when is_integer(example),
    do: %{"type" => "integer"}

  defp inferred_example_schema(example, _custom_schema) when is_float(example),
    do: %{"type" => "number"}

  defp inferred_example_schema(_example, _custom_schema), do: %{}

  @spec transport(keyword()) :: String.t() | nil
  defp transport(opts) do
    case Keyword.fetch(opts, :transport) do
      :error -> nil
      {:ok, value} when value in @transports -> value
      {:ok, value} -> raise ArgumentError, "invalid :transport #{inspect(value)}"
    end
  end

  # --- helpers ---

  @spec base_schema() :: map()
  defp base_schema do
    %{
      "$schema" => @schema_uri,
      "type" => "object",
      "properties" => %{},
      "required" => ["input"]
    }
  end

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @spec maybe_put_any(map(), String.t(), term()) :: map()
  defp maybe_put_any(map, _key, nil), do: map
  defp maybe_put_any(map, key, value), do: Map.put(map, key, value)

  @spec output_to_keyword(map()) :: {:ok, keyword()} | {:error, String.t()}
  defp output_to_keyword(map) do
    entries =
      Enum.map(map, fn
        {key, value} when is_atom(key) -> {:ok, {key, value}}
        {"type", value} -> {:ok, {:type, value}}
        {"format", value} -> {:ok, {:format, value}}
        {"example", value} -> {:ok, {:example, value}}
        {"schema", value} -> {:ok, {:schema, value}}
        {key, _value} -> {:error, "unknown :output option #{inspect(key)}"}
      end)

    case Enum.find(entries, &match?({:error, _}, &1)) do
      {:error, message} ->
        {:error, message}

      nil ->
        {:ok, Enum.map(entries, fn {:ok, entry} -> entry end)}
    end
  end
end
