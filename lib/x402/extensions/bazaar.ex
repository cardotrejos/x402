defmodule X402.Extensions.Bazaar do
  @moduledoc """
  Builds the `bazaar` discovery extension for x402 v2.

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

  See the
  [bazaar extension spec](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).
  """

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

    info_input
    |> Map.put("bodyType", body_type)
    |> Map.put("body", Keyword.get(opts, :input, default_body(body_type)))
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
