defmodule X402.Extensions.BuilderCode do
  @moduledoc """
  The x402 `builder-code` extension: ERC-8021 on-chain attribution codes.

  Implements the
  [builder-code extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md).
  A resource server declares the application's *app code* (`a`) — and
  optionally up to 5 of its own *service codes* (`s`) — under
  `PaymentRequired.extensions["builder-code"]` (`extension/2`). The client
  echoes the declaration and attaches up to 5 service codes of its own
  (`enricher/1`). At settlement the facilitator adds its *wallet code*
  (`w`), CBOR-encodes `a`, `s`, and `w` as an ERC-8021 Schema 2 suffix, and
  appends it to the settlement transaction calldata.

      # server (PaymentRequired.extensions)
      %{"builder-code" => %{"info" => %{"a" => "my_app"}, "schema" => %{...}}}

      # client (PaymentPayload.extensions)
      %{"builder-code" => %{"info" => %{"a" => "my_app", "s" => ["my_client"]}, "schema" => %{...}}}

  Every code matches `^[a-z0-9_]{1,32}$` (`valid_code?/1`).

  ## What the resource server does with the code

  Nothing beyond validation and forwarding: the codes travel inside the
  `PaymentPayload.extensions` the gate already sends to the facilitator on
  `POST /verify` and `POST /settle`, and the facilitator is the party that
  encodes them into calldata. The resource server is, however, the
  authority for `a`: `validate_echo/2` implements the spec's echo rules —
  an echoed `a` must equal the advertised one (and must be absent when the
  server declared none), every code must be well-formed, and the echoed
  `s` may carry at most 10 entries (the combined client and server
  reservations). `X402.Plug.PaymentGate` and `X402.MCP.Server` run these
  rules on every payment whose payload carries the extension.

  The echo may use either wire shape the ecosystem produces: the
  `%{"info" => %{...}}` envelope the reference client emits, or the bare
  `%{"a" => ..., "s" => ...}` map from the spec's examples.
  """

  alias X402.Utils

  @extension_key "builder-code"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"
  @code_pattern ~r/\A[a-z0-9_]{1,32}\z/
  @code_pattern_source "^[a-z0-9_]{1,32}$"
  @max_client_service_codes 5
  @max_server_service_codes 5
  @max_facilitator_service_codes 1
  @max_service_codes @max_client_service_codes + @max_server_service_codes +
                       @max_facilitator_service_codes
  @max_echoed_service_codes @max_client_service_codes + @max_server_service_codes

  @schema %{
    "$schema" => @schema_uri,
    "type" => "object",
    "properties" => %{
      "a" => %{
        "type" => "string",
        "pattern" => @code_pattern_source,
        "description" => "App builder code"
      },
      "w" => %{
        "type" => "string",
        "pattern" => @code_pattern_source,
        "description" => "Wallet builder code"
      },
      "s" => %{
        "type" => "array",
        "maxItems" => @max_service_codes,
        "items" => %{"type" => "string", "pattern" => @code_pattern_source},
        "description" => "Service builder codes"
      }
    },
    "additionalProperties" => false
  }

  @extension_opts_schema [
    service_codes: [
      type: {:custom, __MODULE__, :validate_codes, [@max_server_service_codes]},
      default: [],
      doc: """
      The server's own service code(s) (`info.s`): a code or a list of at
      most #{@max_server_service_codes} codes.
      """
    ]
  ]

  @enricher_opts_schema [
    service_codes: [
      type: {:custom, __MODULE__, :validate_codes, [@max_client_service_codes]},
      required: true,
      doc: """
      The client's service code(s) (`s`): a code or a list of at most
      #{@max_client_service_codes} codes.
      """
    ],
    always: [
      type: :boolean,
      default: true,
      doc: """
      Attach `s` even when the server did not advertise `builder-code`, as
      the spec's client behaviour prescribes. With `false` the enricher is a
      no-op for servers that do not declare the extension.
      """
    ]
  ]

  @typedoc "A builder code: 1–32 lowercase alphanumeric or underscore characters."
  @type code :: String.t()

  @typedoc "Codes extracted from an echoed `builder-code` value."
  @type extracted :: %{app_code: code() | nil, service_codes: [code()]}

  @typedoc "Errors returned by `extract/1` and `validate_echo/2`."
  @type error ::
          :invalid_builder_code_extension
          | {:invalid_builder_code, String.t()}
          | :too_many_service_codes
          | :builder_code_mismatch

  @doc since: "0.9.0"
  @doc """
  Returns the extension key on the wire.

  ## Examples

      iex> X402.Extensions.BuilderCode.extension_key()
      "builder-code"
  """
  @spec extension_key() :: String.t()
  def extension_key, do: @extension_key

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema the server advertises for the extension.

  ## Examples

      iex> schema = X402.Extensions.BuilderCode.schema()
      iex> schema["properties"]["a"]["pattern"]
      "^[a-z0-9_]{1,32}$"
      iex> schema["properties"]["s"]["maxItems"]
      11
  """
  @spec schema() :: map()
  def schema, do: @schema

  @doc since: "0.9.0"
  @doc """
  Checks whether a value is a well-formed builder code.

  ## Examples

      iex> X402.Extensions.BuilderCode.valid_code?("my_app_1")
      true

      iex> X402.Extensions.BuilderCode.valid_code?("My-App")
      false

      iex> X402.Extensions.BuilderCode.valid_code?("")
      false

      iex> X402.Extensions.BuilderCode.valid_code?(String.duplicate("a", 33))
      false

      iex> X402.Extensions.BuilderCode.valid_code?(:my_app)
      false
  """
  @spec valid_code?(term()) :: boolean()
  def valid_code?(code) when is_binary(code), do: Regex.match?(@code_pattern, code)
  def valid_code?(_code), do: false

  @doc since: "0.9.0"
  @doc """
  Builds the server-side advertisement for `PaymentRequired.extensions`.

  Raises `NimbleOptions.ValidationError` for a malformed app code or
  service codes: declaring an invalid code is a configuration error the
  spec requires rejecting at declaration time.

  ## Options

  #{NimbleOptions.docs(@extension_opts_schema)}

  ## Examples

      iex> X402.Extensions.BuilderCode.extension("my_app")["info"]
      %{"a" => "my_app"}

      iex> X402.Extensions.BuilderCode.extension("my_app", service_codes: "sdk_elixir")["info"]
      %{"a" => "my_app", "s" => ["sdk_elixir"]}

      iex> extension = X402.Extensions.BuilderCode.extension("my_app")
      iex> extension["schema"] == X402.Extensions.BuilderCode.schema()
      true
  """
  @spec extension(code(), keyword()) :: map()
  def extension(app_code, opts \\ []) when is_list(opts) do
    opts =
      NimbleOptions.validate!(
        [app_code: app_code] ++ opts,
        [app_code: [type: {:custom, __MODULE__, :validate_code, []}, required: true]] ++
          @extension_opts_schema
      )

    info =
      case Keyword.fetch!(opts, :service_codes) do
        [] -> %{"a" => app_code}
        codes -> %{"a" => app_code, "s" => codes}
      end

    %{"info" => info, "schema" => @schema}
  end

  @doc false
  @spec validate_code(term()) :: {:ok, code()} | {:error, String.t()}
  def validate_code(code) do
    case valid_code?(code) do
      true -> {:ok, code}
      false -> {:error, invalid_code_message(code)}
    end
  end

  @doc false
  @spec validate_codes(term(), pos_integer()) :: {:ok, [code()]} | {:error, String.t()}
  def validate_codes(code, max) when is_binary(code), do: validate_codes([code], max)

  def validate_codes(codes, max) when is_list(codes) and length(codes) > max do
    {:error, "too many service codes: #{length(codes)} exceeds the maximum of #{max}"}
  end

  def validate_codes(codes, _max) when is_list(codes) do
    case Enum.find(codes, &(not valid_code?(&1))) do
      nil -> {:ok, codes}
      invalid -> {:error, invalid_code_message(invalid)}
    end
  end

  def validate_codes(other, _max),
    do: {:error, "expected a builder code or a list of builder codes, got: #{inspect(other)}"}

  @spec invalid_code_message(term()) :: String.t()
  defp invalid_code_message(code) do
    "invalid builder code #{inspect(code)}: expected 1-32 lowercase alphanumeric " <>
      "or underscore characters"
  end

  @doc since: "0.9.0"
  @doc """
  Extracts the app code and service codes from a `builder-code` value.

  Accepts the value as it appears under `extensions["builder-code"]` in a
  `PaymentPayload` (or `PaymentRequired`): either the `%{"info" => ...}`
  envelope or a bare code map. `s` may be a single code or a list; it is
  always returned as a list. Returns `{:ok, nil}` for `nil`.

  Codes are checked for format only. The count of `s` entries is **not**
  checked here — see `validate_echo/2` for the echo rules.

  ## Examples

      iex> X402.Extensions.BuilderCode.extract(%{"info" => %{"a" => "my_app", "s" => "my_client"}})
      {:ok, %{app_code: "my_app", service_codes: ["my_client"]}}

      iex> X402.Extensions.BuilderCode.extract(%{"s" => ["base_mcp", "demo_app"]})
      {:ok, %{app_code: nil, service_codes: ["base_mcp", "demo_app"]}}

      iex> X402.Extensions.BuilderCode.extract(%{"info" => %{"a" => "My App"}})
      {:error, {:invalid_builder_code, "a"}}

      iex> X402.Extensions.BuilderCode.extract(%{"info" => %{"s" => [1]}})
      {:error, {:invalid_builder_code, "s"}}

      iex> X402.Extensions.BuilderCode.extract("my_app")
      {:error, :invalid_builder_code_extension}

      iex> X402.Extensions.BuilderCode.extract(nil)
      {:ok, nil}
  """
  @spec extract(term()) :: {:ok, extracted() | nil} | {:error, error()}
  def extract(nil), do: {:ok, nil}

  def extract(value) when is_map(value) do
    info = extension_info(value)

    with {:ok, app_code} <- extract_app_code(Utils.map_value(info, {"a", :a})),
         {:ok, service_codes} <- extract_service_codes(Utils.map_value(info, {"s", :s})) do
      {:ok, %{app_code: app_code, service_codes: service_codes}}
    end
  end

  def extract(_value), do: {:error, :invalid_builder_code_extension}

  @spec extension_info(map()) :: map()
  defp extension_info(value) do
    case Utils.map_value(value, {"info", :info}) do
      %{} = info -> info
      _absent -> value
    end
  end

  @spec extract_app_code(term()) :: {:ok, code() | nil} | {:error, error()}
  defp extract_app_code(nil), do: {:ok, nil}

  defp extract_app_code(code) do
    case valid_code?(code) do
      true -> {:ok, code}
      false -> {:error, {:invalid_builder_code, "a"}}
    end
  end

  @spec extract_service_codes(term()) :: {:ok, [code()]} | {:error, error()}
  defp extract_service_codes(nil), do: {:ok, []}
  defp extract_service_codes(code) when is_binary(code), do: extract_service_codes([code])

  defp extract_service_codes(codes) when is_list(codes) do
    case Enum.all?(codes, &valid_code?/1) do
      true -> {:ok, codes}
      false -> {:error, {:invalid_builder_code, "s"}}
    end
  end

  defp extract_service_codes(_other), do: {:error, {:invalid_builder_code, "s"}}

  @doc since: "0.9.0"
  @doc """
  Validates a client's echoed `builder-code` value against the advertised
  one, as the resource server must before forwarding a payment.

  Both arguments are the values under `extensions["builder-code"]` (`nil`
  when absent). The rules, from the spec:

  * every echoed code must be well-formed (`{:invalid_builder_code, field}`);
  * an echoed `a` must equal the advertised `info.a`, and must be absent
    when the server declared none (`:builder_code_mismatch`);
  * the echoed `s` may carry at most #{@max_echoed_service_codes} entries —
    the client and server reservations combined (`:too_many_service_codes`).

  A `nil` echo is always valid: omitting the extension is allowed.

  ## Examples

      iex> advertised = X402.Extensions.BuilderCode.extension("my_app")
      iex> X402.Extensions.BuilderCode.validate_echo(%{"info" => %{"a" => "my_app", "s" => ["c"]}}, advertised)
      :ok

      iex> advertised = X402.Extensions.BuilderCode.extension("my_app")
      iex> X402.Extensions.BuilderCode.validate_echo(%{"a" => "other_app"}, advertised)
      {:error, :builder_code_mismatch}

      iex> X402.Extensions.BuilderCode.validate_echo(%{"a" => "my_app"}, nil)
      {:error, :builder_code_mismatch}

      iex> X402.Extensions.BuilderCode.validate_echo(%{"s" => "my_client"}, nil)
      :ok

      iex> too_many = Enum.map(1..11, &"code_\#{&1}")
      iex> X402.Extensions.BuilderCode.validate_echo(%{"s" => too_many}, nil)
      {:error, :too_many_service_codes}

      iex> X402.Extensions.BuilderCode.validate_echo(nil, nil)
      :ok
  """
  @spec validate_echo(term(), term()) :: :ok | {:error, error()}
  def validate_echo(nil, _advertised), do: :ok

  def validate_echo(echoed, advertised) do
    with {:ok, %{app_code: app_code, service_codes: service_codes}} <- extract(echoed),
         :ok <- ensure_app_code_echo(app_code, advertised) do
      case length(service_codes) > @max_echoed_service_codes do
        true -> {:error, :too_many_service_codes}
        false -> :ok
      end
    end
  end

  @spec ensure_app_code_echo(code() | nil, term()) :: :ok | {:error, :builder_code_mismatch}
  defp ensure_app_code_echo(nil, _advertised), do: :ok

  defp ensure_app_code_echo(app_code, advertised) do
    case advertised_app_code(advertised) do
      ^app_code -> :ok
      _other -> {:error, :builder_code_mismatch}
    end
  end

  @spec advertised_app_code(term()) :: code() | nil
  defp advertised_app_code(advertised) when is_map(advertised) do
    advertised
    |> extension_info()
    |> Utils.map_value({"a", :a})
  end

  defp advertised_app_code(_advertised), do: nil

  @doc since: "0.9.0"
  @doc """
  Builds a client-side enricher for `X402.Client.build_payment/3`'s
  `:extensions` option.

  The returned function attaches the client's service codes as
  `extensions["builder-code"]["info"]["s"]`. When the server advertised
  `builder-code`, the advertised `info` (including `a`) and `schema` are
  echoed unchanged and the client codes are prepended to any server codes
  (deduplicated, client first, as the reference client merges them). When
  it did not, only `%{"info" => %{"s" => codes}}` is attached — never `a`.

  ## Options

  #{NimbleOptions.docs(@enricher_opts_schema)}

  ## Examples

      iex> enricher = X402.Extensions.BuilderCode.enricher(service_codes: "my_client")
      iex> advertised = %{"builder-code" => X402.Extensions.BuilderCode.extension("my_app", service_codes: "sdk")}
      iex> {:ok, enriched} = enricher.(%{"extensions" => advertised}, %{"extensions" => advertised})
      iex> enriched["extensions"]["builder-code"]["info"]
      %{"a" => "my_app", "s" => ["my_client", "sdk"]}

      iex> enricher = X402.Extensions.BuilderCode.enricher(service_codes: ["base_mcp", "demo_app"])
      iex> {:ok, enriched} = enricher.(%{"extensions" => %{}}, %{"extensions" => %{}})
      iex> enriched["extensions"]["builder-code"]
      %{"info" => %{"s" => ["base_mcp", "demo_app"]}}

      iex> enricher = X402.Extensions.BuilderCode.enricher(service_codes: "my_client", always: false)
      iex> enricher.(%{"extensions" => %{}}, %{"extensions" => %{}})
      {:ok, %{"extensions" => %{}}}
  """
  @spec enricher(keyword()) :: (map(), map() | nil -> {:ok, map()})
  def enricher(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @enricher_opts_schema)
    service_codes = Keyword.fetch!(opts, :service_codes)
    always = Keyword.fetch!(opts, :always)

    fn payload, payment_required ->
      {:ok, enrich(payload, payment_required, service_codes, always)}
    end
  end

  @spec enrich(map(), map() | nil, [code()], boolean()) :: map()
  defp enrich(payload, payment_required, service_codes, always) do
    advertised = advertised_declaration(payment_required)

    case always or not is_nil(advertised) do
      true -> put_service_codes(payload, advertised || %{}, service_codes)
      false -> payload
    end
  end

  @spec advertised_declaration(term()) :: map() | nil
  defp advertised_declaration(payment_required) when is_map(payment_required) do
    case Utils.map_value(payment_required, {"extensions", :extensions}) do
      %{} = extensions ->
        case Utils.map_value(extensions, {@extension_key, :"builder-code"}) do
          %{} = declaration -> declaration
          _other -> nil
        end

      _extensions ->
        nil
    end
  end

  defp advertised_declaration(_payment_required), do: nil

  # The payload's own echo (already copied by X402.Client) wins over the
  # advertisement so anything an earlier enricher added is preserved.
  @spec put_service_codes(map(), map(), [code()]) :: map()
  defp put_service_codes(payload, advertised, service_codes) do
    extensions =
      case Utils.map_value(payload, {"extensions", :extensions}) do
        %{} = existing -> existing
        _other -> %{}
      end

    declaration =
      case Utils.map_value(extensions, {@extension_key, :"builder-code"}) do
        %{} = existing -> existing
        _other -> advertised
      end

    info =
      case Utils.map_value(declaration, {"info", :info}) do
        %{} = existing -> existing
        _other -> %{}
      end

    merged = Enum.uniq(service_codes ++ existing_service_codes(info))
    updated = Utils.map_put(declaration, {"info", :info}, Map.put(info, "s", merged))
    extensions = Utils.map_put(extensions, {@extension_key, :"builder-code"}, updated)
    Utils.map_put(payload, {"extensions", :extensions}, extensions)
  end

  @spec existing_service_codes(map()) :: [code()]
  defp existing_service_codes(info) do
    case Utils.map_value(info, {"s", :s}) do
      codes when is_list(codes) -> codes
      code when is_binary(code) -> [code]
      _absent -> []
    end
  end
end
