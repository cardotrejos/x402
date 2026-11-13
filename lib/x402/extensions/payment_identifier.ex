defmodule X402.Extensions.PaymentIdentifier do
  @moduledoc """
  The x402 `payment-identifier` extension: client-generated idempotency ids.

  Implements the
  [payment-identifier extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/payment_identifier.md).
  A server advertises the extension in `PaymentRequired.extensions` under
  the `"payment-identifier"` key (`extension/1`); the client echoes the
  advertisement and adds its id under `info.id` (`enricher/1`):

      # server (PaymentRequired.extensions)
      %{"payment-identifier" => %{"info" => %{"required" => true}, "schema" => %{...}}}

      # client (PaymentPayload.extensions)
      %{"payment-identifier" => %{"info" => %{"required" => true, "id" => "..."}, "schema" => %{...}}}

  A valid id is 16 to 128 characters drawn from `[A-Za-z0-9_-]`
  (`valid_id?/1`); `generate_id/0` produces one. Servers extract the echoed
  id with `extract_id/1` and bind it to the request through `fingerprint/2`:
  the same id reused for a different request is a conflict.

  ## Legacy `paymentIdentifier` format (deprecated)

  Releases before 0.7.0 used a `"paymentIdentifier"` key whose value was a
  Base64 JSON `{"paymentId": ...}` string, a bare `%{"paymentId" => id}`
  map, or an `%{"info" => ...}` envelope around either. `extract_id/1`
  still understands that format — reporting it as `{:legacy, id}` — and
  `encode/1`, `decode/1`, and `fetch_payment_id/1` still produce and
  consume it. Every legacy function is deprecated and will be removed in
  1.0.0; servers emit a `[:x402, :payment_identifier, :legacy]` telemetry
  event (and a one-time warning log) when they see it.
  """

  alias X402.Utils

  require Logger

  @extension_key "payment-identifier"
  @legacy_extension_key "paymentIdentifier"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"
  @min_id_length 16
  @max_id_length 128
  # \z rather than $: PCRE's $ also matches before a trailing newline.
  @id_pattern ~r/\A[A-Za-z0-9_-]+\z/
  @generated_id_bytes 24

  @schema %{
    "$schema" => @schema_uri,
    "type" => "object",
    "properties" => %{
      "id" => %{
        "type" => "string",
        "minLength" => @min_id_length,
        "maxLength" => @max_id_length,
        "pattern" => "^[A-Za-z0-9_-]+$"
      },
      "required" => %{"type" => "boolean"}
    }
  }

  @extension_opts_schema [
    required: [
      type: :boolean,
      default: false,
      doc: "Whether clients must supply an id (`info.required`)."
    ]
  ]

  @enricher_opts_schema [
    id: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: """
      Explicit id to attach. When omitted a fresh `generate_id/0` value is
      produced on every invocation of the returned function.
      """
    ],
    always: [
      type: :boolean,
      default: false,
      doc: """
      Attach the extension even when the server did not advertise
      `payment-identifier`. Defaults to `false`: the enricher is a no-op
      for servers that do not support the extension.
      """
    ]
  ]

  @typedoc "Payment identifier value used for idempotency."
  @type payment_id :: String.t()

  @typedoc "An extracted id, tagged with the wire format it arrived in."
  @type extracted :: {:spec, payment_id()} | {:legacy, payment_id()}

  @typedoc "Errors returned by `extract_id/1`."
  @type extract_error :: :invalid_payment_id | {:legacy, decode_error()}

  @typedoc "Request context hashed into `fingerprint/2`."
  @type fingerprint_context :: %{
          optional(:method) => atom() | String.t(),
          optional(:path) => String.t(),
          optional(:tool) => String.t()
        }

  @typedoc "Where a legacy-format identifier was observed."
  @type legacy_source :: :gate | :mcp

  @type encode_error :: :invalid_payment_id | :invalid_json

  @type decode_error ::
          :invalid_base64 | :invalid_json | :missing_payment_id | :invalid_payment_id

  # -- Spec format ------------------------------------------------------------

  @doc since: "0.9.0"
  @doc """
  Returns the extension key on the wire.

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.extension_key()
      "payment-identifier"
  """
  @spec extension_key() :: String.t()
  def extension_key, do: @extension_key

  @doc since: "0.9.0"
  @doc """
  Returns the deprecated pre-0.7.0 extension key.

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.legacy_extension_key()
      "paymentIdentifier"
  """
  @spec legacy_extension_key() :: String.t()
  def legacy_extension_key, do: @legacy_extension_key

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema the server advertises for the extension.

  ## Examples

      iex> schema = X402.Extensions.PaymentIdentifier.schema()
      iex> schema["properties"]["id"]["pattern"]
      "^[A-Za-z0-9_-]+$"
  """
  @spec schema() :: map()
  def schema, do: @schema

  @doc since: "0.9.0"
  @doc """
  Builds the server-side advertisement for `PaymentRequired.extensions`.

  ## Options

  #{NimbleOptions.docs(@extension_opts_schema)}

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.extension()["info"]
      %{"required" => false}

      iex> X402.Extensions.PaymentIdentifier.extension(required: true)["info"]
      %{"required" => true}

      iex> extension = X402.Extensions.PaymentIdentifier.extension()
      iex> extension["schema"] == X402.Extensions.PaymentIdentifier.schema()
      true
  """
  @spec extension(keyword()) :: map()
  def extension(opts \\ []) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @extension_opts_schema)

    %{
      "info" => %{"required" => Keyword.fetch!(opts, :required)},
      "schema" => @schema
    }
  end

  @doc since: "0.9.0"
  @doc """
  Checks whether `id` is a valid spec-format identifier.

  Valid ids are #{@min_id_length} to #{@max_id_length} characters long and
  contain only `A-Z`, `a-z`, `0-9`, `_`, and `-`.

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.valid_id?("abcdefghijklmnop")
      true

      iex> X402.Extensions.PaymentIdentifier.valid_id?("too-short")
      false

      iex> X402.Extensions.PaymentIdentifier.valid_id?("has spaces in the id")
      false

      iex> X402.Extensions.PaymentIdentifier.valid_id?(nil)
      false
  """
  @spec valid_id?(term()) :: boolean()
  def valid_id?(id) when is_binary(id) do
    size = byte_size(id)
    size >= @min_id_length and size <= @max_id_length and Regex.match?(@id_pattern, id)
  end

  def valid_id?(_id), do: false

  @doc since: "0.9.0"
  @doc """
  Generates a random 32-character identifier (#{@generated_id_bytes} random
  bytes, Base64url without padding).

  ## Examples

      iex> id = X402.Extensions.PaymentIdentifier.generate_id()
      iex> String.length(id)
      32
      iex> X402.Extensions.PaymentIdentifier.valid_id?(id)
      true
  """
  @spec generate_id() :: payment_id()
  def generate_id do
    @generated_id_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc since: "0.9.0"
  @doc """
  Returns whether an advertised extensions map marks the id as required.

  Accepts the `PaymentRequired.extensions` map (string or atom keys).

  ## Examples

      iex> extensions = %{"payment-identifier" => X402.Extensions.PaymentIdentifier.extension(required: true)}
      iex> X402.Extensions.PaymentIdentifier.required?(extensions)
      true

      iex> X402.Extensions.PaymentIdentifier.required?(%{"payment-identifier" => %{"info" => %{}}})
      false

      iex> X402.Extensions.PaymentIdentifier.required?(%{})
      false

      iex> X402.Extensions.PaymentIdentifier.required?(nil)
      false
  """
  @spec required?(term()) :: boolean()
  def required?(extensions) when is_map(extensions) do
    Utils.nested_map_value(extensions, [
      {@extension_key, :"payment-identifier"},
      {"info", :info},
      {"required", :required}
    ]) == true
  end

  def required?(_extensions), do: false

  @doc since: "0.9.0"
  @doc """
  Extracts the client's payment id from a `PaymentPayload.extensions` map.

  Returns `{:ok, {:spec, id}}` for the `"payment-identifier"` format,
  `{:ok, {:legacy, id}}` for the deprecated `"paymentIdentifier"` format,
  and `{:ok, nil}` when no id is present (including when the spec extension
  is echoed without an `info.id`). The spec key takes precedence: the legacy
  key is only consulted when the spec key carries no id.

  Errors are `:invalid_payment_id` for a spec-format id that fails
  `valid_id?/1` (or a non-map spec value), and `{:legacy, reason}` for a
  malformed legacy value. Legacy ids are not subject to the spec's length
  and character rules — any non-empty string is accepted.

  ## Examples

      iex> extensions = %{"payment-identifier" => %{"info" => %{"id" => "abcdefghijklmnop", "required" => false}}}
      iex> X402.Extensions.PaymentIdentifier.extract_id(extensions)
      {:ok, {:spec, "abcdefghijklmnop"}}

      iex> X402.Extensions.PaymentIdentifier.extract_id(%{"payment-identifier" => %{"info" => %{"id" => "short"}}})
      {:error, :invalid_payment_id}

      iex> X402.Extensions.PaymentIdentifier.extract_id(%{"paymentIdentifier" => %{"paymentId" => "pay-1"}})
      {:ok, {:legacy, "pay-1"}}

      iex> X402.Extensions.PaymentIdentifier.extract_id(%{"paymentIdentifier" => %{}})
      {:error, {:legacy, :missing_payment_id}}

      iex> X402.Extensions.PaymentIdentifier.extract_id(%{})
      {:ok, nil}

      iex> X402.Extensions.PaymentIdentifier.extract_id(nil)
      {:ok, nil}
  """
  @spec extract_id(term()) :: {:ok, extracted() | nil} | {:error, extract_error()}
  def extract_id(extensions) when is_map(extensions) do
    case extract_spec_id(extensions) do
      {:ok, nil} -> extract_legacy_id(extensions)
      result -> result
    end
  end

  def extract_id(_extensions), do: {:ok, nil}

  @spec extract_spec_id(map()) ::
          {:ok, {:spec, payment_id()} | nil} | {:error, :invalid_payment_id}
  defp extract_spec_id(extensions) do
    case Utils.map_value(extensions, {@extension_key, :"payment-identifier"}) do
      nil -> {:ok, nil}
      %{} = declaration -> spec_id_from_info(Utils.map_value(declaration, {"info", :info}))
      _other -> {:error, :invalid_payment_id}
    end
  end

  @spec spec_id_from_info(term()) ::
          {:ok, {:spec, payment_id()} | nil} | {:error, :invalid_payment_id}
  defp spec_id_from_info(nil), do: {:ok, nil}

  defp spec_id_from_info(%{} = info) do
    case Utils.map_value(info, {"id", :id}) do
      nil -> {:ok, nil}
      id -> validate_spec_id(id)
    end
  end

  defp spec_id_from_info(_info), do: {:error, :invalid_payment_id}

  @spec validate_spec_id(term()) :: {:ok, {:spec, payment_id()}} | {:error, :invalid_payment_id}
  defp validate_spec_id(id) do
    case valid_id?(id) do
      true -> {:ok, {:spec, id}}
      false -> {:error, :invalid_payment_id}
    end
  end

  @spec extract_legacy_id(map()) ::
          {:ok, {:legacy, payment_id()} | nil} | {:error, {:legacy, decode_error()}}
  defp extract_legacy_id(extensions) do
    case Utils.map_value(extensions, {@legacy_extension_key, :paymentIdentifier}) do
      nil -> {:ok, nil}
      value -> decode_legacy_value(value)
    end
  end

  # The legacy value may be wrapped in the generic %{"info" => ...} envelope
  # that X402.PaymentRequirements.extensions_match?/2 unwraps, so an echo
  # that passes extension validation must not be rejected as malformed here.
  @spec decode_legacy_value(term()) ::
          {:ok, {:legacy, payment_id()}} | {:error, {:legacy, decode_error()}}
  defp decode_legacy_value(%{} = value) do
    case Utils.map_value(value, {"info", :info}) do
      nil -> decode_bare_legacy_value(value)
      info -> decode_bare_legacy_value(info)
    end
  end

  defp decode_legacy_value(value), do: decode_bare_legacy_value(value)

  @spec decode_bare_legacy_value(term()) ::
          {:ok, {:legacy, payment_id()}} | {:error, {:legacy, decode_error()}}
  defp decode_bare_legacy_value(value) when is_binary(value) do
    case decode(value) do
      {:ok, payment_id} -> {:ok, {:legacy, payment_id}}
      {:error, reason} -> {:error, {:legacy, reason}}
    end
  end

  defp decode_bare_legacy_value(value) when is_map(value) do
    case fetch_payment_id(value) do
      {:ok, payment_id} -> {:ok, {:legacy, payment_id}}
      {:error, reason} -> {:error, {:legacy, reason}}
    end
  end

  defp decode_bare_legacy_value(_value), do: {:error, {:legacy, :invalid_payment_id}}

  @doc since: "0.9.0"
  @doc """
  Computes the request fingerprint a payment id is bound to.

  The fingerprint is the lowercase hex SHA-256 of the newline-joined
  sequence `scheme`, `network`, `asset`, `amount`, `payTo` (read from
  `requirements`, string or atom keys) followed by the context's `:method`,
  `:path`, and `:tool`, in that order. Absent values contribute an empty
  string; atoms are stringified (`:get` becomes `"get"`). Two requests with
  the same fingerprint are the same request for idempotency purposes; a
  reused id with a different fingerprint is a conflict.

  ## Examples

      iex> requirements = %{"scheme" => "exact", "network" => "eip155:8453", "asset" => "0xusdc", "amount" => "1000", "payTo" => "0xabc"}
      iex> a = X402.Extensions.PaymentIdentifier.fingerprint(requirements, %{method: :get, path: "/api"})
      iex> b = X402.Extensions.PaymentIdentifier.fingerprint(requirements, %{method: :get, path: "/api"})
      iex> a == b
      true
      iex> String.length(a)
      64

      iex> requirements = %{"scheme" => "exact", "network" => "eip155:8453", "asset" => "0xusdc", "amount" => "1000", "payTo" => "0xabc"}
      iex> a = X402.Extensions.PaymentIdentifier.fingerprint(requirements, %{tool: "search"})
      iex> b = X402.Extensions.PaymentIdentifier.fingerprint(requirements, %{tool: "other"})
      iex> a == b
      false
  """
  @spec fingerprint(map(), fingerprint_context()) :: String.t()
  def fingerprint(requirements, context) when is_map(requirements) and is_map(context) do
    canonical =
      Enum.map_join(
        [
          Utils.map_value(requirements, {"scheme", :scheme}),
          Utils.map_value(requirements, {"network", :network}),
          Utils.map_value(requirements, {"asset", :asset}),
          Utils.map_value(requirements, {"amount", :amount}),
          Utils.map_value(requirements, {"payTo", :payTo}),
          Map.get(context, :method),
          Map.get(context, :path),
          Map.get(context, :tool)
        ],
        "\n",
        &fingerprint_component/1
      )

    Base.encode16(:crypto.hash(:sha256, canonical), case: :lower)
  end

  @spec fingerprint_component(term()) :: String.t()
  defp fingerprint_component(nil), do: ""
  defp fingerprint_component(value) when is_binary(value), do: value
  defp fingerprint_component(value) when is_atom(value), do: Atom.to_string(value)
  defp fingerprint_component(value) when is_integer(value), do: Integer.to_string(value)
  defp fingerprint_component(value), do: inspect(value)

  @doc since: "0.9.0"
  @doc """
  Builds a client-side enricher for `X402.Client.build_payment/3`'s
  `:extensions` option.

  When the server advertised `payment-identifier` (or `always: true`), the
  returned function attaches the spec-format extension to the payload:
  the advertised `info` and `schema` are echoed unchanged and `info.id` is
  added. Otherwise the payload passes through untouched. Without an
  advertisement the `always: true` form attaches `%{"info" => %{"id" => id}}`.

  The returned function yields `{:error, :invalid_payment_id}` when an
  explicit `:id` fails `valid_id?/1`.

  ## Options

  #{NimbleOptions.docs(@enricher_opts_schema)}

  ## Examples

      iex> enricher = X402.Extensions.PaymentIdentifier.enricher(id: "abcdefghijklmnop")
      iex> advertised = %{"payment-identifier" => X402.Extensions.PaymentIdentifier.extension(required: true)}
      iex> payment_required = %{"extensions" => advertised}
      iex> payload = %{"extensions" => advertised}
      iex> {:ok, enriched} = enricher.(payload, payment_required)
      iex> enriched["extensions"]["payment-identifier"]["info"]
      %{"required" => true, "id" => "abcdefghijklmnop"}

      iex> enricher = X402.Extensions.PaymentIdentifier.enricher()
      iex> enricher.(%{"extensions" => %{}}, %{"extensions" => %{}})
      {:ok, %{"extensions" => %{}}}
  """
  @spec enricher(keyword()) ::
          (map(), map() | nil -> {:ok, map()} | {:error, :invalid_payment_id})
  def enricher(opts \\ []) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @enricher_opts_schema)
    explicit_id = Keyword.fetch!(opts, :id)
    always = Keyword.fetch!(opts, :always)

    fn payload, payment_required -> enrich(payload, payment_required, explicit_id, always) end
  end

  @spec enrich(map(), map() | nil, payment_id() | nil, boolean()) ::
          {:ok, map()} | {:error, :invalid_payment_id}
  defp enrich(payload, payment_required, explicit_id, always) do
    advertised = advertised_declaration(payment_required)

    case always or not is_nil(advertised) do
      true ->
        with {:ok, id} <- enricher_id(explicit_id) do
          {:ok, put_id(payload, advertised || %{}, id)}
        end

      false ->
        {:ok, payload}
    end
  end

  @spec enricher_id(payment_id() | nil) :: {:ok, payment_id()} | {:error, :invalid_payment_id}
  defp enricher_id(nil), do: {:ok, generate_id()}

  defp enricher_id(id) do
    case valid_id?(id) do
      true -> {:ok, id}
      false -> {:error, :invalid_payment_id}
    end
  end

  @spec advertised_declaration(term()) :: map() | nil
  defp advertised_declaration(payment_required) when is_map(payment_required) do
    case Utils.map_value(payment_required, {"extensions", :extensions}) do
      %{} = extensions ->
        case Utils.map_value(extensions, {@extension_key, :"payment-identifier"}) do
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
  @spec put_id(map(), map(), payment_id()) :: map()
  defp put_id(payload, advertised, id) do
    extensions =
      case Utils.map_value(payload, {"extensions", :extensions}) do
        %{} = existing -> existing
        _other -> %{}
      end

    declaration =
      case Utils.map_value(extensions, {@extension_key, :"payment-identifier"}) do
        %{} = existing -> existing
        _other -> advertised
      end

    info =
      case Utils.map_value(declaration, {"info", :info}) do
        %{} = existing -> existing
        _other -> %{}
      end

    updated = Utils.map_put(declaration, {"info", :info}, Map.put(info, "id", id))
    extensions = Utils.map_put(extensions, {@extension_key, :"payment-identifier"}, updated)
    Utils.map_put(payload, {"extensions", :extensions}, extensions)
  end

  @doc false
  @spec legacy_notice(legacy_source()) :: :ok
  def legacy_notice(source) when source in [:gate, :mcp] do
    X402.Telemetry.emit(:payment_identifier, :legacy, :ok, %{source: source})
    warn_legacy_once()
  end

  @spec warn_legacy_once() :: :ok
  defp warn_legacy_once do
    key = {__MODULE__, :legacy_format_warned}

    unless :persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "[X402.Extensions.PaymentIdentifier] received a payment identifier in the " <>
          "deprecated `paymentIdentifier` format. Clients should send the spec " <>
          "`payment-identifier` extension; legacy support is removed in 1.0.0."
      )
    end

    :ok
  end

  # -- Legacy format (deprecated) ---------------------------------------------

  @doc since: "0.1.0"
  @deprecated "Use the spec `payment-identifier` format (extension/1, extract_id/1); removed in 1.0.0"
  @doc """
  Encodes a legacy payment identifier to a Base64 JSON payload.

      {:ok, encoded} = X402.Extensions.PaymentIdentifier.encode("payment-123")
      {:ok, "payment-123"} = X402.Extensions.PaymentIdentifier.decode(encoded)
  """
  @spec encode(payment_id()) :: {:ok, String.t()} | {:error, encode_error()}
  def encode(payment_id) when is_binary(payment_id) and payment_id != "" do
    payload = %{"paymentId" => payment_id}

    case Jason.encode(payload) do
      {:ok, json} -> {:ok, Base.encode64(json)}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  def encode(_payment_id), do: {:error, :invalid_payment_id}

  @doc since: "0.1.0"
  @deprecated "Use the spec `payment-identifier` format (extension/1, extract_id/1); removed in 1.0.0"
  @doc """
  Decodes a legacy Base64 JSON payload and returns the payment identifier.

      {:ok, encoded} = X402.Extensions.PaymentIdentifier.encode("payment-123")
      X402.Extensions.PaymentIdentifier.decode(encoded)
      #=> {:ok, "payment-123"}

      X402.Extensions.PaymentIdentifier.decode("not-base64")
      #=> {:error, :invalid_base64}
  """
  @spec decode(String.t()) :: {:ok, payment_id()} | {:error, decode_error()}
  def decode(value) when is_binary(value) do
    with {:ok, json} <- decode_base64(value),
         {:ok, decoded} <- Jason.decode(json),
         {:ok, payment_id} <- fetch_payment_id(decoded) do
      {:ok, payment_id}
    else
      {:error, :invalid_base64} -> {:error, :invalid_base64}
      {:error, :missing_payment_id} -> {:error, :missing_payment_id}
      {:error, :invalid_payment_id} -> {:error, :invalid_payment_id}
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_json}
    end
  end

  def decode(_value), do: {:error, :invalid_base64}

  @doc since: "0.1.0"
  @deprecated "Use the spec `payment-identifier` format (extension/1, extract_id/1); removed in 1.0.0"
  @doc """
  Extracts and validates `"paymentId"` from a decoded legacy payload map.

      X402.Extensions.PaymentIdentifier.fetch_payment_id(%{"paymentId" => "pay-1"})
      #=> {:ok, "pay-1"}

      X402.Extensions.PaymentIdentifier.fetch_payment_id(%{})
      #=> {:error, :missing_payment_id}
  """
  @spec fetch_payment_id(term()) ::
          {:ok, payment_id()} | {:error, :missing_payment_id | :invalid_payment_id}
  def fetch_payment_id(payload) when is_map(payload) do
    case Map.fetch(payload, "paymentId") do
      {:ok, payment_id} when is_binary(payment_id) and payment_id != "" -> {:ok, payment_id}
      {:ok, _invalid} -> {:error, :invalid_payment_id}
      :error -> {:error, :missing_payment_id}
    end
  end

  def fetch_payment_id(_payload), do: {:error, :invalid_payment_id}

  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  defp decode_base64(""), do: {:error, :invalid_base64}

  defp decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end
end
