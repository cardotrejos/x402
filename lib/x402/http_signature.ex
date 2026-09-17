defmodule X402.HTTPSignature do
  @moduledoc """
  RFC 9421 HTTP Message Signatures: sign and verify requests and responses.

  Implements the profile the x402 `http-message-signatures` extension
  relies on: the derived components `@method`, `@target-uri`,
  `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
  `@query-param;name` and `@status`, plain HTTP fields (with the `req`
  flag for request components covered by a response signature, RFC 9421
  §2.4), the `created`, `expires`, `nonce`, `alg`, `keyid` and `tag`
  parameters, and the `ed25519`, `ecdsa-p256-sha256` and
  `rsa-pss-sha512` algorithms (`X402.HTTPSignature.Key`).

  ## Messages

  A message is a plain map:

  * `:method` — the request method (`"GET"` or `:get`);
  * `:url` — the absolute target URI of the request;
  * `:headers` — a list of `{name, value}` pairs (any case, repeated
    names allowed) or a map of name to value or list of values;
  * `:status` — the status code, which marks the message as a response;
  * `:request` — for a response, the request it answers, used by
    components carrying the `req` flag.

  ## Signing a request

      {:ok, key} = X402.HTTPSignature.Key.generate("ed25519")

      message = %{
        method: "GET",
        url: "https://api.example.com/premium?limit=10",
        headers: [{"payment-signature", encoded_payload}]
      }

      {:ok, headers} = X402.HTTPSignature.sign(message, key, tag: "web-bot-auth")
      # [{"signature-input", ~S|sig1=("@method" "@authority" "@path" "payment-signature");created=...|},
      #  {"signature", "sig1=:...:"}]

  ## Signing a response

  Response signatures cover `@status`, the x402 header and, bound to the
  request through `;req`, the request authority and path — the shape the
  extension specification recommends:

      response = %{status: 200, headers: [{"payment-response", encoded}], request: message}
      {:ok, headers} = X402.HTTPSignature.sign(response, key, tag: "x402-response")

  ## Verifying

  `verify/2` takes the message (with its `Signature-Input` and
  `Signature` headers) and resolves the key from the `keyid` parameter:

      X402.HTTPSignature.verify(message,
        keys: fn keyid -> MyApp.Keys.fetch(keyid) end,
        required_components: ["@method", "@authority", "@path"],
        max_age: 300
      )
      # {:ok, %{label: "sig1", key: key, params: %{"created" => ..., "keyid" => ...}, components: [...]}}

  Verification trusts nothing the signature says about itself: the key
  comes from `:keys` (the `keyid` parameter is only a lookup hint and
  must match the key's `kid`), the algorithm is the key's and must be in
  `:algorithms` (an `alg` parameter that disagrees is rejected), and the
  caller states which components and parameters must be covered. A
  message carrying two candidate signatures, or a `Signature-Input`
  with a repeated label or parameter, is rejected as ambiguous rather
  than picking one.

  ## Profile

  This is a bounded profile of RFC 9421, not a complete implementation.
  Out of scope, and rejected when encountered:

  * the `hmac-sha256`, `rsa-v1_5-sha256` and `ecdsa-p384-sha384`
    algorithms, and the `sf`, `key`, `bs` and `tr` component parameters
    (RFC 9421 §2.1.1–§2.1.4);
  * `Accept-Signature` negotiation (§5) and `Content-Digest` (RFC 9530),
    which callers cover as a plain field when they compute it;
  * key discovery: `verify/2` never fetches a directory, the caller's
    `:keys` does the lookup.
  """

  alias X402.HTTPSignature.Key
  alias X402.HTTPSignature.StructuredField

  @typedoc "A component identifier: the lowercased name and its ordered parameters."
  @type component :: {String.t(), [{String.t(), true | String.t()}]}

  @typedoc """
  A component as given to `sign/3`: a name, or a name with parameters
  such as `{"@authority", req: true}` or `{"@query-param", name: "Pet"}`.
  """
  @type component_spec :: String.t() | {String.t(), keyword()}

  @typedoc "Signature parameters in serialization order."
  @type params :: [{String.t(), StructuredField.bare()}]

  @typedoc "A request or response message."
  @type message :: %{
          optional(:method) => String.t() | atom(),
          optional(:url) => String.t(),
          optional(:headers) => [{String.t(), String.t()}] | %{optional(String.t()) => term()},
          optional(:status) => 100..599,
          optional(:request) => map()
        }

  @typedoc "A successful verification."
  @type verified :: %{
          label: String.t(),
          key: Key.t(),
          params: %{optional(String.t()) => StructuredField.bare()},
          components: [component()]
        }

  @type base_error ::
          {:missing_component, String.t()}
          | {:duplicate_component, String.t()}
          | {:invalid_component, String.t()}
          | {:unknown_component, String.t()}
          | {:unsupported_component_parameter, String.t()}
          | {:invalid_field_value, String.t()}
          | :non_ascii
          | :invalid_structured_field

  @type sign_error :: base_error() | Key.error()

  @type verify_error ::
          base_error()
          | :missing_signature
          | :malformed_signature_input
          | :malformed_signature
          | :signature_not_found
          | :ambiguous_signature
          | :unknown_key
          | :invalid_key
          | :algorithm_mismatch
          | {:unsupported_algorithm, term()}
          | {:missing_parameter, String.t()}
          | :signature_expired
          | :signature_too_old
          | :signature_not_yet_valid
          | :invalid_signature

  @signature_input_header "signature-input"
  @signature_header "signature"

  @request_only ~w(@method @target-uri @authority @scheme @request-target @path @query @query-param)
  @derived @request_only ++ ["@status"]

  @unsupported_component_params ~w(sf key bs tr)

  @sign_opts_schema [
    components: [
      type: {:list, :any},
      doc: """
      Covered components, in order. Defaults to `"@method"`, `"@authority"`
      and `"@path"` plus `"payment-signature"` when present for a request,
      and to `"@status"`, `"payment-required"`/`"payment-response"` when
      present, and `"@authority";req`/`"@path";req` when `:request` is
      given for a response.
      """
    ],
    label: [type: :string, default: "sig1", doc: "The signature label."],
    created: [
      type: {:or, [:non_neg_integer, {:in, [false]}]},
      doc: "The `created` timestamp; defaults to now. `false` omits it."
    ],
    expires: [type: :non_neg_integer, doc: "Absolute `expires` timestamp."],
    ttl: [type: :pos_integer, doc: "Sets `expires` to `created` plus this many seconds."],
    nonce: [
      type: {:or, [:string, :boolean]},
      default: false,
      doc: "A `nonce` value; `true` generates a random one."
    ],
    tag: [type: :string, doc: "The application `tag`."],
    keyid: [
      type: {:or, [:string, {:in, [false]}]},
      doc: "Overrides the key's `kid`; `false` omits the parameter."
    ],
    alg: [type: :boolean, default: false, doc: "Include the `alg` parameter."]
  ]

  @verify_opts_schema [
    keys: [
      type: :any,
      required: true,
      doc: """
      The verification keys: a `X402.HTTPSignature.Key`, a list of them
      (matched by `kid`), or a function receiving the `keyid` parameter
      (or `nil`) and returning a key, a JWK map, `{:ok, key}`, or
      `nil`/`:error`.
      """
    ],
    label: [type: :string, doc: "Verify the signature with this label only."],
    tag: [type: :string, doc: "Verify the signature carrying this `tag` only."],
    algorithms: [
      type: {:list, :string},
      default: Key.algorithms(),
      doc: "Accepted algorithms."
    ],
    required_components: [
      type: {:list, :any},
      default: [],
      doc: "Components that must be covered (same forms as `sign/3`)."
    ],
    required_params: [
      type: {:list, :string},
      default: [],
      doc: "Signature parameters that must be present, for example `[\"created\"]`."
    ],
    max_age: [type: :pos_integer, doc: "Maximum seconds since `created`."],
    clock_skew: [type: :non_neg_integer, default: 0, doc: "Tolerance for time checks."],
    now: [type: :non_neg_integer, doc: "The current UNIX time; defaults to the system clock."]
  ]

  @doc since: "0.9.0"
  @doc """
  Signs a message, returning the `signature-input` and `signature`
  headers to attach to it.

  The key must carry private material. Parameters are serialized in the
  order `created`, `expires`, `keyid`, `alg`, `nonce`, `tag`.

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}

  ## Examples

      iex> seed = Base.url_decode64!("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU", padding: false)
      iex> {:ok, key} = X402.HTTPSignature.Key.new(alg: "ed25519", private_key: seed, kid: "test-key-ed25519")
      iex> message = %{
      ...>   method: "POST",
      ...>   url: "https://example.com/foo?param=Value&Pet=dog",
      ...>   headers: [
      ...>     {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
      ...>     {"Content-Type", "application/json"},
      ...>     {"Content-Length", "18"}
      ...>   ]
      ...> }
      iex> X402.HTTPSignature.sign(message, key,
      ...>   label: "sig-b26",
      ...>   components: ["date", "@method", "@path", "@authority", "content-type", "content-length"],
      ...>   created: 1_618_884_473
      ...> )
      {:ok, [
        {"signature-input", ~S|sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"|},
        {"signature", "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"}
      ]}

      iex> {:ok, key} = X402.HTTPSignature.Key.generate("ed25519")
      iex> X402.HTTPSignature.sign(%{method: "GET", url: "https://example.com/"}, key, components: ["content-type"])
      {:error, {:missing_component, ~S|"content-type"|}}
  """
  @spec sign(message(), Key.t(), keyword()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, sign_error()}
  def sign(message, %Key{} = key, opts \\ []) when is_map(message) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)
    label = Keyword.fetch!(opts, :label)

    with {:ok, components} <-
           normalize_components(
             Keyword.get_lazy(opts, :components, fn -> default_components(message) end)
           ),
         params = signature_params(key, opts),
         {:ok, base} <- signature_base(message, components, params),
         {:ok, signature} <- Key.sign(key, base),
         {:ok, input_value} <-
           StructuredField.serialize_dictionary([{label, inner_list(components, params)}]),
         {:ok, signature_value} <-
           StructuredField.serialize_dictionary([{label, {{:bytes, signature}, []}}]) do
      {:ok, [{@signature_input_header, input_value}, {@signature_header, signature_value}]}
    end
  end

  @spec signature_params(Key.t(), keyword()) :: params()
  defp signature_params(key, opts) do
    created = optional_param(Keyword.get(opts, :created, System.os_time(:second)))
    expires = signature_expiry(Keyword.get(opts, :expires), Keyword.get(opts, :ttl), created)
    keyid = optional_param(Keyword.get(opts, :keyid, key.kid))
    nonce = signature_nonce(Keyword.fetch!(opts, :nonce))
    alg = if Keyword.fetch!(opts, :alg), do: key.alg

    [
      {"created", created},
      {"expires", expires},
      {"keyid", keyid},
      {"alg", alg},
      {"nonce", nonce},
      {"tag", Keyword.get(opts, :tag)}
    ]
    |> Enum.reject(fn {_name, value} -> is_nil(value) end)
  end

  @spec optional_param(term()) :: term()
  defp optional_param(false), do: nil
  defp optional_param(value), do: value

  @spec signature_expiry(integer() | nil, non_neg_integer() | nil, integer() | nil) ::
          integer() | nil
  defp signature_expiry(nil, nil, _created), do: nil
  defp signature_expiry(nil, ttl, nil), do: System.os_time(:second) + ttl
  defp signature_expiry(nil, ttl, created), do: created + ttl
  defp signature_expiry(expires, _ttl, _created), do: expires

  @spec signature_nonce(boolean() | String.t()) :: String.t() | nil
  defp signature_nonce(false), do: nil
  defp signature_nonce(true), do: Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
  defp signature_nonce(value), do: value

  @doc since: "0.9.0"
  @doc """
  Returns the default covered components for a message (see `sign/3`).

  ## Examples

      iex> X402.HTTPSignature.default_components(%{method: "GET", url: "https://example.com/"})
      ["@method", "@authority", "@path"]

      iex> X402.HTTPSignature.default_components(%{method: "GET", url: "https://example.com/", headers: [{"PAYMENT-SIGNATURE", "abc"}]})
      ["@method", "@authority", "@path", "payment-signature"]

      iex> X402.HTTPSignature.default_components(%{status: 402, headers: %{"payment-required" => "abc"}, request: %{}})
      ["@status", "payment-required", {"@authority", [req: true]}, {"@path", [req: true]}]

      iex> X402.HTTPSignature.default_components(%{status: 200})
      ["@status"]
  """
  @spec default_components(message()) :: [component_spec()]
  def default_components(%{status: _status} = response) do
    headers = header_names(response)

    ["@status"] ++
      Enum.filter(["payment-required", "payment-response"], &(&1 in headers)) ++
      if(Map.has_key?(response, :request),
        do: [{"@authority", [req: true]}, {"@path", [req: true]}],
        else: []
      )
  end

  def default_components(request) do
    case "payment-signature" in header_names(request) do
      true -> ["@method", "@authority", "@path", "payment-signature"]
      false -> ["@method", "@authority", "@path"]
    end
  end

  @spec header_names(message()) :: [String.t()]
  defp header_names(message) do
    message |> Map.get(:headers, []) |> normalize_headers() |> Enum.map(&elem(&1, 0))
  end

  @doc since: "0.9.0"
  @doc """
  Verifies a signature on a message.

  Exactly one signature is verified: the one selected by `:label` and/or
  `:tag`, or the only signature present; several candidates are
  `:ambiguous_signature`. The key is resolved from the `keyid` parameter
  through `:keys`; a key with a `kid` different from the parameter is
  rejected, as is a key whose algorithm differs from an explicit `alg`
  parameter or is not in `:algorithms`.

  Time checks use the `created`/`expires` parameters when present:
  `expires` in the past, `created` in the future, or `created` older
  than `:max_age` fail the verification (`:clock_skew` widens each check).
  Nothing is bounded by default: set `:max_age` (which also demands
  `created`) or `required_params: ["expires"]` to enforce freshness.

  ## Options

  #{NimbleOptions.docs(@verify_opts_schema)}

  ## Examples

      iex> jwk = %{"kty" => "OKP", "crv" => "Ed25519", "kid" => "test-key-ed25519", "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
      iex> {:ok, key} = X402.HTTPSignature.Key.from_jwk(jwk)
      iex> message = %{
      ...>   method: "POST",
      ...>   url: "https://example.com/foo?param=Value&Pet=dog",
      ...>   headers: [
      ...>     {"date", "Tue, 20 Apr 2021 02:07:55 GMT"},
      ...>     {"content-type", "application/json"},
      ...>     {"content-length", "18"},
      ...>     {"signature-input", ~S|sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"|},
      ...>     {"signature", "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"}
      ...>   ]
      ...> }
      iex> {:ok, verified} = X402.HTTPSignature.verify(message, keys: [key])
      iex> {verified.label, verified.params["created"], length(verified.components)}
      {"sig-b26", 1618884473, 6}

      iex> X402.HTTPSignature.verify(%{method: "GET", url: "https://example.com/"}, keys: [])
      {:error, :missing_signature}
  """
  @spec verify(message(), keyword()) :: {:ok, verified()} | {:error, verify_error()}
  def verify(message, opts) when is_map(message) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @verify_opts_schema)
    headers = message |> Map.get(:headers, []) |> normalize_headers()

    with {:ok, inputs} <- parse_signature_inputs(headers),
         {:ok, signatures} <- parse_signatures(headers),
         {:ok, label, components, params} <- select_signature(inputs, opts),
         {:ok, signature} <- fetch_signature(signatures, label),
         :ok <- check_required(components, params, opts),
         :ok <- check_times(params, opts),
         {:ok, key} <- resolve_key(params, opts),
         {:ok, base} <- signature_base(message, components, params),
         true <- Key.verify(key, base, signature) || {:error, :invalid_signature} do
      {:ok, %{label: label, key: key, params: Map.new(params), components: components}}
    end
  end

  @spec parse_signature_inputs([{String.t(), String.t()}]) ::
          {:ok, StructuredField.dictionary()} | {:error, verify_error()}
  defp parse_signature_inputs(headers) do
    case field_instances(headers, @signature_input_header) do
      [] -> {:error, :missing_signature}
      values -> parse_dictionary(Enum.join(values, ", "), :malformed_signature_input)
    end
  end

  @spec parse_signatures([{String.t(), String.t()}]) ::
          {:ok, StructuredField.dictionary()} | {:error, verify_error()}
  defp parse_signatures(headers) do
    case field_instances(headers, @signature_header) do
      [] -> {:error, :missing_signature}
      values -> parse_dictionary(Enum.join(values, ", "), :malformed_signature)
    end
  end

  @spec parse_dictionary(String.t(), atom()) ::
          {:ok, StructuredField.dictionary()} | {:error, atom()}
  defp parse_dictionary(value, error) do
    case StructuredField.parse_dictionary(value, duplicate_keys: :error) do
      {:ok, dictionary} -> {:ok, dictionary}
      {:error, _reason} -> {:error, error}
    end
  end

  @spec select_signature(StructuredField.dictionary(), keyword()) ::
          {:ok, String.t(), [component()], params()} | {:error, verify_error()}
  defp select_signature(inputs, opts) do
    label = Keyword.get(opts, :label)
    tag = Keyword.get(opts, :tag)

    inputs
    |> Enum.filter(fn {input_label, value} ->
      (is_nil(label) or input_label == label) and (is_nil(tag) or tag_of(value) == tag)
    end)
    |> case do
      [{label, {:inner_list, items, params}}] ->
        with {:ok, components} <- parse_components(items),
             :ok <- validate_params(params) do
          {:ok, label, components, params}
        end

      [{_label, _item}] ->
        {:error, :malformed_signature_input}

      [] ->
        {:error, :signature_not_found}

      [_first, _second | _rest] ->
        {:error, :ambiguous_signature}
    end
  end

  @spec tag_of(StructuredField.member()) :: term()
  defp tag_of({:inner_list, _items, params}), do: param(params, "tag")
  defp tag_of(_member), do: nil

  @spec parse_components([StructuredField.item()]) ::
          {:ok, [component()]} | {:error, verify_error()}
  defp parse_components(items) do
    Enum.reduce_while(items, {:ok, []}, fn
      {name, params}, {:ok, acc} when is_binary(name) ->
        case valid_component_params?(params) do
          true -> {:cont, {:ok, [{name, params} | acc]}}
          false -> {:halt, {:error, :malformed_signature_input}}
        end

      _item, _acc ->
        {:halt, {:error, :malformed_signature_input}}
    end)
    |> case do
      {:ok, components} -> {:ok, Enum.reverse(components)}
      error -> error
    end
  end

  @spec valid_component_params?(StructuredField.params()) :: boolean()
  defp valid_component_params?(params) do
    Enum.all?(params, fn
      {"req", true} -> true
      {"name", value} -> is_binary(value)
      {key, true} -> key in @unsupported_component_params
      {_key, _value} -> false
    end)
  end

  @spec validate_params(StructuredField.params()) :: :ok | {:error, :malformed_signature_input}
  defp validate_params(params) do
    valid? =
      Enum.all?(params, fn
        {"created", value} -> is_integer(value)
        {"expires", value} -> is_integer(value)
        {name, value} when name in ~w(keyid alg nonce tag) -> is_binary(value)
        {_name, _value} -> true
      end)

    if valid?, do: :ok, else: {:error, :malformed_signature_input}
  end

  @spec fetch_signature(StructuredField.dictionary(), String.t()) ::
          {:ok, binary()} | {:error, verify_error()}
  defp fetch_signature(signatures, label) do
    case List.keyfind(signatures, label, 0) do
      {^label, {{:bytes, signature}, _params}} -> {:ok, signature}
      {^label, _other} -> {:error, :malformed_signature}
      nil -> {:error, :missing_signature}
    end
  end

  @spec check_required([component()], params(), keyword()) :: :ok | {:error, verify_error()}
  defp check_required(components, params, opts) do
    with {:ok, required} <- normalize_components(Keyword.fetch!(opts, :required_components)),
         :ok <- check_required_components(components, required) do
      check_required_params(params, Keyword.fetch!(opts, :required_params))
    end
  end

  @spec check_required_components([component()], [component()]) :: :ok | {:error, verify_error()}
  defp check_required_components(components, required) do
    covered = Enum.map(components, &canonical_component/1)

    case Enum.find(required, &(canonical_component(&1) not in covered)) do
      nil -> :ok
      missing -> {:error, {:missing_component, serialize_component!(missing)}}
    end
  end

  # RFC 9421 §2: parameter order is preserved on the wire but is not
  # significant when comparing identifiers for equality.
  @spec canonical_component(component()) :: component()
  defp canonical_component({name, params}), do: {name, Enum.sort(params)}

  @spec check_required_params(params(), [String.t()]) :: :ok | {:error, verify_error()}
  defp check_required_params(params, required) do
    case Enum.find(required, &is_nil(List.keyfind(params, &1, 0))) do
      nil -> :ok
      missing -> {:error, {:missing_parameter, missing}}
    end
  end

  @spec check_times(params(), keyword()) :: :ok | {:error, verify_error()}
  defp check_times(params, opts) do
    now = Keyword.get_lazy(opts, :now, fn -> System.os_time(:second) end)
    skew = Keyword.fetch!(opts, :clock_skew)
    created = param(params, "created")
    expires = param(params, "expires")
    max_age = Keyword.get(opts, :max_age)

    cond do
      is_integer(expires) and now > expires + skew ->
        {:error, :signature_expired}

      is_integer(created) and created > now + skew ->
        {:error, :signature_not_yet_valid}

      true ->
        check_age(created, max_age, now, skew)
    end
  end

  @spec check_age(integer() | nil, non_neg_integer() | nil, integer(), non_neg_integer()) ::
          :ok | {:error, verify_error()}
  defp check_age(created, max_age, now, skew)
       when is_integer(created) and is_integer(max_age) and now > created + max_age + skew,
       do: {:error, :signature_too_old}

  defp check_age(nil, max_age, _now, _skew) when is_integer(max_age),
    do: {:error, {:missing_parameter, "created"}}

  defp check_age(_created, _max_age, _now, _skew), do: :ok

  @spec param(params(), String.t()) :: term()
  defp param(params, name) do
    case List.keyfind(params, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  @spec resolve_key(params(), keyword()) :: {:ok, Key.t()} | {:error, verify_error()}
  defp resolve_key(params, opts) do
    keyid = param(params, "keyid")

    with {:ok, key} <- lookup_key(Keyword.fetch!(opts, :keys), keyid),
         :ok <- check_kid(key, keyid),
         :ok <- check_algorithm(key, param(params, "alg"), Keyword.fetch!(opts, :algorithms)) do
      {:ok, key}
    end
  end

  @spec lookup_key(term(), String.t() | nil) :: {:ok, Key.t()} | {:error, verify_error()}
  defp lookup_key(%Key{} = key, _keyid), do: {:ok, key}

  defp lookup_key(keys, keyid) when is_list(keys) do
    case Enum.find(keys, &(match?(%Key{}, &1) and &1.kid == keyid)) do
      nil -> {:error, :unknown_key}
      key -> {:ok, key}
    end
  end

  defp lookup_key(fun, keyid) when is_function(fun, 1), do: normalize_lookup(fun.(keyid))
  defp lookup_key(_keys, _keyid), do: {:error, :unknown_key}

  @spec normalize_lookup(term()) :: {:ok, Key.t()} | {:error, verify_error()}
  defp normalize_lookup(%Key{} = key), do: {:ok, key}
  defp normalize_lookup({:ok, %Key{} = key}), do: {:ok, key}
  defp normalize_lookup(%{"kty" => _} = jwk), do: Key.from_jwk(jwk)
  defp normalize_lookup({:ok, %{"kty" => _} = jwk}), do: Key.from_jwk(jwk)
  defp normalize_lookup(_other), do: {:error, :unknown_key}

  @spec check_kid(Key.t(), String.t() | nil) :: :ok | {:error, :unknown_key}
  defp check_kid(%Key{kid: nil}, _keyid), do: :ok
  defp check_kid(_key, nil), do: :ok
  defp check_kid(%Key{kid: kid}, kid), do: :ok
  defp check_kid(_key, _keyid), do: {:error, :unknown_key}

  @spec check_algorithm(Key.t(), String.t() | nil, [String.t()]) :: :ok | {:error, verify_error()}
  defp check_algorithm(%Key{alg: alg}, param_alg, allowed) do
    cond do
      alg not in allowed -> {:error, {:unsupported_algorithm, alg}}
      is_binary(param_alg) and param_alg != alg -> {:error, :algorithm_mismatch}
      true -> :ok
    end
  end

  @doc since: "0.9.0"
  @doc """
  Builds the signature base (RFC 9421 §2.5) for a message, covered
  components and signature parameters.

  ## Examples

      iex> message = %{method: "POST", url: "https://example.com/foo?param=Value&Pet=dog",
      ...>   headers: [{"Content-Type", "application/json"}]}
      iex> {:ok, base} = X402.HTTPSignature.signature_base(message,
      ...>   ["@method", "@authority", "@path", "content-type"],
      ...>   [{"created", 1_618_884_473}, {"keyid", "test-key-rsa-pss"}])
      iex> String.split(base, "\\n")
      [
        ~S|"@method": POST|,
        ~S|"@authority": example.com|,
        ~S|"@path": /foo|,
        ~S|"content-type": application/json|,
        ~S|"@signature-params": ("@method" "@authority" "@path" "content-type");created=1618884473;keyid="test-key-rsa-pss"|
      ]

      iex> X402.HTTPSignature.signature_base(%{method: "GET", url: "https://example.com/"}, ["@status"], [])
      {:error, {:invalid_component, ~S|"@status"|}}

      iex> X402.HTTPSignature.signature_base(%{method: "GET", url: "https://example.com/"}, ["@path", "@path"], [])
      {:error, {:duplicate_component, ~S|"@path"|}}
  """
  @spec signature_base(message(), [component_spec()], params()) ::
          {:ok, String.t()} | {:error, base_error()}
  def signature_base(message, components, params)
      when is_map(message) and is_list(components) and is_list(params) do
    with {:ok, components} <- normalize_components(components),
         :ok <- check_duplicates(components),
         {:ok, lines} <- component_lines(message, components),
         {:ok, params_value} <-
           StructuredField.serialize_inner_list(inner_list(components, params)) do
      base = IO.iodata_to_binary([lines, ~S("@signature-params": ), params_value])

      case Regex.match?(~r/\A[\x00-\x7F]*\z/, base) do
        true -> {:ok, base}
        false -> {:error, :non_ascii}
      end
    end
  end

  @spec inner_list([component()], params()) :: StructuredField.inner_list()
  defp inner_list(components, params), do: {:inner_list, components, params}

  @spec check_duplicates([component()]) :: :ok | {:error, base_error()}
  defp check_duplicates(components) do
    components
    |> Enum.map(&canonical_component/1)
    |> Enum.reduce_while(MapSet.new(), fn component, seen ->
      case MapSet.member?(seen, component) do
        true -> {:halt, {:error, {:duplicate_component, serialize_component!(component)}}}
        false -> {:cont, MapSet.put(seen, component)}
      end
    end)
    |> case do
      {:error, _reason} = error -> error
      _seen -> :ok
    end
  end

  @spec component_lines(message(), [component()]) :: {:ok, iodata()} | {:error, base_error()}
  defp component_lines(message, components) do
    Enum.reduce_while(components, {:ok, []}, fn component, {:ok, acc} ->
      with {:ok, identifier} <- serialize_component(component),
           {:ok, value} <- component_value(message, component) do
        {:cont, {:ok, [[identifier, ": ", value, "\n"] | acc]}}
      else
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, lines} -> {:ok, Enum.reverse(lines)}
      error -> error
    end
  end

  @spec serialize_component(component()) ::
          {:ok, String.t()} | {:error, :invalid_structured_field}
  defp serialize_component({name, params}), do: StructuredField.serialize_item({name, params})

  @spec serialize_component!(component()) :: String.t()
  defp serialize_component!(component) do
    case serialize_component(component) do
      {:ok, serialized} -> serialized
      {:error, _reason} -> inspect(component)
    end
  end

  # -- Component values -------------------------------------------------------

  @spec component_value(message(), component()) :: {:ok, String.t()} | {:error, base_error()}
  defp component_value(message, {name, params} = component) do
    with :ok <- check_component_params(component),
         {:ok, target} <- component_target(message, component) do
      case name do
        "@" <> _derived -> derived_value(target, name, params, component)
        _field -> field_value(target, name, component)
      end
    end
  end

  @spec check_component_params(component()) :: :ok | {:error, base_error()}
  defp check_component_params({name, params} = component) do
    Enum.reduce_while(params, :ok, fn {key, value}, :ok ->
      cond do
        key in @unsupported_component_params ->
          {:halt, {:error, {:unsupported_component_parameter, key}}}

        key == "req" and value == true ->
          {:cont, :ok}

        key == "name" and name == "@query-param" and is_binary(value) ->
          {:cont, :ok}

        true ->
          {:halt, {:error, {:invalid_component, serialize_component!(component)}}}
      end
    end)
  end

  # RFC 9421 §2.5 step 2.5: `req` is only valid on a response and pulls the
  # value from the related request; request-targeted derived components
  # are invalid on a response without it, and `@status` on a request.
  @spec component_target(message(), component()) :: {:ok, message()} | {:error, base_error()}
  defp component_target(message, {name, params} = component) do
    req? = List.keymember?(params, "req", 0)
    response? = Map.has_key?(message, :status)

    case {req?, response?} do
      {true, false} ->
        {:error, {:invalid_component, serialize_component!(component)}}

      {true, true} ->
        request_target(message, component)

      {false, true} when name in @request_only ->
        {:error, {:invalid_component, serialize_component!(component)}}

      {false, false} when name == "@status" ->
        {:error, {:invalid_component, serialize_component!(component)}}

      _other ->
        {:ok, message}
    end
  end

  @spec request_target(message(), component()) :: {:ok, message()} | {:error, base_error()}
  defp request_target(%{request: request}, _component) when is_map(request), do: {:ok, request}

  defp request_target(_message, component),
    do: {:error, {:missing_component, serialize_component!(component)}}

  @spec derived_value(message(), String.t(), [{String.t(), term()}], component()) ::
          {:ok, String.t()} | {:error, base_error()}
  defp derived_value(_target, name, _params, component) when name not in @derived,
    do: {:error, {:unknown_component, serialize_component!(component)}}

  defp derived_value(target, "@status", _params, component) do
    case Map.get(target, :status) do
      status when is_integer(status) and status in 100..599 -> {:ok, Integer.to_string(status)}
      _other -> {:error, {:missing_component, serialize_component!(component)}}
    end
  end

  defp derived_value(target, "@method", _params, component) do
    case Map.get(target, :method) do
      method when is_binary(method) and method != "" ->
        {:ok, method}

      method when is_atom(method) and not is_nil(method) ->
        {:ok, method |> Atom.to_string() |> String.upcase()}

      _other ->
        {:error, {:missing_component, serialize_component!(component)}}
    end
  end

  defp derived_value(target, "@query-param", params, component) do
    case List.keyfind(params, "name", 0) do
      {"name", name} when is_binary(name) ->
        with {:ok, uri} <- target_uri(target, component) do
          query_param_value(uri.query || "", name, component)
        end

      nil ->
        {:error, {:invalid_component, serialize_component!(component)}}
    end
  end

  defp derived_value(target, name, _params, component) do
    with {:ok, uri} <- target_uri(target, component) do
      case name do
        "@target-uri" -> {:ok, URI.to_string(uri)}
        "@authority" -> {:ok, authority(uri)}
        "@scheme" -> {:ok, String.downcase(uri.scheme)}
        "@request-target" -> {:ok, path(uri) <> query_suffix(uri)}
        "@path" -> {:ok, path(uri)}
        "@query" -> {:ok, "?" <> (uri.query || "")}
      end
    end
  end

  @spec target_uri(message(), component()) :: {:ok, URI.t()} | {:error, base_error()}
  defp target_uri(target, component) do
    with url when is_binary(url) <- Map.get(target, :url, :missing),
         %URI{scheme: scheme, host: host} = uri
         when is_binary(scheme) and is_binary(host) and host != "" <-
           URI.parse(url) do
      {:ok, uri}
    else
      _other -> {:error, {:missing_component, serialize_component!(component)}}
    end
  end

  # RFC 9110 §4.2.3: lowercase host and omit the scheme's default port.
  @spec authority(URI.t()) :: String.t()
  defp authority(%URI{host: host, port: port, scheme: scheme}) do
    host = String.downcase(host)
    host = if String.contains?(host, ":"), do: "[" <> host <> "]", else: host

    case is_nil(port) or port == URI.default_port(scheme) do
      true -> host
      false -> host <> ":" <> Integer.to_string(port)
    end
  end

  @spec path(URI.t()) :: String.t()
  defp path(%URI{path: path}) when path in [nil, ""], do: "/"
  defp path(%URI{path: path}), do: path

  @spec query_suffix(URI.t()) :: String.t()
  defp query_suffix(%URI{query: nil}), do: ""
  defp query_suffix(%URI{query: query}), do: "?" <> query

  # RFC 9421 §2.2.8: parse as application/x-www-form-urlencoded and
  # re-encode with the form percent-encode set (space as %20, not +).
  @spec query_param_value(String.t(), String.t(), component()) ::
          {:ok, String.t()} | {:error, base_error()}
  defp query_param_value(query, name, component) do
    decoded_name = form_decode(name)

    query
    |> String.split("&")
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(fn pair ->
      case String.split(pair, "=", parts: 2) do
        [key, value] -> {form_decode(key), form_decode(value)}
        [key] -> {form_decode(key), ""}
      end
    end)
    |> Enum.filter(fn {key, _value} -> key == decoded_name end)
    |> case do
      [{_key, value}] -> {:ok, form_encode(value)}
      [] -> {:error, {:missing_component, serialize_component!(component)}}
      _many -> {:error, {:duplicate_component, serialize_component!(component)}}
    end
  end

  @spec form_decode(String.t()) :: String.t()
  defp form_decode(value), do: value |> String.replace("+", " ") |> URI.decode()

  @doc since: "0.9.0"
  @doc """
  Percent-encodes a query parameter name or value as RFC 9421 §2.2.8
  requires (the form-urlencoded percent-encode set, space as `%20`).

  ## Examples

      iex> X402.HTTPSignature.form_encode("with plus whitespace")
      "with%20plus%20whitespace"

      iex> X402.HTTPSignature.form_encode("façade\\": ")
      "fa%C3%A7ade%22%3A%20"

      iex> X402.HTTPSignature.form_encode("a-b_c.d*e")
      "a-b_c.d*e"
  """
  @spec form_encode(String.t()) :: String.t()
  def form_encode(value) when is_binary(value) do
    URI.encode(value, fn char ->
      char in ?a..?z or char in ?A..?Z or char in ?0..?9 or char in [?*, ?-, ?., ?_]
    end)
  end

  # RFC 9421 §2.1: instances in order, trimmed, obs-fold collapsed, joined
  # with ", ". An absent field is an error; an empty one is the empty string.
  @spec field_value(message(), String.t(), component()) ::
          {:ok, String.t()} | {:error, base_error()}
  defp field_value(target, name, component) do
    case field_instances(target |> Map.get(:headers, []) |> normalize_headers(), name) do
      [] ->
        {:error, {:missing_component, serialize_component!(component)}}

      values ->
        value = Enum.map_join(values, ", ", &canonicalize_field_value/1)

        case String.contains?(value, ["\r", "\n"]) do
          true -> {:error, {:invalid_field_value, name}}
          false -> {:ok, value}
        end
    end
  end

  @spec canonicalize_field_value(String.t()) :: String.t()
  defp canonicalize_field_value(value) do
    value
    |> String.replace(~r/\r?\n[ \t]+/, " ")
    |> String.replace(~r/\A[ \t]+|[ \t]+\z/, "")
  end

  @spec field_instances([{String.t(), String.t()}], String.t()) :: [String.t()]
  defp field_instances(headers, name) do
    for {^name, value} <- headers, do: value
  end

  @doc false
  @spec normalize_headers(term()) :: [{String.t(), String.t()}]
  def normalize_headers(headers) when is_list(headers) do
    for {name, value} <- headers,
        value <- List.wrap(value),
        do: {String.downcase(to_string(name)), to_string(value)}
  end

  def normalize_headers(headers) when is_map(headers),
    do: headers |> Enum.to_list() |> normalize_headers()

  def normalize_headers(_headers), do: []

  @doc since: "0.9.0"
  @doc """
  Normalizes component specs (as accepted by `sign/3`) to component
  identifiers with string parameter keys.

  ## Examples

      iex> X402.HTTPSignature.normalize_components(["@Method", {"@authority", req: true}, {"@query-param", name: "Pet"}])
      {:ok, [{"@method", []}, {"@authority", [{"req", true}]}, {"@query-param", [{"name", "Pet"}]}]}

      iex> X402.HTTPSignature.normalize_components([{"@path", req: "yes"}])
      {:error, {:invalid_component, "@path"}}

      iex> X402.HTTPSignature.normalize_components([:method])
      {:error, {:invalid_component, ":method"}}
  """
  @spec normalize_components([component_spec() | component()]) ::
          {:ok, [component()]} | {:error, {:invalid_component, String.t()}}
  def normalize_components(components) when is_list(components) do
    Enum.reduce_while(components, {:ok, []}, fn spec, {:ok, acc} ->
      case normalize_component(spec) do
        {:ok, component} -> {:cont, {:ok, [component | acc]}}
        :error -> {:halt, {:error, {:invalid_component, inspect_spec(spec)}}}
      end
    end)
    |> case do
      {:ok, components} -> {:ok, Enum.reverse(components)}
      error -> error
    end
  end

  @spec normalize_component(term()) :: {:ok, component()} | :error
  defp normalize_component(name) when is_binary(name), do: normalize_component({name, []})

  defp normalize_component({name, params})
       when is_binary(name) and name != "" and is_list(params) do
    params =
      Enum.reduce_while(params, {:ok, []}, fn
        {key, value}, {:ok, acc} when is_atom(key) or is_binary(key) ->
          case valid_component_param?(to_string(key), value) do
            true -> {:cont, {:ok, [{to_string(key), value} | acc]}}
            false -> {:halt, :error}
          end

        _param, _acc ->
          {:halt, :error}
      end)

    case params do
      {:ok, params} -> {:ok, {String.downcase(name), Enum.reverse(params)}}
      :error -> :error
    end
  end

  defp normalize_component(_spec), do: :error

  # `req` is a flag and `name` a string; other registered parameters are
  # kept as given and rejected when the signature base is built.
  @spec valid_component_param?(String.t(), term()) :: boolean()
  defp valid_component_param?("req", value), do: value == true
  defp valid_component_param?("name", value), do: is_binary(value)
  defp valid_component_param?(_key, value), do: value == true or is_binary(value)

  @spec inspect_spec(term()) :: String.t()
  defp inspect_spec({name, _params}) when is_binary(name), do: name
  defp inspect_spec(spec), do: inspect(spec)

  @doc since: "0.9.0"
  @doc """
  Builds the `/.well-known/http-message-signatures-directory` document
  (draft-meunier-http-message-signatures-directory §3): a JWK Set of the
  keys' public parts.

  Each entry is a `X402.HTTPSignature.Key` or `{key, extra}` where
  `extra` is a keyword list or map of additional JWK members such as
  `nbf` and `exp`.

  ## Examples

      iex> jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
      iex> {:ok, key} = X402.HTTPSignature.Key.from_jwk(jwk)
      iex> X402.HTTPSignature.directory([{key, nbf: 1_712_793_600, exp: 1_715_385_600}])
      %{
        "keys" => [
          %{
            "kty" => "OKP",
            "crv" => "Ed25519",
            "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
            "kid" => "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
            "alg" => "ed25519",
            "use" => "sig",
            "nbf" => 1712793600,
            "exp" => 1715385600
          }
        ]
      }
  """
  @spec directory([Key.t() | {Key.t(), keyword() | map()}]) :: map()
  def directory(keys) when is_list(keys) do
    %{"keys" => Enum.map(keys, &directory_entry/1)}
  end

  @spec directory_entry(Key.t() | {Key.t(), keyword() | map()}) :: map()
  defp directory_entry(%Key{} = key), do: Key.to_jwk(key)

  defp directory_entry({%Key{} = key, extra}) do
    extra = Map.new(extra, fn {name, value} -> {to_string(name), value} end)
    Map.merge(Key.to_jwk(key), extra)
  end

  @doc since: "0.9.0"
  @doc """
  Merges the headers produced by several `sign/3` calls (with distinct
  labels) into one `signature-input` and one `signature` header, as a
  directory response signed with every key requires.

  ## Examples

      iex> X402.HTTPSignature.merge_headers([
      ...>   [{"signature-input", "a=();created=1"}, {"signature", "a=:AQ==:"}],
      ...>   [{"signature-input", "b=();created=2"}, {"signature", "b=:Ag==:"}]
      ...> ])
      [{"signature-input", "a=();created=1, b=();created=2"}, {"signature", "a=:AQ==:, b=:Ag==:"}]
  """
  @spec merge_headers([[{String.t(), String.t()}]]) :: [{String.t(), String.t()}]
  def merge_headers(header_lists) when is_list(header_lists) do
    all = header_lists |> List.flatten() |> normalize_headers()

    for name <- [@signature_input_header, @signature_header] do
      {name, all |> field_instances(name) |> Enum.join(", ")}
    end
  end
end
