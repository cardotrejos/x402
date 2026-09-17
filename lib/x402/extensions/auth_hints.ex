defmodule X402.Extensions.AuthHints do
  @moduledoc """
  The x402 `auth-hints` extension: per-requirement authentication hints.

  Implements the
  [auth-hints extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-auth-hints.md).
  A resource server whose `accepts[]` entries require authentication maps
  them to the authentication methods that satisfy them under
  `PaymentRequired.extensions["auth-hints"]`, so a client can register
  and obtain credentials *before* submitting a payment instead of
  discovering the requirement through a `401`:

      %{
        "auth-hints" => %{
          "info" => %{
            "authRequirements" => [
              %{"acceptIndexes" => [1], "methods" => [%{"type" => "oauth2", ...}]}
            ]
          },
          "schema" => %{...}
        }
      }

  Two method types are defined: `oauth2` (`oauth2/1`), carrying the token
  type and the authorization server's endpoints, and `sign-in-with-x`
  (`sign_in_with_x/0`), a pointer to the `sign-in-with-x` extension on
  the same response (`X402.Extensions.SIWX`). Unknown types are preserved
  on decode so clients can skip what they do not support.

  ## Server

  Advertise hints from a gate route with `X402.Extensions.AuthHints.Adapter`
  or build the value yourself with `extension/1`:

      X402.Extensions.AuthHints.extension([
        [accept_indexes: [1], methods: [X402.Extensions.AuthHints.oauth2(
          token_type: "DPoP",
          authorization_server: "https://as.example.com",
          token_endpoint: "https://as.example.com/token",
          registration_endpoint: "https://as.example.com/register"
        )]]
      ])

  The hints are discovery metadata only: validating the credentials the
  client then presents (`Authorization`, `DPoP`, `SIGN-IN-WITH-X`) stays
  with the application, and the facilitator is not involved.

  ## Client

  `methods_for/2` returns the methods a chosen `accepts[]` entry requires
  — an empty list when it needs none — so a `X402.Client.Hooks`
  `before_payment/2` implementation can complete the flow first:

      def before_payment(%{payment_required: payment_required, requirements: chosen} = context, _meta) do
        case X402.Extensions.AuthHints.methods_for(payment_required, chosen) do
          [] -> {:ok, context}
          methods -> authenticate(methods, context)
        end
      end

  Indexes that fall outside `accepts[]` are silently ignored, as the
  specification requires of clients.
  """

  alias X402.Utils

  @extension_key "auth-hints"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"
  @oauth2 "oauth2"
  @siwx "sign-in-with-x"
  @token_types ["Bearer", "DPoP"]

  @schema %{
    "$schema" => @schema_uri,
    "type" => "object",
    "properties" => %{
      "authRequirements" => %{
        "type" => "array",
        "items" => %{
          "type" => "object",
          "properties" => %{
            "acceptIndexes" => %{
              "type" => "array",
              "items" => %{"type" => "integer"},
              "description" => "Indexes into the accepts[] array"
            },
            "methods" => %{
              "type" => "array",
              "items" => %{
                "type" => "object",
                "properties" => %{
                  "type" => %{
                    "type" => "string",
                    "description" => "Authentication method type"
                  }
                },
                "required" => ["type"]
              }
            }
          },
          "required" => ["acceptIndexes", "methods"]
        }
      }
    },
    "required" => ["authRequirements"]
  }

  @oauth2_opts_schema [
    token_type: [
      type: {:in, @token_types},
      required: true,
      doc: "How the access token is presented: `\"Bearer\"` or `\"DPoP\"`."
    ],
    authorization_server: [
      type: {:custom, __MODULE__, :validate_url, []},
      required: true,
      doc: "Base URL of the authorization server."
    ],
    token_endpoint: [
      type: {:custom, __MODULE__, :validate_url, []},
      required: true,
      doc: "Token endpoint URL."
    ],
    registration_endpoint: [
      type: {:custom, __MODULE__, :validate_url, []},
      doc: "RFC 7591 dynamic client registration endpoint, when registration is available."
    ]
  ]

  @requirement_opts_schema [
    accept_indexes: [
      type: {:custom, __MODULE__, :validate_indexes, []},
      required: true,
      doc: "Indexes into `accepts[]` that require authentication (at least one)."
    ],
    methods: [
      type: {:custom, __MODULE__, :validate_methods, []},
      required: true,
      doc:
        "Methods that satisfy the requirement (at least one), as built by `oauth2/1` or `sign_in_with_x/0`."
    ]
  ]

  @typedoc "A method map as it appears on the wire."
  @type method :: %{required(String.t()) => term()}

  @typedoc "A decoded requirement."
  @type requirement :: %{accept_indexes: [non_neg_integer()], methods: [method()]}

  @typedoc "Errors returned by `decode/1` and `validate_method/1`."
  @type error ::
          :invalid_auth_hints
          | :invalid_accept_indexes
          | :invalid_method
          | {:missing_method_field, String.t()}
          | :invalid_token_type

  @doc since: "0.9.0"
  @doc """
  Returns the extension key on the wire.

  ## Examples

      iex> X402.Extensions.AuthHints.extension_key()
      "auth-hints"
  """
  @spec extension_key() :: String.t()
  def extension_key, do: @extension_key

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema the server advertises for the extension.

  ## Examples

      iex> schema = X402.Extensions.AuthHints.schema()
      iex> schema["required"]
      ["authRequirements"]
      iex> get_in(schema, ["properties", "authRequirements", "items", "required"])
      ["acceptIndexes", "methods"]
  """
  @spec schema() :: map()
  def schema, do: @schema

  @doc since: "0.9.0"
  @doc """
  Builds an `oauth2` method.

  Raises `NimbleOptions.ValidationError` for invalid options: a malformed
  hint is a configuration error.

  ## Options

  #{NimbleOptions.docs(@oauth2_opts_schema)}

  ## Examples

      iex> X402.Extensions.AuthHints.oauth2(
      ...>   token_type: "DPoP",
      ...>   authorization_server: "https://as.example.com",
      ...>   token_endpoint: "https://as.example.com/token",
      ...>   registration_endpoint: "https://as.example.com/register"
      ...> )
      %{
        "type" => "oauth2",
        "tokenType" => "DPoP",
        "authorizationServer" => "https://as.example.com",
        "tokenEndpoint" => "https://as.example.com/token",
        "registrationEndpoint" => "https://as.example.com/register"
      }

      iex> X402.Extensions.AuthHints.oauth2(
      ...>   token_type: "Bearer",
      ...>   authorization_server: "https://as.example.com",
      ...>   token_endpoint: "https://as.example.com/token"
      ...> )
      %{
        "type" => "oauth2",
        "tokenType" => "Bearer",
        "authorizationServer" => "https://as.example.com",
        "tokenEndpoint" => "https://as.example.com/token"
      }
  """
  @spec oauth2(keyword()) :: method()
  def oauth2(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @oauth2_opts_schema)

    method = %{
      "type" => @oauth2,
      "tokenType" => Keyword.fetch!(opts, :token_type),
      "authorizationServer" => Keyword.fetch!(opts, :authorization_server),
      "tokenEndpoint" => Keyword.fetch!(opts, :token_endpoint)
    }

    case Keyword.get(opts, :registration_endpoint) do
      nil -> method
      endpoint -> Map.put(method, "registrationEndpoint", endpoint)
    end
  end

  @doc since: "0.9.0"
  @doc """
  Builds a `sign-in-with-x` method: a pointer to the `sign-in-with-x`
  extension advertised on the same response.

  ## Examples

      iex> X402.Extensions.AuthHints.sign_in_with_x()
      %{"type" => "sign-in-with-x"}
  """
  @spec sign_in_with_x() :: method()
  def sign_in_with_x, do: %{"type" => @siwx}

  @doc since: "0.9.0"
  @doc """
  Validates a method map as it appears on the wire.

  `oauth2` must carry a `tokenType` of `Bearer` or `DPoP` and string
  `authorizationServer` and `tokenEndpoint` values; `sign-in-with-x`
  needs only its type. Other types are accepted as long as `type` is a
  string, so clients can ignore methods they do not implement.

  ## Examples

      iex> X402.Extensions.AuthHints.validate_method(%{"type" => "sign-in-with-x"})
      {:ok, %{"type" => "sign-in-with-x"}}

      iex> X402.Extensions.AuthHints.validate_method(%{"type" => "oauth2", "tokenType" => "Bearer",
      ...>   "authorizationServer" => "https://as.example.com"})
      {:error, {:missing_method_field, "tokenEndpoint"}}

      iex> X402.Extensions.AuthHints.validate_method(%{"type" => "oauth2", "tokenType" => "MAC",
      ...>   "authorizationServer" => "https://as.example.com", "tokenEndpoint" => "https://as.example.com/token"})
      {:error, :invalid_token_type}

      iex> X402.Extensions.AuthHints.validate_method(%{"type" => "future"})
      {:ok, %{"type" => "future"}}

      iex> X402.Extensions.AuthHints.validate_method(%{"tokenType" => "Bearer"})
      {:error, :invalid_method}
  """
  @spec validate_method(term()) :: {:ok, method()} | {:error, error()}
  def validate_method(%{"type" => @oauth2} = method) do
    with :ok <- require_string(method, "tokenType"),
         :ok <- require_string(method, "authorizationServer"),
         :ok <- require_string(method, "tokenEndpoint"),
         true <- method["tokenType"] in @token_types || {:error, :invalid_token_type},
         true <- optional_string?(method, "registrationEndpoint") || {:error, :invalid_method} do
      {:ok, method}
    end
  end

  def validate_method(%{"type" => type} = method) when is_binary(type), do: {:ok, method}
  def validate_method(_method), do: {:error, :invalid_method}

  @spec require_string(map(), String.t()) :: :ok | {:error, error()}
  defp require_string(method, field) do
    case Map.get(method, field) do
      value when is_binary(value) and value != "" -> :ok
      nil -> {:error, {:missing_method_field, field}}
      _other -> {:error, :invalid_method}
    end
  end

  @spec optional_string?(map(), String.t()) :: boolean()
  defp optional_string?(method, field) do
    case Map.get(method, field) do
      nil -> true
      value -> is_binary(value)
    end
  end

  @doc false
  @spec validate_methods(term()) :: {:ok, [method()]} | {:error, String.t()}
  def validate_methods([]), do: {:error, "expected at least one authentication method"}

  def validate_methods(methods) when is_list(methods) do
    Enum.reduce_while(methods, {:ok, []}, fn method, {:ok, acc} ->
      case validate_method(method) do
        {:ok, method} ->
          {:cont, {:ok, [method | acc]}}

        {:error, reason} ->
          {:halt,
           {:error, "invalid authentication method #{inspect(method)}: #{inspect(reason)}"}}
      end
    end)
    |> case do
      {:ok, methods} -> {:ok, Enum.reverse(methods)}
      error -> error
    end
  end

  def validate_methods(other),
    do: {:error, "expected a list of authentication methods, got: #{inspect(other)}"}

  @doc false
  @spec validate_indexes(term()) :: {:ok, [non_neg_integer()]} | {:error, String.t()}
  def validate_indexes([_ | _] = indexes) do
    case Enum.all?(indexes, &(is_integer(&1) and &1 >= 0)) do
      true -> {:ok, indexes}
      false -> {:error, "expected non-negative accept indexes, got: #{inspect(indexes)}"}
    end
  end

  def validate_indexes(other),
    do: {:error, "expected a non-empty list of accept indexes, got: #{inspect(other)}"}

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

  @doc since: "0.9.0"
  @doc """
  Builds the server-side advertisement for `PaymentRequired.extensions`.

  Each requirement is a keyword list with `:accept_indexes` and
  `:methods`. Raises `NimbleOptions.ValidationError` for an invalid
  declaration, including an empty requirement list.

  ## Requirement options

  #{NimbleOptions.docs(@requirement_opts_schema)}

  ## Examples

      iex> extension = X402.Extensions.AuthHints.extension([
      ...>   [accept_indexes: [1], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]
      ...> ])
      iex> extension["info"]
      %{"authRequirements" => [%{"acceptIndexes" => [1], "methods" => [%{"type" => "sign-in-with-x"}]}]}
      iex> extension["schema"] == X402.Extensions.AuthHints.schema()
      true
  """
  @spec extension([keyword()]) :: map()
  def extension([_ | _] = auth_requirements) do
    requirements =
      Enum.map(auth_requirements, fn requirement ->
        opts = NimbleOptions.validate!(requirement, @requirement_opts_schema)

        %{
          "acceptIndexes" => Keyword.fetch!(opts, :accept_indexes),
          "methods" => Keyword.fetch!(opts, :methods)
        }
      end)

    %{"info" => %{"authRequirements" => requirements}, "schema" => @schema}
  end

  def extension(other) do
    raise NimbleOptions.ValidationError,
      message: "expected a non-empty list of auth requirements, got: #{inspect(other)}",
      key: :auth_requirements
  end

  @doc since: "0.9.0"
  @doc """
  Decodes the requirements from a `PaymentRequired` map (or its
  `extensions` map).

  Returns `{:ok, []}` when the extension is absent. Indexes outside the
  response's `accepts[]` are dropped (when the map given is the full
  `PaymentRequired`); a requirement left with no index is dropped too.
  Methods are checked with `validate_method/1`.

  ## Examples

      iex> extension = X402.Extensions.AuthHints.extension([
      ...>   [accept_indexes: [1, 7], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]
      ...> ])
      iex> payment_required = %{"accepts" => [%{}, %{}], "extensions" => %{"auth-hints" => extension}}
      iex> X402.Extensions.AuthHints.decode(payment_required)
      {:ok, [%{accept_indexes: [1], methods: [%{"type" => "sign-in-with-x"}]}]}

      iex> X402.Extensions.AuthHints.decode(%{"accepts" => [], "extensions" => %{}})
      {:ok, []}

      iex> X402.Extensions.AuthHints.decode(%{"extensions" => %{"auth-hints" => %{"info" => %{"authRequirements" => "x"}}}})
      {:error, :invalid_auth_hints}

      iex> hints = %{"info" => %{"authRequirements" => [%{"acceptIndexes" => [0], "methods" => [%{"type" => "oauth2"}]}]}}
      iex> X402.Extensions.AuthHints.decode(%{"accepts" => [%{}], "extensions" => %{"auth-hints" => hints}})
      {:error, {:missing_method_field, "tokenType"}}
  """
  @spec decode(term()) :: {:ok, [requirement()]} | {:error, error()}
  def decode(payment_required) when is_map(payment_required) do
    case advertised(payment_required) do
      nil -> {:ok, []}
      declaration -> decode_declaration(declaration, accepts_count(payment_required))
    end
  end

  def decode(_payment_required), do: {:error, :invalid_auth_hints}

  @spec advertised(map()) :: term()
  defp advertised(payment_required) do
    extensions =
      case Utils.map_value(payment_required, {"extensions", :extensions}) do
        %{} = extensions -> extensions
        _other -> payment_required
      end

    Utils.map_value(extensions, {@extension_key, :"auth-hints"})
  end

  @spec accepts_count(map()) :: non_neg_integer() | nil
  defp accepts_count(payment_required) do
    case Utils.map_value(payment_required, {"accepts", :accepts}) do
      accepts when is_list(accepts) -> length(accepts)
      _other -> nil
    end
  end

  @spec decode_declaration(term(), non_neg_integer() | nil) ::
          {:ok, [requirement()]} | {:error, error()}
  defp decode_declaration(%{} = declaration, count) do
    info =
      case Utils.map_value(declaration, {"info", :info}) do
        %{} = info -> info
        _other -> declaration
      end

    case Utils.map_value(info, {"authRequirements", :authRequirements}) do
      requirements when is_list(requirements) -> decode_requirements(requirements, count)
      _other -> {:error, :invalid_auth_hints}
    end
  end

  defp decode_declaration(_declaration, _count), do: {:error, :invalid_auth_hints}

  @spec decode_requirements([term()], non_neg_integer() | nil) ::
          {:ok, [requirement()]} | {:error, error()}
  defp decode_requirements(requirements, count) do
    Enum.reduce_while(requirements, {:ok, []}, fn requirement, {:ok, acc} ->
      case decode_requirement(requirement, count) do
        {:ok, nil} -> {:cont, {:ok, acc}}
        {:ok, decoded} -> {:cont, {:ok, [decoded | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      error -> error
    end
  end

  @spec decode_requirement(term(), non_neg_integer() | nil) ::
          {:ok, requirement() | nil} | {:error, error()}
  defp decode_requirement(%{} = requirement, count) do
    with {:ok, indexes} <-
           decode_indexes(Utils.map_value(requirement, {"acceptIndexes", :acceptIndexes}), count),
         {:ok, methods} <- decode_methods(Utils.map_value(requirement, {"methods", :methods})) do
      case indexes do
        [] -> {:ok, nil}
        indexes -> {:ok, %{accept_indexes: indexes, methods: methods}}
      end
    end
  end

  defp decode_requirement(_requirement, _count), do: {:error, :invalid_auth_hints}

  @spec decode_indexes(term(), non_neg_integer() | nil) ::
          {:ok, [non_neg_integer()]} | {:error, error()}
  defp decode_indexes(indexes, count) when is_list(indexes) do
    case Enum.all?(indexes, &is_integer/1) do
      true -> {:ok, Enum.filter(indexes, &in_range?(&1, count))}
      false -> {:error, :invalid_accept_indexes}
    end
  end

  defp decode_indexes(_indexes, _count), do: {:error, :invalid_accept_indexes}

  @spec in_range?(integer(), non_neg_integer() | nil) :: boolean()
  defp in_range?(index, nil), do: index >= 0
  defp in_range?(index, count), do: index >= 0 and index < count

  @spec decode_methods(term()) :: {:ok, [method()]} | {:error, error()}
  defp decode_methods(methods) when is_list(methods) do
    Enum.reduce_while(methods, {:ok, []}, fn method, {:ok, acc} ->
      case validate_method(method) do
        {:ok, method} -> {:cont, {:ok, [method | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, methods} -> {:ok, Enum.reverse(methods)}
      error -> error
    end
  end

  defp decode_methods(_methods), do: {:error, :invalid_method}

  @doc since: "0.9.0"
  @doc """
  Returns the methods that satisfy authentication for one `accepts[]`
  entry, given by index or by the requirements map itself.

  Methods from every requirement naming the entry are concatenated in
  order. Returns `[]` when no authentication is needed, when the entry is
  not found, or when the extension is malformed — the client then
  proceeds without credentials and the server answers as it would for
  any unauthenticated request.

  ## Examples

      iex> oauth2 = X402.Extensions.AuthHints.oauth2(token_type: "DPoP",
      ...>   authorization_server: "https://as.example.com", token_endpoint: "https://as.example.com/token")
      iex> extension = X402.Extensions.AuthHints.extension([[accept_indexes: [1], methods: [oauth2]]])
      iex> exact = %{"scheme" => "exact", "network" => "eip155:8453"}
      iex> deferred = %{"scheme" => "deferred", "network" => "eip155:8453"}
      iex> payment_required = %{"accepts" => [exact, deferred], "extensions" => %{"auth-hints" => extension}}
      iex> X402.Extensions.AuthHints.methods_for(payment_required, deferred) == [oauth2]
      true
      iex> X402.Extensions.AuthHints.methods_for(payment_required, 1) == [oauth2]
      true
      iex> X402.Extensions.AuthHints.methods_for(payment_required, exact)
      []
      iex> X402.Extensions.AuthHints.methods_for(payment_required, 5)
      []
  """
  @spec methods_for(map(), non_neg_integer() | map()) :: [method()]
  def methods_for(payment_required, index) when is_map(payment_required) and is_integer(index) do
    case decode(payment_required) do
      {:ok, requirements} ->
        requirements
        |> Enum.filter(&(index in &1.accept_indexes))
        |> Enum.flat_map(& &1.methods)

      {:error, _reason} ->
        []
    end
  end

  def methods_for(payment_required, requirements)
      when is_map(payment_required) and is_map(requirements) do
    accepts =
      case Utils.map_value(payment_required, {"accepts", :accepts}) do
        accepts when is_list(accepts) -> accepts
        _other -> []
      end

    case Enum.find_index(accepts, &(&1 == requirements)) do
      nil -> []
      index -> methods_for(payment_required, index)
    end
  end

  @doc since: "0.9.0"
  @doc """
  Returns whether an `accepts[]` entry (by index or map) requires
  authentication.

  ## Examples

      iex> extension = X402.Extensions.AuthHints.extension([
      ...>   [accept_indexes: [0], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]
      ...> ])
      iex> payment_required = %{"accepts" => [%{"scheme" => "exact"}, %{"scheme" => "upto"}], "extensions" => %{"auth-hints" => extension}}
      iex> X402.Extensions.AuthHints.requires_auth?(payment_required, 0)
      true
      iex> X402.Extensions.AuthHints.requires_auth?(payment_required, %{"scheme" => "upto"})
      false
  """
  @spec requires_auth?(map(), non_neg_integer() | map()) :: boolean()
  def requires_auth?(payment_required, index_or_requirements),
    do: methods_for(payment_required, index_or_requirements) != []
end
