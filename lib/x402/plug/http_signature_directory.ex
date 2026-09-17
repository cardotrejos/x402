if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.HTTPSignatureDirectory do
    @moduledoc """
    Plug serving a signature agent's key directory at
    `/.well-known/http-message-signatures-directory`.

    The `http-message-signatures` extension asks paying agents to host
    the public keys they sign with as a JWKS document
    (`X402.HTTPSignature.directory/1`), served with the
    `application/http-message-signatures-directory+json` media type and
    signed with each of those keys so a verifier can check the directory
    belongs to the origin serving it
    (draft-meunier-http-message-signatures-directory).

        plug X402.Plug.HTTPSignatureDirectory, keys: [key]

    Requests for any other path, or with another method, pass through
    untouched, so the plug can sit anywhere in a pipeline. Keys are given
    as `X402.HTTPSignature.Key` structs carrying private material (needed
    to sign the response) or as a zero-arity function returning them, for
    keys rotated at runtime.

    ## Response signatures

    Each key signs the response over `@authority` bound to the request
    (`("@authority";req)`, as RFC 9421 §2.4 requires of a request
    component in a response signature), with `created`, `expires`,
    `keyid` (the key's `kid`), `alg`, `nonce` and the
    `http-message-signatures-directory` tag. Labels are `sig1`, `sig2`,
    and so on, in key order.
    """

    @behaviour Plug

    alias X402.HTTPSignature
    alias X402.HTTPSignature.Key

    import Plug.Conn, only: [halt: 1, put_resp_content_type: 2, put_resp_header: 3, send_resp: 3]

    @media_type "application/http-message-signatures-directory+json"
    @tag "http-message-signatures-directory"
    @default_path "/.well-known/http-message-signatures-directory"

    @options_schema [
      keys: [
        type: {:custom, __MODULE__, :validate_keys, []},
        required: true,
        doc: """
        The keys to publish: a list of `X402.HTTPSignature.Key` with private
        material, or a zero-arity function returning such a list.
        """
      ],
      path: [
        type: :string,
        default: @default_path,
        doc: "The request path served."
      ],
      sign: [
        type: :boolean,
        default: true,
        doc: "Whether to sign the response with each published key."
      ],
      ttl: [
        type: :pos_integer,
        default: 3600,
        doc: "Seconds between the signatures' `created` and `expires`."
      ]
    ]

    @typedoc "Validated options."
    @type options :: %{
            keys: [Key.t()] | (-> [Key.t()]),
            path: String.t(),
            sign: boolean(),
            ttl: pos_integer()
          }

    @doc since: "0.9.0"
    @doc """
    Returns the media type of the directory document.

    ## Examples

        iex> X402.Plug.HTTPSignatureDirectory.media_type()
        "application/http-message-signatures-directory+json"
    """
    @spec media_type() :: String.t()
    def media_type, do: @media_type

    @doc since: "0.9.0"
    @doc """
    Validates the options.

    ## Options

    #{NimbleOptions.docs(@options_schema)}

    ## Examples

        iex> {:ok, key} = X402.HTTPSignature.Key.generate("ed25519")
        iex> options = X402.Plug.HTTPSignatureDirectory.init(keys: [key])
        iex> {options.path, options.sign, options.ttl}
        {"/.well-known/http-message-signatures-directory", true, 3600}
    """
    @impl Plug
    @spec init(keyword()) :: options()
    def init(opts) do
      opts
      |> NimbleOptions.validate!(@options_schema)
      |> Map.new()
    end

    @doc false
    @spec validate_keys(term()) :: {:ok, [Key.t()] | (-> [Key.t()])} | {:error, String.t()}
    def validate_keys(fun) when is_function(fun, 0), do: {:ok, fun}

    def validate_keys([_ | _] = keys) do
      case Enum.all?(keys, &match?(%Key{private: private} when not is_nil(private), &1)) do
        true -> {:ok, keys}
        false -> {:error, "expected X402.HTTPSignature.Key structs with private material"}
      end
    end

    def validate_keys(other),
      do:
        {:error,
         "expected a non-empty list of keys or a zero-arity function, got: #{inspect(other)}"}

    @doc since: "0.9.0"
    @doc """
    Serves the directory for `GET` requests on the configured path.
    """
    @impl Plug
    @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
    def call(%Plug.Conn{method: "GET", request_path: path} = conn, %{path: path} = options) do
      keys = resolve_keys(options.keys)
      body = keys |> HTTPSignature.directory() |> Jason.encode!()

      conn
      |> put_resp_content_type(@media_type)
      |> put_resp_header("cache-control", "max-age=#{options.ttl}")
      |> put_signatures(keys, options)
      |> send_resp(200, body)
      |> halt()
    end

    def call(%Plug.Conn{} = conn, _options), do: conn

    @spec resolve_keys([Key.t()] | (-> [Key.t()])) :: [Key.t()]
    defp resolve_keys(fun) when is_function(fun, 0), do: fun.()
    defp resolve_keys(keys), do: keys

    @spec put_signatures(Plug.Conn.t(), [Key.t()], options()) :: Plug.Conn.t()
    defp put_signatures(conn, _keys, %{sign: false}), do: conn

    defp put_signatures(conn, keys, %{ttl: ttl}) do
      request = %{
        method: conn.method,
        url: Plug.Conn.request_url(conn),
        headers: conn.req_headers
      }

      response = %{status: 200, headers: [], request: request}

      keys
      |> Enum.with_index(1)
      |> Enum.map(fn {key, index} ->
        {:ok, headers} =
          HTTPSignature.sign(response, key,
            label: "sig#{index}",
            components: [{"@authority", req: true}],
            ttl: ttl,
            alg: true,
            nonce: true,
            tag: @tag
          )

        headers
      end)
      |> HTTPSignature.merge_headers()
      |> Enum.reduce(conn, fn {name, value}, conn -> put_resp_header(conn, name, value) end)
    end
  end
end
