defmodule X402.Facilitator.Auth.CDP do
  @moduledoc """
  Authentication for the Coinbase Developer Platform (CDP) x402 facilitator.

  CDP's hosted facilitator (`facilitator_url/0`) requires an
  `Authorization: Bearer <JWT>` header on every request. The JWT is an EdDSA
  or ES256 signed token carrying the API key id and a `uris` claim binding it
  to the exact request.

  ## API keys

  Credentials are passed to `new/1` via the `:api_key_id` and
  `:api_key_secret` options. In applications that want a single source of
  truth at runtime, put them in application configuration and let the
  facilitator resolve them (see the `otp_app` option on
  `X402.Facilitator.start_link/1`):

      # config/runtime.exs
      config :my_app, MyX402,
        auth: {X402.Facilitator.Auth.CDP,
               api_key_id: System.fetch_env!("CDP_API_KEY_ID"),
               api_key_secret: System.fetch_env!("CDP_API_KEY_SECRET")}

  Two API key secret formats are supported, matching the CDP SDK:

    * **Ed25519** — base64 of the 64-byte private key (32-byte seed + 32-byte
      public key). This is the default for new API keys.
    * **EC (P-256)** — a PEM `EC PRIVATE KEY` (SEC1) or PKCS#8 private key.
      Used by legacy API keys.

  The secret format is detected automatically; no configuration is required.

  ## Usage

      X402.Facilitator.start_link(
        finch: MyFinch,
        url: X402.Facilitator.Auth.CDP.facilitator_url(),
        auth: {X402.Facilitator.Auth.CDP, api_key_id: "...", api_key_secret: "..."}
      )

  The JWT is generated per facilitator operation with a fresh nonce and
  timestamps. Transport retries reuse it within its 120-second validity
  window. The `aud` claim is intentionally omitted to match the reference CDP
  SDK's x402 facilitator client.
  """

  @behaviour X402.Facilitator.Auth

  alias X402.Facilitator.Auth

  @facilitator_url "https://api.cdp.coinbase.com/platform/v2/x402"
  @jwt_ttl_seconds 120
  @secp256r1_oid {1, 2, 840, 10_045, 3, 1, 7}

  @typedoc "API key secret format."
  @type key_format :: :ed25519 | :ecdsa_p256

  @typedoc "CDP auth state."
  @type t :: %__MODULE__{
          api_key_id: String.t(),
          key_format: key_format(),
          key_material: binary()
        }

  defstruct [:api_key_id, :key_format, :key_material]

  @doc """
  Returns the CDP x402 facilitator base URL.

  Note that this URL is never used as a default; a facilitator must be
  configured with an explicit `url:` option.
  """
  @doc since: "0.5.0"
  @spec facilitator_url() :: String.t()
  def facilitator_url, do: @facilitator_url

  @impl true
  @doc """
  Builds CDP auth state from `:api_key_id` and `:api_key_secret` options.

  Returns `{:error, reason}` when credentials are missing or the secret is not
  a valid Ed25519 or P-256 key. For config-driven credentials, see the
  `otp_app` option on `X402.Facilitator.start_link/1`.
  """
  @doc since: "0.5.0"
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) when is_list(opts) do
    api_key_id = Keyword.get(opts, :api_key_id)
    api_key_secret = Keyword.get(opts, :api_key_secret)

    with {:ok, api_key_id} <- require_credential(api_key_id, :api_key_id),
         {:ok, api_key_secret} <- require_credential(api_key_secret, :api_key_secret),
         {:ok, key_format, key_material} <- parse_secret(api_key_secret) do
      {:ok,
       %__MODULE__{
         api_key_id: api_key_id,
         key_format: key_format,
         key_material: key_material
       }}
    end
  end

  @impl true
  @doc """
  Builds the `Authorization` (and `Correlation-Context`) headers for a request.

  The JWT binds the request method, host, and path in its `uris` claim and is
  signed fresh for every call.
  """
  @doc since: "0.5.0"
  @spec headers(t(), Auth.request_info()) :: {:ok, [{String.t(), String.t()}]}
  def headers(%__MODULE__{} = auth, %{method: method, host: host, path: path}) do
    token = jwt(auth, method, host, path)

    {:ok,
     [
       {"authorization", "Bearer " <> token},
       {"correlation-context", correlation_context()}
     ]}
  end

  defp jwt(%__MODULE__{} = auth, method, host, path) do
    now = System.os_time(:second)

    header =
      %{
        alg: algorithm(auth.key_format),
        kid: auth.api_key_id,
        typ: "JWT",
        nonce: nonce()
      }

    claims =
      %{
        sub: auth.api_key_id,
        iss: "cdp",
        uris: ["#{method_string(method)} #{host}#{path}"],
        iat: now,
        nbf: now,
        exp: now + @jwt_ttl_seconds
      }

    signing_input = encode_part(header) <> "." <> encode_part(claims)
    signature = sign(auth, signing_input)
    signing_input <> "." <> Base.url_encode64(signature, padding: false)
  end

  defp encode_part(map) do
    map
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp sign(%__MODULE__{key_format: :ed25519, key_material: seed}, signing_input) do
    :crypto.sign(:eddsa, :none, signing_input, [seed, :ed25519])
  end

  defp sign(%__MODULE__{key_format: :ecdsa_p256, key_material: d}, signing_input) do
    der = :crypto.sign(:ecdsa, :sha256, signing_input, [d, :secp256r1])
    der_to_raw32(der)
  end

  # JWT ES256 signatures are the raw r || s pair, each exactly 32 bytes. The
  # DER form produced by :crypto may carry a leading zero byte on either
  # component; that must be stripped and the value left-padded to 32 bytes.
  defp der_to_raw32(
         <<48, _length, 2, r_len, r::binary-size(r_len), 2, s_len, s::binary-size(s_len)>>
       ) do
    to_raw32(r) <> to_raw32(s)
  end

  defp to_raw32(<<0, rest::binary>>) when byte_size(rest) <= 32, do: to_raw32(rest)

  defp to_raw32(bin) when byte_size(bin) < 32,
    do: <<0::size((32 - byte_size(bin)) * 8)>> <> bin

  defp to_raw32(bin) when byte_size(bin) == 32, do: bin

  defp algorithm(:ed25519), do: "EdDSA"
  defp algorithm(:ecdsa_p256), do: "ES256"

  defp method_string(:post), do: "POST"
  defp method_string(:get), do: "GET"

  defp nonce do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp correlation_context do
    version =
      case Application.spec(:x402, :vsn) do
        vsn when is_binary(vsn) -> vsn
        _ -> "unknown"
      end

    "sdkLanguage=elixir,source=x402,sourceVersion=#{version}"
  end

  defp require_credential(value, _key) when is_binary(value) and value != "", do: {:ok, value}
  defp require_credential(_value, key), do: {:error, {:missing_credential, key}}

  defp parse_secret("-----BEGIN" <> _rest = secret), do: parse_ec_pem(secret)

  defp parse_secret(secret) when is_binary(secret) do
    case secret |> String.replace(~r/\s/, "") |> Base.decode64() do
      {:ok, <<seed::binary-size(32), _public_key::binary-size(32)>>} ->
        {:ok, :ed25519, seed}

      {:ok, _decoded} ->
        {:error, :invalid_ed25519_secret}

      :error ->
        {:error, :invalid_secret_format}
    end
  end

  defp parse_ec_pem(pem) do
    with [entry] <- :public_key.pem_decode(pem),
         {:ECPrivateKey, _version, d, {:namedCurve, @secp256r1_oid}, _public_key, _novalue} <-
           :public_key.pem_entry_decode(entry),
         {:ok, scalar} <- normalize_scalar(d) do
      {:ok, :ecdsa_p256, scalar}
    else
      _other -> {:error, :invalid_ec_private_key}
    end
  rescue
    _error -> {:error, :invalid_ec_private_key}
  end

  defp normalize_scalar(d) when is_binary(d) do
    case trim_leading_zeros(d) do
      nil -> {:error, :invalid_ec_private_key}
      trimmed when byte_size(trimmed) <= 32 -> {:ok, pad_left(trimmed, 32)}
      _too_large -> {:error, :invalid_ec_private_key}
    end
  end

  defp normalize_scalar(d) when is_integer(d) and d >= 0,
    do: normalize_scalar(:binary.encode_unsigned(d))

  defp normalize_scalar(_d), do: {:error, :invalid_ec_private_key}

  defp trim_leading_zeros(<<0, rest::binary>>), do: trim_leading_zeros(rest)
  defp trim_leading_zeros(""), do: nil
  defp trim_leading_zeros(bin), do: bin

  defp pad_left(bin, width) when byte_size(bin) < width,
    do: <<0::size((width - byte_size(bin)) * 8)>> <> bin

  defp pad_left(bin, _width), do: bin
end
