defmodule X402.HTTPSignature.Key do
  @moduledoc """
  Key material for RFC 9421 HTTP Message Signatures.

  A key pairs an algorithm from the HTTP Signature Algorithms registry
  with its public material and, for signing, its private material:

  | `alg`                 | Public material                 | Private material     |
  | --------------------- | ------------------------------- | -------------------- |
  | `"ed25519"`           | 32-byte public key              | 32-byte seed         |
  | `"ecdsa-p256-sha256"` | 65-byte uncompressed point      | 32-byte scalar       |
  | `"rsa-pss-sha512"`    | `[e, n]` big-endian binaries    | `[e, n, d]` binaries |

  `new/1` accepts the material as raw bytes, PEM (`PUBLIC KEY`,
  `PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE KEY`), a JWK map, or the
  `:public_key` records those PEMs decode to; `from_jwk/1` and `to_jwk/1`
  convert to and from the JWK form the
  `/.well-known/http-message-signatures-directory` document uses. The key
  identifier defaults to the RFC 7638 JWK thumbprint (`thumbprint/1`), as
  draft-meunier-http-message-signatures-directory requires.

  ECDSA signatures use the raw `r || s` form RFC 9421 §3.3.4 mandates,
  and RSA-PSS uses SHA-512 with a 64-byte salt (§3.3.1).
  """

  @typedoc "An HTTP Signature Algorithms registry name supported here."
  @type alg :: String.t()

  @type t :: %__MODULE__{
          alg: alg(),
          kid: String.t() | nil,
          public: term(),
          private: term() | nil
        }

  @type error :: :invalid_key | {:unsupported_algorithm, term()} | :missing_private_key

  @enforce_keys [:alg, :public]
  defstruct [:alg, :kid, :public, private: nil]

  @ed25519 "ed25519"
  @ecdsa_p256 "ecdsa-p256-sha256"
  @rsa_pss "rsa-pss-sha512"
  @algorithms [@ed25519, @ecdsa_p256, @rsa_pss]

  @ed25519_oid {1, 3, 101, 112}
  @p256_oid {1, 2, 840, 10_045, 3, 1, 7}
  @rsa_pss_opts [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 64, rsa_mgf1_md: :sha512]

  @new_opts_schema [
    alg: [type: {:in, @algorithms}, required: true, doc: "The signature algorithm."],
    kid: [type: :string, doc: "Key identifier; defaults to the JWK thumbprint."],
    public_key: [type: :any, doc: "Public material (raw, PEM, JWK, or `:public_key` record)."],
    private_key: [type: :any, doc: "Private material (raw, PEM, JWK, or `:public_key` record)."]
  ]

  @doc since: "0.9.0"
  @doc """
  Returns the supported algorithm names.

  ## Examples

      iex> X402.HTTPSignature.Key.algorithms()
      ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"]
  """
  @spec algorithms() :: [alg()]
  def algorithms, do: @algorithms

  @doc since: "0.9.0"
  @doc """
  Builds a key from its algorithm and material.

  At least one of `:public_key` and `:private_key` is required; the
  public material is derived from the private one when omitted.

  ## Options

  #{NimbleOptions.docs(@new_opts_schema)}

  ## Examples

      iex> seed = :binary.copy(<<7>>, 32)
      iex> {:ok, key} = X402.HTTPSignature.Key.new(alg: "ed25519", private_key: seed, kid: "k1")
      iex> {key.alg, key.kid, byte_size(key.public), key.private == seed}
      {"ed25519", "k1", 32, true}

      iex> X402.HTTPSignature.Key.new(alg: "ed25519", public_key: "too short")
      {:error, :invalid_key}

      iex> X402.HTTPSignature.Key.new(alg: "hmac-sha256", public_key: "x")
      {:error, {:unsupported_algorithm, "hmac-sha256"}}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, error()}
  def new(opts) when is_list(opts) do
    opts = Enum.reject(opts, fn {_name, value} -> is_nil(value) end)

    with {:ok, opts} <- validate_new_opts(opts),
         alg = Keyword.fetch!(opts, :alg),
         {:ok, private} <- normalize_private(alg, Keyword.get(opts, :private_key)),
         {:ok, public} <- resolve_public(alg, Keyword.get(opts, :public_key), private) do
      key = %__MODULE__{alg: alg, public: public, private: private}
      {:ok, %{key | kid: Keyword.get(opts, :kid) || thumbprint(key)}}
    end
  end

  @spec validate_new_opts(keyword()) :: {:ok, keyword()} | {:error, error()}
  defp validate_new_opts(opts) do
    case NimbleOptions.validate(opts, @new_opts_schema) do
      {:ok, validated} ->
        {:ok, validated}

      {:error, %NimbleOptions.ValidationError{key: :alg}} ->
        {:error, {:unsupported_algorithm, Keyword.get(opts, :alg)}}

      {:error, _error} ->
        {:error, :invalid_key}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Generates a fresh key pair for an algorithm.

  ## Examples

      iex> {:ok, key} = X402.HTTPSignature.Key.generate("ecdsa-p256-sha256")
      iex> {byte_size(key.public), byte_size(key.private), String.length(key.kid)}
      {65, 32, 43}

      iex> X402.HTTPSignature.Key.generate("hmac-sha256")
      {:error, {:unsupported_algorithm, "hmac-sha256"}}
  """
  @spec generate(alg()) :: {:ok, t()} | {:error, error()}
  def generate(@ed25519) do
    {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    new(alg: @ed25519, private_key: seed)
  end

  def generate(@ecdsa_p256) do
    {_public, scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    new(alg: @ecdsa_p256, private_key: pad(scalar, 32))
  end

  def generate(@rsa_pss) do
    new(alg: @rsa_pss, private_key: :public_key.generate_key({:rsa, 2048, 65_537}))
  end

  def generate(alg), do: {:error, {:unsupported_algorithm, alg}}

  @doc since: "0.9.0"
  @doc """
  Builds a key from a JWK map (RFC 7517), including the private part when
  `d` is present.

  The `alg` member may name the HTTP signature algorithm; when absent it
  is inferred from `kty`/`crv`. Any `kid` is kept.

  ## Examples

      iex> jwk = %{"kty" => "OKP", "crv" => "Ed25519", "kid" => "test-key-ed25519",
      ...>   "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
      iex> {:ok, key} = X402.HTTPSignature.Key.from_jwk(jwk)
      iex> {key.alg, key.kid, key.private}
      {"ed25519", "test-key-ed25519", nil}

      iex> X402.HTTPSignature.Key.from_jwk(%{"kty" => "oct", "k" => "secret"})
      {:error, {:unsupported_algorithm, "oct"}}
  """
  @spec from_jwk(map()) :: {:ok, t()} | {:error, error()}
  def from_jwk(%{"kty" => "OKP", "crv" => "Ed25519", "x" => x} = jwk) do
    with {:ok, public} <- url_decode(x),
         {:ok, private} <- optional_url_decode(jwk["d"]) do
      new(alg: @ed25519, kid: jwk["kid"], public_key: public, private_key: private)
    end
  end

  def from_jwk(%{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y} = jwk) do
    with {:ok, x} <- url_decode(x),
         {:ok, y} <- url_decode(y),
         {:ok, private} <- optional_url_decode(jwk["d"]) do
      new(alg: @ecdsa_p256, kid: jwk["kid"], public_key: <<4>> <> x <> y, private_key: private)
    end
  end

  def from_jwk(%{"kty" => "RSA", "n" => n, "e" => e} = jwk) do
    with {:ok, n} <- url_decode(n),
         {:ok, e} <- url_decode(e),
         {:ok, d} <- optional_url_decode(jwk["d"]) do
      private = if d, do: [e, n, d]
      new(alg: @rsa_pss, kid: jwk["kid"], public_key: [e, n], private_key: private)
    end
  end

  def from_jwk(%{"kty" => kty}), do: {:error, {:unsupported_algorithm, kty}}
  def from_jwk(_jwk), do: {:error, :invalid_key}

  @doc since: "0.9.0"
  @doc """
  Returns the public JWK for a key, with `kid` and the HTTP signature
  `alg` name as draft-meunier-http-message-signatures-directory §3 requires.

  ## Examples

      iex> jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
      iex> {:ok, key} = X402.HTTPSignature.Key.from_jwk(jwk)
      iex> X402.HTTPSignature.Key.to_jwk(key)
      %{
        "kty" => "OKP",
        "crv" => "Ed25519",
        "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
        "kid" => "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
        "alg" => "ed25519",
        "use" => "sig"
      }
  """
  @spec to_jwk(t()) :: map()
  def to_jwk(%__MODULE__{} = key) do
    key
    |> public_jwk_members()
    |> Map.merge(%{"alg" => key.alg, "use" => "sig"})
    |> put_kid(key.kid)
  end

  @spec put_kid(map(), String.t() | nil) :: map()
  defp put_kid(jwk, nil), do: jwk
  defp put_kid(jwk, kid), do: Map.put(jwk, "kid", kid)

  @doc since: "0.9.0"
  @doc """
  Computes the RFC 7638 JWK thumbprint (SHA-256, Base64url) of a key.

  ## Examples

      iex> jwk = %{"kty" => "OKP", "crv" => "Ed25519", "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
      iex> {:ok, key} = X402.HTTPSignature.Key.from_jwk(jwk)
      iex> X402.HTTPSignature.Key.thumbprint(key)
      "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
  """
  @spec thumbprint(t()) :: String.t()
  def thumbprint(%__MODULE__{} = key) do
    # RFC 7638 §3: required members only, lexicographically ordered, no whitespace.
    json =
      key
      |> public_jwk_members()
      |> Enum.sort()
      |> Enum.map_join(",", fn {name, value} -> ~s("#{name}":"#{value}") end)

    Base.url_encode64(:crypto.hash(:sha256, "{" <> json <> "}"), padding: false)
  end

  @spec public_jwk_members(t()) :: map()
  defp public_jwk_members(%__MODULE__{alg: @ed25519, public: public}),
    do: %{"kty" => "OKP", "crv" => "Ed25519", "x" => url_encode(public)}

  defp public_jwk_members(%__MODULE__{
         alg: @ecdsa_p256,
         public: <<4, x::binary-32, y::binary-32>>
       }),
       do: %{"kty" => "EC", "crv" => "P-256", "x" => url_encode(x), "y" => url_encode(y)}

  defp public_jwk_members(%__MODULE__{alg: @rsa_pss, public: [e, n]}),
    do: %{"kty" => "RSA", "n" => url_encode(n), "e" => url_encode(e)}

  @doc since: "0.9.0"
  @doc """
  Signs `data` with the key's private material, returning the raw
  signature bytes RFC 9421 §3.3 defines for the algorithm.

  ## Examples

      iex> {:ok, key} = X402.HTTPSignature.Key.generate("ed25519")
      iex> {:ok, signature} = X402.HTTPSignature.Key.sign(key, "data")
      iex> byte_size(signature)
      64

      iex> {:ok, key} = X402.HTTPSignature.Key.generate("ed25519")
      iex> X402.HTTPSignature.Key.sign(%{key | private: nil}, "data")
      {:error, :missing_private_key}
  """
  @spec sign(t(), binary()) :: {:ok, binary()} | {:error, :missing_private_key}
  def sign(%__MODULE__{private: nil}, _data), do: {:error, :missing_private_key}

  def sign(%__MODULE__{alg: @ed25519, private: seed}, data) when is_binary(data),
    do: {:ok, :crypto.sign(:eddsa, :none, data, [seed, :ed25519])}

  def sign(%__MODULE__{alg: @ecdsa_p256, private: scalar}, data) when is_binary(data) do
    der = :crypto.sign(:ecdsa, :sha256, data, [scalar, :secp256r1])
    {:ok, der_to_raw(der)}
  end

  def sign(%__MODULE__{alg: @rsa_pss, private: private}, data) when is_binary(data),
    do: {:ok, :crypto.sign(:rsa, :sha512, data, private, @rsa_pss_opts)}

  @doc since: "0.9.0"
  @doc """
  Verifies a raw signature over `data` with the key's public material.

  ## Examples

      iex> {:ok, key} = X402.HTTPSignature.Key.generate("ecdsa-p256-sha256")
      iex> {:ok, signature} = X402.HTTPSignature.Key.sign(key, "data")
      iex> X402.HTTPSignature.Key.verify(key, "data", signature)
      true
      iex> X402.HTTPSignature.Key.verify(key, "other", signature)
      false
      iex> X402.HTTPSignature.Key.verify(key, "data", "short")
      false
  """
  @spec verify(t(), binary(), binary()) :: boolean()
  def verify(%__MODULE__{alg: @ed25519, public: public}, data, <<signature::binary-64>>)
      when is_binary(data),
      do: :crypto.verify(:eddsa, :none, data, signature, [public, :ed25519])

  def verify(%__MODULE__{alg: @ecdsa_p256, public: public}, data, <<r::binary-32, s::binary-32>>)
      when is_binary(data),
      do: :crypto.verify(:ecdsa, :sha256, data, raw_to_der(r, s), [public, :secp256r1])

  def verify(%__MODULE__{alg: @rsa_pss, public: public}, data, signature)
      when is_binary(data) and is_binary(signature),
      do: :crypto.verify(:rsa, :sha512, data, signature, public, @rsa_pss_opts)

  def verify(%__MODULE__{}, _data, _signature), do: false

  # -- Private material -------------------------------------------------------

  @spec normalize_private(alg(), term()) :: {:ok, term() | nil} | {:error, error()}
  defp normalize_private(_alg, nil), do: {:ok, nil}

  defp normalize_private(alg, "-----BEGIN" <> _ = pem) do
    with {:ok, entry} <- decode_pem(pem), do: normalize_private(alg, entry)
  end

  defp normalize_private(alg, %{"kty" => _} = jwk) do
    case from_jwk(jwk) do
      {:ok, %__MODULE__{alg: ^alg, private: private}} when not is_nil(private) -> {:ok, private}
      _other -> {:error, :invalid_key}
    end
  end

  defp normalize_private(@ed25519, <<seed::binary-32>>), do: {:ok, seed}
  defp normalize_private(@ed25519, <<seed::binary-32, _public::binary-32>>), do: {:ok, seed}

  defp normalize_private(
         @ed25519,
         {:ECPrivateKey, _v, seed, {:namedCurve, @ed25519_oid}, _pub, _}
       ),
       do: normalize_private(@ed25519, seed)

  defp normalize_private(@ecdsa_p256, <<scalar::binary-32>>), do: {:ok, scalar}

  defp normalize_private(
         @ecdsa_p256,
         {:ECPrivateKey, _v, scalar, {:namedCurve, @p256_oid}, _pub, _}
       )
       when byte_size(scalar) <= 32,
       do: {:ok, pad(scalar, 32)}

  defp normalize_private(@rsa_pss, [e, n, d]) when is_binary(e) and is_binary(n) and is_binary(d),
    do: {:ok, [e, n, d]}

  defp normalize_private(@rsa_pss, [e, n, d])
       when is_integer(e) and is_integer(n) and is_integer(d),
       do: {:ok, Enum.map([e, n, d], &:binary.encode_unsigned/1)}

  defp normalize_private(@rsa_pss, rsa_private_key)
       when is_tuple(rsa_private_key) and elem(rsa_private_key, 0) == :RSAPrivateKey do
    {:RSAPrivateKey, _v, n, e, d, _p, _q, _dp, _dq, _qi, _other} = rsa_private_key
    normalize_private(@rsa_pss, [e, n, d])
  end

  defp normalize_private(_alg, _material), do: {:error, :invalid_key}

  # -- Public material --------------------------------------------------------

  @spec resolve_public(alg(), term(), term() | nil) :: {:ok, term()} | {:error, error()}
  defp resolve_public(_alg, nil, nil), do: {:error, :invalid_key}
  defp resolve_public(alg, nil, private), do: {:ok, derive_public(alg, private)}
  defp resolve_public(alg, material, _private), do: normalize_public(alg, material)

  @spec derive_public(alg(), term()) :: term()
  defp derive_public(@ed25519, seed), do: elem(:crypto.generate_key(:eddsa, :ed25519, seed), 0)

  defp derive_public(@ecdsa_p256, scalar),
    do: elem(:crypto.generate_key(:ecdh, :secp256r1, scalar), 0)

  defp derive_public(@rsa_pss, [e, n, _d]), do: [e, n]

  @spec normalize_public(alg(), term()) :: {:ok, term()} | {:error, error()}
  defp normalize_public(alg, "-----BEGIN" <> _ = pem) do
    with {:ok, entry} <- decode_pem(pem), do: normalize_public(alg, entry)
  end

  defp normalize_public(alg, %{"kty" => _} = jwk) do
    case from_jwk(jwk) do
      {:ok, %__MODULE__{alg: ^alg, public: public}} -> {:ok, public}
      _other -> {:error, :invalid_key}
    end
  end

  defp normalize_public(@ed25519, <<public::binary-32>>), do: {:ok, public}

  defp normalize_public(@ed25519, {{:ECPoint, public}, {:namedCurve, @ed25519_oid}}),
    do: normalize_public(@ed25519, public)

  defp normalize_public(@ecdsa_p256, <<4, _point::binary-64>> = public), do: {:ok, public}

  defp normalize_public(@ecdsa_p256, {{:ECPoint, public}, {:namedCurve, @p256_oid}}),
    do: normalize_public(@ecdsa_p256, public)

  defp normalize_public(@rsa_pss, [e, n]) when is_binary(e) and is_binary(n), do: {:ok, [e, n]}

  defp normalize_public(@rsa_pss, [e, n]) when is_integer(e) and is_integer(n),
    do: {:ok, Enum.map([e, n], &:binary.encode_unsigned/1)}

  defp normalize_public(@rsa_pss, {:RSAPublicKey, n, e}), do: normalize_public(@rsa_pss, [e, n])

  defp normalize_public(alg, private_entry) when is_tuple(private_entry) do
    # A private PEM also carries the public part: derive it instead of failing.
    case normalize_private(alg, private_entry) do
      {:ok, private} -> {:ok, derive_public(alg, private)}
      error -> error
    end
  end

  defp normalize_public(_alg, _material), do: {:error, :invalid_key}

  @spec decode_pem(binary()) :: {:ok, tuple()} | {:error, :invalid_key}
  defp decode_pem(pem) do
    case :public_key.pem_decode(pem) do
      [entry] -> {:ok, :public_key.pem_entry_decode(entry)}
      _other -> {:error, :invalid_key}
    end
  rescue
    _error -> {:error, :invalid_key}
  end

  # -- Encoding helpers -------------------------------------------------------

  # RFC 9421 §3.3.4: r and s as 32-byte big-endian unsigned integers. DER
  # integers are signed, so a leading zero may be present and must be
  # stripped, and short values must be left-padded.
  @spec der_to_raw(binary()) :: binary()
  defp der_to_raw(<<48, _len, 2, r_len, r::binary-size(r_len), 2, s_len, s::binary-size(s_len)>>),
    do: to_fixed(r, 32) <> to_fixed(s, 32)

  @spec to_fixed(binary(), pos_integer()) :: binary()
  defp to_fixed(<<0, rest::binary>>, width) when byte_size(rest) >= width,
    do: to_fixed(rest, width)

  defp to_fixed(value, width), do: pad(value, width)

  @spec raw_to_der(binary(), binary()) :: binary()
  defp raw_to_der(r, s) do
    content = der_integer(r) <> der_integer(s)
    <<48, byte_size(content), content::binary>>
  end

  @spec der_integer(binary()) :: binary()
  defp der_integer(<<0, rest::binary>>) when rest != "", do: der_integer(rest)

  defp der_integer(<<first, _::binary>> = value) when first >= 0x80,
    do: <<2, byte_size(value) + 1, 0, value::binary>>

  defp der_integer(value), do: <<2, byte_size(value), value::binary>>

  @spec pad(binary(), pos_integer()) :: binary()
  defp pad(value, width) when byte_size(value) < width,
    do: <<0::size((width - byte_size(value)) * 8), value::binary>>

  defp pad(value, _width), do: value

  @spec url_encode(binary()) :: String.t()
  defp url_encode(bytes), do: Base.url_encode64(bytes, padding: false)

  @spec url_decode(term()) :: {:ok, binary()} | {:error, :invalid_key}
  defp url_decode(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_key}
    end
  end

  defp url_decode(_value), do: {:error, :invalid_key}

  @spec optional_url_decode(term()) :: {:ok, binary() | nil} | {:error, :invalid_key}
  defp optional_url_decode(nil), do: {:ok, nil}
  defp optional_url_decode(value), do: url_decode(value)
end
