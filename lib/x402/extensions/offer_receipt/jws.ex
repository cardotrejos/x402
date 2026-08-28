defmodule X402.Extensions.OfferReceipt.JWS do
  @moduledoc """
  Compact JWS signing and verification for the offer-receipt extension.

  Implements the JWS Compact Serialization (`header.payload.signature`,
  RFC 7515) used by the x402 offer-and-receipt extension with the two
  algorithms the extension names (§3.3):

    * `"ES256K"` — ECDSA over secp256k1 with SHA-256 (RFC 8812), with the
      64-byte `R || S` JOSE signature encoding
    * `"EdDSA"` — Ed25519 (RFC 8037)

  Both are implemented with OTP's `:crypto` application — no additional
  dependencies. Payloads are canonicalized with the JSON Canonicalization
  Scheme (JCS, RFC 8785) before signing, as required by the extension's
  security considerations (§10).

  ## Keys

  Keys are raw binaries, not JWKs:

    * `"ES256K"` — a 32-byte secp256k1 private key; the public key is a
      SEC1 point (65-byte uncompressed, 33-byte compressed, or the bare
      64-byte X || Y coordinates)
    * `"EdDSA"` — a 32-byte Ed25519 seed; the public key is the 32-byte
      Ed25519 public key

  ## Boundaries

    * Key discovery is out of scope: the `kid` header (a DID URL per the
      extension spec) is carried and returned verbatim, but this module never
      resolves it — callers supply the public key for verification and are
      responsible for checking the key is authorized for the resource
      (spec §4.5.1).
    * `canonicalize/1` supports the JSON values that appear in offer and
      receipt payloads (objects, arrays, strings, integers, booleans, null).
      Floats are rejected with `{:error, {:unsupported_json_value, value}}`
      rather than risking a non-canonical number serialization.
    * ECDSA over secp256k1 requires OTP's `:crypto` to be linked against an
      OpenSSL with secp256k1 support (the common case); otherwise `"ES256K"`
      operations return `{:error, {:unsupported_algorithm, "ES256K"}}`.
  """

  @algorithms ["ES256K", "EdDSA"]

  # secp256k1 group order, for low-S normalization of ES256K signatures.
  @secp256k1_n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @sign_opts_schema [
    alg: [
      type: {:in, @algorithms},
      required: true,
      doc: "JWS algorithm: `ES256K` or `EdDSA`."
    ],
    kid: [
      type: :string,
      required: true,
      doc: "Key identifier placed in the protected header (a DID URL)."
    ],
    key: [
      type: :string,
      required: true,
      doc: """
      Raw private key: a 32-byte secp256k1 private key for `"ES256K"`, a
      32-byte Ed25519 seed for `"EdDSA"`.
      """
    ]
  ]

  @verify_opts_schema [
    algs: [
      type: {:list, {:in, @algorithms}},
      default: @algorithms,
      doc: "Algorithms accepted during verification (allowlist)."
    ]
  ]

  @typedoc "A JWS Compact Serialization string (`header.payload.signature`)."
  @type compact :: String.t()

  @typedoc "A decoded protected header with at least `alg` and `kid`."
  @type header :: %{optional(String.t()) => term()}

  @type sign_error ::
          {:unsupported_algorithm, String.t()}
          | {:invalid_key, String.t()}
          | {:unsupported_json_value, term()}

  @type verify_error ::
          :invalid_jws
          | :signature_mismatch
          | {:unsupported_algorithm, term()}
          | {:invalid_key, String.t()}
          | {:missing_header, String.t()}

  @doc since: "0.6.0"
  @doc """
  Signs a JSON payload into a JWS Compact Serialization string.

  The protected header is `{"alg": alg, "kid": kid}`; the payload is
  JCS-canonicalized before base64url encoding, so signing the same payload
  twice produces the same JWS (for a deterministic algorithm like EdDSA).

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}

  ## Examples

      {:ok, jws} =
        X402.Extensions.OfferReceipt.JWS.sign(
          %{"version" => 1, "resourceUrl" => "https://api.example.com/data"},
          alg: "EdDSA",
          kid: "did:web:api.example.com#key-1",
          key: ed25519_seed
        )
  """
  @spec sign(map(), keyword()) :: {:ok, compact()} | {:error, sign_error()}
  def sign(payload, opts) when is_map(payload) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)
    alg = Keyword.fetch!(opts, :alg)

    with {:ok, header_json} <- canonicalize(%{"alg" => alg, "kid" => Keyword.fetch!(opts, :kid)}),
         {:ok, payload_json} <- canonicalize(payload) do
      signing_input = base64url(header_json) <> "." <> base64url(payload_json)

      with {:ok, signature} <- sign_bytes(alg, signing_input, Keyword.fetch!(opts, :key)) do
        {:ok, signing_input <> "." <> base64url(signature)}
      end
    end
  end

  @doc since: "0.6.0"
  @doc """
  Verifies a JWS Compact Serialization string against a public key.

  Returns the decoded header and payload on success. The header must carry
  `"alg"` (one of the allowed `:algs`) and `"kid"` (required by the
  extension, §3.3). Key authorization for the signed resource is the
  caller's responsibility (spec §4.5.1).

  ## Options

  #{NimbleOptions.docs(@verify_opts_schema)}
  """
  @spec verify(compact(), binary(), keyword()) ::
          {:ok, %{header: header(), payload: term()}} | {:error, verify_error()}
  def verify(compact, public_key, opts \\ [])
      when is_binary(compact) and is_binary(public_key) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @verify_opts_schema)

    with {:ok, header_b64, payload_b64, signature_b64} <- split(compact),
         {:ok, header} <- decode_json_segment(header_b64),
         {:ok, alg} <- fetch_alg(header, Keyword.fetch!(opts, :algs)),
         :ok <- ensure_kid(header),
         {:ok, signature} <- decode_base64url(signature_b64),
         :ok <- verify_bytes(alg, header_b64 <> "." <> payload_b64, signature, public_key),
         {:ok, payload} <- decode_json_segment(payload_b64) do
      {:ok, %{header: header, payload: payload}}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Decodes the protected header of a JWS without verifying the signature.

  Useful for extracting the `kid` in order to resolve the verification key.

  ## Examples

      iex> X402.Extensions.OfferReceipt.JWS.peek_header(
      ...>   "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6d2ViOmFwaS5leGFtcGxlLmNvbSNrZXktMSJ9.e30.c2ln"
      ...> )
      {:ok, %{"alg" => "ES256K", "kid" => "did:web:api.example.com#key-1"}}

      iex> X402.Extensions.OfferReceipt.JWS.peek_header("not a jws")
      {:error, :invalid_jws}
  """
  @spec peek_header(compact()) :: {:ok, header()} | {:error, :invalid_jws}
  def peek_header(compact) when is_binary(compact) do
    with {:ok, header_b64, _payload_b64, _signature_b64} <- split(compact) do
      decode_json_segment(header_b64)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Decodes the payload of a JWS **without verifying the signature**.

  Only use the result for display or matching; verified reads must go
  through `verify/3`.

  ## Examples

      iex> X402.Extensions.OfferReceipt.JWS.peek_payload("eyJhbGciOiJFUzI1NksiLCJraWQiOiJrIn0.eyJ2ZXJzaW9uIjoxfQ.c2ln")
      {:ok, %{"version" => 1}}
  """
  @spec peek_payload(compact()) :: {:ok, term()} | {:error, :invalid_jws}
  def peek_payload(compact) when is_binary(compact) do
    with {:ok, _header_b64, payload_b64, _signature_b64} <- split(compact) do
      decode_json_segment(payload_b64)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Serializes a JSON-representable term with the JSON Canonicalization Scheme.

  Implements RFC 8785 for the value domain used by offer and receipt
  payloads: object keys are sorted by UTF-16 code units, no insignificant
  whitespace is emitted, and strings use ECMAScript's minimal escaping.
  Atom keys and values are serialized as their string form (as `Jason`
  does); floats are rejected as unsupported.

  ## Examples

      iex> X402.Extensions.OfferReceipt.JWS.canonicalize(%{"b" => 1, "a" => [true, nil, "x"]})
      {:ok, ~s({"a":[true,null,"x"],"b":1})}

      iex> X402.Extensions.OfferReceipt.JWS.canonicalize(%{"bad" => 1.5})
      {:error, {:unsupported_json_value, 1.5}}
  """
  @spec canonicalize(term()) :: {:ok, String.t()} | {:error, {:unsupported_json_value, term()}}
  def canonicalize(value) do
    {:ok, serialize(value)}
  catch
    {:unsupported_json_value, unsupported} ->
      {:error, {:unsupported_json_value, unsupported}}
  end

  # -- Signing primitives -----------------------------------------------------

  @spec sign_bytes(String.t(), binary(), binary()) :: {:ok, binary()} | {:error, sign_error()}
  defp sign_bytes("EdDSA", message, key) do
    case byte_size(key) do
      32 -> {:ok, :crypto.sign(:eddsa, :none, message, [key, :ed25519])}
      _size -> {:error, {:invalid_key, "expected a 32-byte Ed25519 seed"}}
    end
  end

  defp sign_bytes("ES256K", message, key) do
    with :ok <- ensure_secp256k1(),
         :ok <- ensure_key_size(key, 32, "expected a 32-byte secp256k1 private key") do
      der = :crypto.sign(:ecdsa, :sha256, message, [key, :secp256k1])

      with {:ok, {r, s}} <- der_to_integers(der) do
        {:ok, integers_to_raw(r, normalize_s(s))}
      end
    end
  end

  @spec verify_bytes(String.t(), binary(), binary(), binary()) ::
          :ok | {:error, verify_error()}
  defp verify_bytes("EdDSA", message, signature, public_key) do
    with :ok <- ensure_key_size(public_key, 32, "expected a 32-byte Ed25519 public key") do
      case byte_size(signature) == 64 and
             :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519]) do
        true -> :ok
        false -> {:error, :signature_mismatch}
      end
    end
  end

  defp verify_bytes("ES256K", message, signature, public_key) do
    with :ok <- ensure_secp256k1(),
         {:ok, point} <- sec1_point(public_key),
         {:ok, der} <- raw_to_der(signature) do
      case :crypto.verify(:ecdsa, :sha256, message, der, [point, :secp256k1]) do
        true -> :ok
        false -> {:error, :signature_mismatch}
      end
    end
  end

  @spec ensure_secp256k1() :: :ok | {:error, {:unsupported_algorithm, String.t()}}
  defp ensure_secp256k1 do
    case :secp256k1 in :crypto.supports(:curves) do
      true -> :ok
      false -> {:error, {:unsupported_algorithm, "ES256K"}}
    end
  end

  @spec ensure_key_size(binary(), pos_integer(), String.t()) ::
          :ok | {:error, {:invalid_key, String.t()}}
  defp ensure_key_size(key, size, message) do
    case byte_size(key) == size do
      true -> :ok
      false -> {:error, {:invalid_key, message}}
    end
  end

  @spec sec1_point(binary()) :: {:ok, binary()} | {:error, {:invalid_key, String.t()}}
  defp sec1_point(<<4, _coordinates::binary-size(64)>> = point), do: {:ok, point}
  defp sec1_point(<<prefix, _x::binary-size(32)>> = point) when prefix in [2, 3], do: {:ok, point}
  defp sec1_point(<<coordinates::binary-size(64)>>), do: {:ok, <<4>> <> coordinates}

  defp sec1_point(_key),
    do: {:error, {:invalid_key, "expected a SEC1 secp256k1 point (33, 64, or 65 bytes)"}}

  # ECDSA signatures leave :crypto DER-encoded; JOSE uses the raw 64-byte
  # R || S concatenation. The DER form is small enough that lengths always
  # use the short form.

  @spec der_to_integers(binary()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}} | {:error, :signature_mismatch}
  defp der_to_integers(<<0x30, _length, 0x02, r_length, rest::binary>>) do
    case rest do
      <<r::binary-size(^r_length), 0x02, s_length, s::binary-size(s_length)>> ->
        {:ok, {:binary.decode_unsigned(r), :binary.decode_unsigned(s)}}

      _other ->
        {:error, :signature_mismatch}
    end
  end

  defp der_to_integers(_der), do: {:error, :signature_mismatch}

  @spec integers_to_raw(non_neg_integer(), non_neg_integer()) :: <<_::512>>
  defp integers_to_raw(r, s),
    do: <<r::unsigned-big-integer-size(256), s::unsigned-big-integer-size(256)>>

  @spec raw_to_der(binary()) :: {:ok, binary()} | {:error, :signature_mismatch}
  defp raw_to_der(<<r::unsigned-big-integer-size(256), s::unsigned-big-integer-size(256)>>) do
    r_der = der_integer(r)
    s_der = der_integer(s)
    body = <<0x02, byte_size(r_der)>> <> r_der <> <<0x02, byte_size(s_der)>> <> s_der
    {:ok, <<0x30, byte_size(body)>> <> body}
  end

  defp raw_to_der(_signature), do: {:error, :signature_mismatch}

  @spec der_integer(non_neg_integer()) :: binary()
  defp der_integer(integer) do
    bytes = :binary.encode_unsigned(integer)

    case bytes do
      <<high, _rest::binary>> when high >= 0x80 -> <<0>> <> bytes
      _bytes -> bytes
    end
  end

  # Normalizes ECDSA `s` to the lower half of the group order. RFC 8812 does
  # not require it, but the wider secp256k1 ecosystem rejects high-S
  # signatures, and emitting the canonical form keeps signatures stable.
  @spec normalize_s(non_neg_integer()) :: non_neg_integer()
  defp normalize_s(s) when s > div(@secp256k1_n, 2), do: @secp256k1_n - s
  defp normalize_s(s), do: s

  # -- Compact serialization helpers ------------------------------------------

  @spec split(binary()) :: {:ok, binary(), binary(), binary()} | {:error, :invalid_jws}
  defp split(compact) do
    case String.split(compact, ".") do
      [header, payload, signature] -> {:ok, header, payload, signature}
      _parts -> {:error, :invalid_jws}
    end
  end

  @spec decode_json_segment(binary()) :: {:ok, term()} | {:error, :invalid_jws}
  defp decode_json_segment(segment) do
    with {:ok, json} <- decode_base64url(segment),
         {:ok, decoded} <- Jason.decode(json) do
      {:ok, decoded}
    else
      _error -> {:error, :invalid_jws}
    end
  end

  @spec decode_base64url(binary()) :: {:ok, binary()} | {:error, :invalid_jws}
  defp decode_base64url(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_jws}
    end
  end

  @spec base64url(binary()) :: binary()
  defp base64url(bytes), do: Base.url_encode64(bytes, padding: false)

  @spec fetch_alg(map(), [String.t()]) ::
          {:ok, String.t()}
          | {:error, {:unsupported_algorithm, term()} | {:missing_header, String.t()}}
  defp fetch_alg(header, allowed) when is_map(header) do
    case Map.fetch(header, "alg") do
      {:ok, alg} when is_binary(alg) ->
        if alg in allowed, do: {:ok, alg}, else: {:error, {:unsupported_algorithm, alg}}

      {:ok, alg} ->
        {:error, {:unsupported_algorithm, alg}}

      :error ->
        {:error, {:missing_header, "alg"}}
    end
  end

  defp fetch_alg(_header, _allowed), do: {:error, {:missing_header, "alg"}}

  @spec ensure_kid(map()) :: :ok | {:error, {:missing_header, String.t()}}
  defp ensure_kid(header) do
    case Map.get(header, "kid") do
      kid when is_binary(kid) and kid != "" -> :ok
      _missing -> {:error, {:missing_header, "kid"}}
    end
  end

  # -- JCS (RFC 8785) ---------------------------------------------------------

  @spec serialize(term()) :: binary()
  defp serialize(nil), do: "null"
  defp serialize(true), do: "true"
  defp serialize(false), do: "false"
  defp serialize(value) when is_integer(value), do: Integer.to_string(value)
  defp serialize(value) when is_binary(value), do: serialize_string(value)
  defp serialize(value) when is_atom(value), do: serialize_string(Atom.to_string(value))

  defp serialize(value) when is_list(value),
    do: "[" <> Enum.map_join(value, ",", &serialize/1) <> "]"

  defp serialize(value) when is_map(value) and not is_struct(value) do
    pairs =
      value
      |> Enum.map(fn {key, entry} -> {serialize_key(key), entry} end)
      |> Enum.sort_by(fn {key, _entry} -> utf16_units(key) end)
      |> Enum.map_join(",", fn {key, entry} ->
        serialize_string(key) <> ":" <> serialize(entry)
      end)

    "{" <> pairs <> "}"
  end

  defp serialize(value), do: throw({:unsupported_json_value, value})

  @spec serialize_key(term()) :: binary()
  defp serialize_key(key) when is_binary(key), do: key
  defp serialize_key(key) when is_atom(key) and not is_nil(key), do: Atom.to_string(key)
  defp serialize_key(key), do: throw({:unsupported_json_value, key})

  # RFC 8785 sorts object keys by their UTF-16 code units.
  @spec utf16_units(binary()) :: binary()
  defp utf16_units(key) do
    case :unicode.characters_to_binary(key, :utf8, {:utf16, :big}) do
      encoded when is_binary(encoded) -> encoded
      _error -> throw({:unsupported_json_value, key})
    end
  end

  @spec serialize_string(binary()) :: binary()
  defp serialize_string(value) do
    escaped =
      value
      |> String.to_charlist()
      |> Enum.map_join("", &escape_char/1)

    "\"" <> escaped <> "\""
  end

  @spec escape_char(char()) :: binary()
  defp escape_char(?"), do: "\\\""
  defp escape_char(?\\), do: "\\\\"
  defp escape_char(?\b), do: "\\b"
  defp escape_char(?\t), do: "\\t"
  defp escape_char(?\n), do: "\\n"
  defp escape_char(?\f), do: "\\f"
  defp escape_char(?\r), do: "\\r"

  defp escape_char(char) when char < 0x20 do
    hex = char |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
    "\\u" <> hex
  end

  defp escape_char(char), do: <<char::utf8>>
end
