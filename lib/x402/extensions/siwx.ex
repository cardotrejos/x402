defmodule X402.Extensions.SIWX do
  @moduledoc """
  The x402 `sign-in-with-x` extension: CAIP-122 wallet authentication.

  Implements the
  [sign-in-with-x extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/sign-in-with-x.md).
  A server advertises a challenge under `PaymentRequired.extensions`
  (`challenge/1`); a client proves control of a wallet by signing the
  CAIP-122 message the challenge describes (`sign/3`) and sends the proof
  Base64-encoded in the `SIGN-IN-WITH-X` header (`encode_signed/1`); the
  server decodes (`decode_signed/1`) and verifies it (`verify/2`), then
  decides — from its own payment history — whether the address may skip
  payment. `X402.Plug.PaymentGate` wires all of this up through its `:siwx`
  option.

      # server (PaymentRequired.extensions)
      %{"sign-in-with-x" => X402.Extensions.SIWX.challenge(
          domain: "api.example.com",
          uri: "https://api.example.com",
          supported_chains: [%{chain_id: "eip155:8453"}]
        )}

      # client
      {:ok, signed} = X402.Extensions.SIWX.sign(challenge, signer, chain_id: "eip155:8453")
      {:ok, header} = X402.Extensions.SIWX.encode_signed(signed)

      # server
      {:ok, decoded} = X402.Extensions.SIWX.decode_signed(header)
      {:ok, %{address: address}} =
        X402.Extensions.SIWX.verify(decoded,
          domain: "api.example.com",
          uri: "https://api.example.com",
          supported_chains: [%{chain_id: "eip155:8453"}]
        )

  Supported chains are `eip155:*` (EIP-4361 text, EIP-191 `personal_sign`,
  verified by `X402.Extensions.SIWX.Verifier.Default`) and `solana:*`
  (Sign-In With Solana text, Ed25519, verified by
  `X402.Extensions.SIWX.Verifier.Ed25519`). Message construction lives in
  `X402.Extensions.SIWX.Message`, challenge construction in
  `X402.Extensions.SIWX.Challenge`.

  ## Legacy formats (deprecated)

  Releases before 0.7.0 sent the `SIGN-IN-WITH-X` header as a Base64 JSON
  `{"message", "signature"}` object carrying the signed EIP-4361 text
  itself. `decode_signed/1` still understands that shape — reporting it as
  `{:legacy, proof}` — and `verify/2` applies the same rules to it.
  `encode_header/1` and `decode_header/1` produce and consume it directly,
  are deprecated, and will be removed in 1.0.0; `encode/1` and `decode/1`
  remain as the EIP-4361 text codec they always were. Servers emit a
  `[:x402, :siwx, :legacy]` telemetry event (and a one-time warning log)
  when they receive the legacy format.
  """

  alias X402.Extensions.SIWX.Challenge
  alias X402.Extensions.SIWX.Message
  alias X402.Extensions.SIWX.Verification
  alias X402.Signer
  alias X402.Utils
  alias X402.Wallet

  require Logger

  @extension_key "sign-in-with-x"
  @max_header_bytes X402.Header.max_header_bytes()
  @siwe_version "1"

  @required_message_fields [
    :domain,
    :address,
    :statement,
    :uri,
    :version,
    :chain_id,
    :nonce,
    :issued_at,
    :expiration_time
  ]

  @domain_suffix " wants you to sign in with your Ethereum account:"
  @nonce_regex ~r/^[A-Za-z0-9]{8,}$/

  @required_proof_fields [
    {"domain", :domain},
    {"address", :address},
    {"uri", :uri},
    {"version", :version},
    {"chainId", :chain_id},
    {"type", :type},
    {"nonce", :nonce},
    {"issuedAt", :issued_at}
  ]

  @optional_proof_fields [
    {"expirationTime", :expiration_time},
    {"notBefore", :not_before},
    {"requestId", :request_id},
    {"statement", :statement},
    {"signatureScheme", :signature_scheme}
  ]

  @copied_info_fields [
    {"domain", :domain},
    {"uri", :uri},
    {"version", :version},
    {"nonce", :nonce},
    {"issuedAt", :issued_at},
    {"expirationTime", :expiration_time},
    {"notBefore", :not_before},
    {"requestId", :request_id},
    {"statement", :statement}
  ]

  @sign_opts_schema [
    chain_id: [
      type: :string,
      required: true,
      doc: "CAIP-2 chain the proof is for; must be one the challenge supports."
    ],
    address: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Address to place in the proof; the signer's address when omitted."
    ],
    signature_scheme: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Optional `signatureScheme` hint copied into the proof."
    ]
  ]

  @typedoc "Spec-format proof fields, keyed by their wire (camelCase) names."
  @type fields :: %{optional(String.t()) => String.t() | [String.t()]}

  @typedoc "A decoded `SIGN-IN-WITH-X` header, tagged with its wire format."
  @type decoded :: {:spec, fields()} | {:legacy, %{String.t() => String.t()}}

  @typedoc "The wallet identity a verified proof establishes."
  @type identity :: %{address: String.t(), chain_id: String.t(), fields: fields()}

  @typedoc "Machine-readable verification failure codes from the spec."
  @type verify_code ::
          :invalid_siwx_domain_mismatch
          | :invalid_siwx_uri_mismatch
          | :invalid_siwx_issued_at
          | :invalid_siwx_issued_at_too_old
          | :invalid_siwx_issued_at_in_future
          | :invalid_siwx_expiration_time
          | :invalid_siwx_expired
          | :invalid_siwx_not_before
          | :invalid_siwx_not_yet_valid
          | :invalid_siwx_nonce
          | :invalid_siwx_signature
          | :invalid_siwx_chain_id
          | :invalid_siwx_unsupported_chain
          | :invalid_siwx_malformed_signature
          | :invalid_siwx_verifier_error

  @typedoc "Errors returned by `verify/2`."
  @type verify_error :: verify_code() | :invalid_payload | signed_decode_error()

  @typedoc "Errors returned by `sign/3`."
  @type sign_error ::
          :unsupported_chain | :invalid_chain_id | :invalid_payload | :invalid_signer | term()

  @typedoc "Errors returned by `encode_signed/1`."
  @type signed_encode_error :: :invalid_payload | :invalid_json

  @typedoc "Errors returned by `decode_signed/1`."
  @type signed_decode_error ::
          :invalid_base64 | :invalid_json | :invalid_payload | :payload_too_large

  @typedoc "Where a legacy-format proof was observed."
  @type legacy_source :: :gate

  @typedoc "Legacy EIP-4361 message payload fields."
  @type message_payload :: %{
          required(:domain) => String.t(),
          required(:address) => String.t(),
          required(:statement) => String.t(),
          required(:uri) => String.t(),
          required(:version) => String.t(),
          required(:chain_id) => String.t(),
          required(:nonce) => String.t(),
          required(:issued_at) => String.t(),
          required(:expiration_time) => String.t()
        }

  @type encode_error :: :invalid_payload | {:missing_fields, [atom()]} | {:invalid_field, atom()}
  @type decode_error :: :invalid_message | {:invalid_field, atom()}
  @type header_encode_error :: :invalid_payload | :invalid_json
  @type header_decode_error :: :invalid_base64 | :invalid_json | :invalid_payload

  # -- Spec format ------------------------------------------------------------

  @doc since: "0.9.0"
  @doc """
  Returns the extension key on the wire.

  ## Examples

      iex> X402.Extensions.SIWX.extension_key()
      "sign-in-with-x"
  """
  @spec extension_key() :: String.t()
  def extension_key, do: @extension_key

  @doc since: "0.3.0", group: :headers
  @doc """
  Returns the canonical SIWX header name.

  ## Examples

      iex> X402.Extensions.SIWX.header_name()
      "SIGN-IN-WITH-X"
  """
  @spec header_name() :: String.t()
  def header_name, do: "SIGN-IN-WITH-X"

  @doc since: "0.9.0"
  @doc """
  Returns the JSON schema of a proof, advertised under `schema`.

  ## Examples

      iex> X402.Extensions.SIWX.schema()["properties"]["issuedAt"]
      %{"type" => "string", "format" => "date-time"}
  """
  @spec schema() :: map()
  defdelegate schema(), to: Challenge

  @doc since: "0.9.0"
  @doc """
  Generates a challenge nonce: 32 lowercase hex characters from 16 random
  bytes.

  ## Examples

      iex> nonce = X402.Extensions.SIWX.generate_nonce()
      iex> String.length(nonce)
      32
  """
  @spec generate_nonce() :: String.t()
  defdelegate generate_nonce(), to: Challenge

  @doc since: "0.9.0"
  @doc """
  Builds the server-side challenge advertised under
  `PaymentRequired.extensions["sign-in-with-x"]`.

  Every call produces a fresh nonce (unless `:nonce` is given) and
  timestamps; advertise a new challenge on every 402 response. Raises
  `NimbleOptions.ValidationError` for invalid options (programmer error).

  ## Options

  #{NimbleOptions.docs(Challenge.opts_schema())}

  ## Examples

      iex> challenge = X402.Extensions.SIWX.challenge(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [[chain_id: "eip155:8453"], [chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]],
      ...>   statement: "Sign in to access premium data"
      ...> )
      iex> challenge["supportedChains"]
      [
        %{"chainId" => "eip155:8453", "type" => "eip191"},
        %{"chainId" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "type" => "ed25519"}
      ]
      iex> challenge["info"]["statement"]
      "Sign in to access premium data"
      iex> challenge["schema"] == X402.Extensions.SIWX.schema()
      true
  """
  @spec challenge(keyword()) :: map()
  defdelegate challenge(opts), to: Challenge, as: :build

  @doc since: "0.9.0"
  @doc """
  Builds the CAIP-122 message text a wallet signs for a fields map.

  Delegates to `X402.Extensions.SIWX.Message.build/1`; see it for the
  exact formats.

  ## Examples

      iex> {:ok, text} = X402.Extensions.SIWX.message(%{
      ...>   "domain" => "api.example.com",
      ...>   "address" => "BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW",
      ...>   "uri" => "https://api.example.com",
      ...>   "version" => "1",
      ...>   "chainId" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      ...>   "nonce" => "a1b2c3d4e5f67890a1b2c3d4e5f67890",
      ...>   "issuedAt" => "2024-01-15T10:30:00.000Z"
      ...> })
      iex> String.split(text, "\\n") |> Enum.take(3)
      ["api.example.com wants you to sign in with your Solana account:", "BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW", ""]
  """
  @spec message(map()) :: {:ok, String.t()} | {:error, Message.build_error()}
  defdelegate message(fields), to: Message, as: :build

  @doc since: "0.9.0"
  @doc """
  Signs a challenge with an `X402.Signer`, producing the proof fields.

  `challenge` is the advertised extension value (`%{"info" => ..., "supportedChains" => ...}`)
  or its bare `info` map. The server's fields are copied verbatim, the
  signer's address (or `:address`) and the chain's `chainId` / `type` are
  added, and the CAIP-122 message is signed: `eip155:*` chains through
  `X402.Signer.sign_message/2` (EIP-191), `solana:*` chains through
  `X402.Signer.sign_ed25519/2` with the signature Base58-encoded.

  Returns `{:error, :unsupported_chain}` when the chain's namespace is not
  supported or the challenge's `supportedChains` does not list it,
  `{:error, :invalid_chain_id}` for a malformed reference,
  `{:error, :invalid_payload}` when the challenge lacks required info
  fields, and signer errors (`:unsupported_signer`, `:missing_dependency`,
  ...) as they are.

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}

  ## Examples

      iex> {:ok, signer} = X402.Signer.SolanaKey.new(:binary.copy(<<1>>, 32))
      iex> challenge = X402.Extensions.SIWX.challenge(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}]
      ...> )
      iex> {:ok, signed} = X402.Extensions.SIWX.sign(challenge, signer, chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      iex> {signed["address"], signed["type"]}
      {"AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9", "ed25519"}

      iex> {:ok, signer} = X402.Signer.SolanaKey.new(:binary.copy(<<1>>, 32))
      iex> challenge = X402.Extensions.SIWX.challenge(
      ...>   domain: "api.example.com",
      ...>   uri: "https://api.example.com",
      ...>   supported_chains: [%{chain_id: "eip155:8453"}]
      ...> )
      iex> X402.Extensions.SIWX.sign(challenge, signer, chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      {:error, :unsupported_chain}
  """
  @spec sign(map(), Signer.t(), keyword()) :: {:ok, fields()} | {:error, sign_error()}
  def sign(challenge, signer, opts) when is_map(challenge) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)
    chain_id = Keyword.fetch!(opts, :chain_id)

    with {:ok, family} <- sign_family(chain_id),
         :ok <- ensure_advertised_chain(challenge, chain_id),
         {:ok, address} <- signer_address(signer, Keyword.fetch!(opts, :address)),
         fields = proof_fields(challenge, family, chain_id, address, opts),
         {:ok, message} <- build_message(fields),
         {:ok, signature} <- sign_message(family, signer, message) do
      {:ok, Map.put(fields, "signature", signature)}
    end
  end

  def sign(_challenge, _signer, _opts), do: {:error, :invalid_payload}

  @spec sign_family(String.t()) ::
          {:ok, Message.family()} | {:error, :unsupported_chain | :invalid_chain_id}
  defp sign_family(chain_id), do: Message.family(chain_id)

  @spec ensure_advertised_chain(map(), String.t()) :: :ok | {:error, :unsupported_chain}
  defp ensure_advertised_chain(challenge, chain_id) do
    case Utils.map_value(challenge, {"supportedChains", :supported_chains}) do
      chains when is_list(chains) and chains != [] ->
        case Enum.any?(chains, &(chain_entry_id(&1) == chain_id)) do
          true -> :ok
          false -> {:error, :unsupported_chain}
        end

      _absent ->
        :ok
    end
  end

  @spec chain_entry_id(term()) :: term()
  defp chain_entry_id(entry) when is_map(entry),
    do: Utils.map_value(entry, {"chainId", :chain_id})

  defp chain_entry_id(entry) when is_list(entry), do: Keyword.get(entry, :chain_id)
  defp chain_entry_id(_entry), do: nil

  @spec signer_address(Signer.t(), String.t() | nil) :: {:ok, String.t()} | {:error, term()}
  defp signer_address(_signer, address) when is_binary(address), do: {:ok, address}
  defp signer_address(signer, nil), do: Signer.address(signer)

  @spec proof_fields(map(), Message.family(), String.t(), String.t(), keyword()) :: map()
  defp proof_fields(challenge, family, chain_id, address, opts) do
    info =
      case Utils.map_value(challenge, {"info", :info}) do
        %{} = info -> info
        _absent -> challenge
      end

    @copied_info_fields
    |> Enum.reduce(%{}, fn {wire_key, _atom_key} = keys, acc ->
      case Utils.map_value(info, keys) do
        nil -> acc
        value -> Map.put(acc, wire_key, value)
      end
    end)
    |> maybe_put_resources(Utils.map_value(info, {"resources", :resources}))
    |> Map.put("address", address)
    |> Map.put("chainId", chain_id)
    |> Map.put("type", Message.signature_type(family))
    |> maybe_put("signatureScheme", Keyword.fetch!(opts, :signature_scheme))
  end

  @spec build_message(map()) :: {:ok, String.t()} | {:error, :invalid_payload}
  defp build_message(fields) do
    case Message.build(fields) do
      {:ok, message} -> {:ok, message}
      {:error, _reason} -> {:error, :invalid_payload}
    end
  end

  @spec sign_message(Message.family(), Signer.t(), String.t()) ::
          {:ok, String.t()} | {:error, term()}
  defp sign_message(:eip155, signer, message), do: Signer.sign_message(signer, message)

  defp sign_message(:solana, signer, message) do
    with {:ok, signature} <- Signer.sign_ed25519(signer, message) do
      {:ok, X402.Base58.encode(signature)}
    end
  end

  @doc since: "0.9.0", group: :headers
  @doc """
  Encodes signed proof fields as a `SIGN-IN-WITH-X` header value.

  The fields must be a complete proof (`validate_fields/1` plus a
  `signature`), keyed by wire names or their snake_case atoms.

  ## Examples

      iex> {:ok, header} = X402.Extensions.SIWX.encode_signed(%{
      ...>   "domain" => "api.example.com",
      ...>   "address" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   "uri" => "https://api.example.com",
      ...>   "version" => "1",
      ...>   "chainId" => "eip155:8453",
      ...>   "type" => "eip191",
      ...>   "nonce" => "a1b2c3d4e5f67890a1b2c3d4e5f67890",
      ...>   "issuedAt" => "2024-01-15T10:30:00.000Z",
      ...>   "signature" => "0xabc"
      ...> })
      iex> {:ok, {:spec, fields}} = X402.Extensions.SIWX.decode_signed(header)
      iex> fields["chainId"]
      "eip155:8453"

      iex> X402.Extensions.SIWX.encode_signed(%{"domain" => "api.example.com"})
      {:error, :invalid_payload}
  """
  @spec encode_signed(map()) :: {:ok, String.t()} | {:error, signed_encode_error()}
  def encode_signed(fields) when is_map(fields) do
    with {:ok, validated} <- validate_proof(fields),
         {:ok, json} <- encode_json(validated) do
      {:ok, Base.encode64(json)}
    end
  end

  def encode_signed(_fields), do: {:error, :invalid_payload}

  @spec encode_json(map()) :: {:ok, String.t()} | {:error, :invalid_json}
  defp encode_json(map) do
    case Jason.encode(map) do
      {:ok, json} -> {:ok, json}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  @doc since: "0.9.0", group: :headers
  @doc """
  Decodes a `SIGN-IN-WITH-X` header value.

  Returns `{:ok, {:spec, fields}}` for the spec format (a JSON object with
  the CAIP-122 fields and a `signature`) and
  `{:ok, {:legacy, %{"message" => ..., "signature" => ...}}}` for the
  deprecated pre-0.7.0 format, whose message must parse as a legacy
  EIP-4361 text (`decode/1`). Values above 8 KB are rejected with
  `{:error, :payload_too_large}` before decoding.

  ## Examples

      iex> X402.Extensions.SIWX.decode_signed("%%")
      {:error, :invalid_base64}

      iex> X402.Extensions.SIWX.decode_signed(Base.encode64("{"))
      {:error, :invalid_json}

      iex> X402.Extensions.SIWX.decode_signed(Base.encode64(~s({"domain":"api.example.com"})))
      {:error, :invalid_payload}
  """
  @spec decode_signed(String.t()) :: {:ok, decoded()} | {:error, signed_decode_error()}
  def decode_signed(value) when is_binary(value) and byte_size(value) > @max_header_bytes,
    do: {:error, :payload_too_large}

  def decode_signed(value) when is_binary(value) do
    with {:ok, json} <- Utils.decode_base64(value),
         {:ok, decoded} <- decode_json(json) do
      classify_proof(decoded)
    end
  end

  def decode_signed(_value), do: {:error, :invalid_base64}

  @spec decode_json(String.t()) :: {:ok, term()} | {:error, :invalid_json}
  defp decode_json(json) do
    case Jason.decode(json) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _reason} -> {:error, :invalid_json}
    end
  end

  @spec classify_proof(term()) :: {:ok, decoded()} | {:error, :invalid_payload}
  defp classify_proof(%{"message" => message, "signature" => signature} = decoded)
       when is_binary(message) and is_binary(signature) and not is_map_key(decoded, "domain") do
    case decode(message) do
      {:ok, _payload} when signature != "" ->
        {:ok, {:legacy, %{"message" => message, "signature" => signature}}}

      _other ->
        {:error, :invalid_payload}
    end
  end

  defp classify_proof(%{} = decoded) do
    with {:ok, fields} <- validate_proof(decoded) do
      {:ok, {:spec, fields}}
    end
  end

  defp classify_proof(_decoded), do: {:error, :invalid_payload}

  @doc since: "0.9.0"
  @doc """
  Validates and normalizes spec-format proof fields.

  Requires `domain`, `address`, `uri`, `version` (`"1"`), `chainId`, `type`,
  `nonce`, and `issuedAt` as non-empty strings; `expirationTime`,
  `notBefore`, `requestId`, `statement`, `signatureScheme`, and `signature`
  must be non-empty strings when present and `resources` a list of strings.
  Unknown keys are dropped. Accepts wire (camelCase string) keys or their
  snake_case atoms and always returns wire keys.

  ## Examples

      iex> {:ok, fields} = X402.Extensions.SIWX.validate_fields(%{
      ...>   domain: "api.example.com",
      ...>   address: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   uri: "https://api.example.com",
      ...>   version: "1",
      ...>   chain_id: "eip155:8453",
      ...>   type: "eip191",
      ...>   nonce: "a1b2c3d4e5f67890a1b2c3d4e5f67890",
      ...>   issued_at: "2024-01-15T10:30:00.000Z",
      ...>   resources: ["https://api.example.com/premium-data"]
      ...> })
      iex> Map.keys(fields) |> Enum.sort()
      ["address", "chainId", "domain", "issuedAt", "nonce", "resources", "type", "uri", "version"]

      iex> X402.Extensions.SIWX.validate_fields(%{"domain" => "api.example.com"})
      {:error, :invalid_payload}
  """
  @spec validate_fields(map()) :: {:ok, fields()} | {:error, :invalid_payload}
  def validate_fields(fields) when is_map(fields) do
    with {:ok, required} <- take_required(fields),
         :ok <- ensure_version(required),
         {:ok, optional} <- take_optional(fields),
         {:ok, resources} <- take_resources(fields) do
      {:ok, required |> Map.merge(optional) |> maybe_put_resources(resources)}
    end
  end

  def validate_fields(_fields), do: {:error, :invalid_payload}

  @doc false
  @spec validate_proof(map()) :: {:ok, fields()} | {:error, :invalid_payload}
  def validate_proof(fields) when is_map(fields) do
    with {:ok, validated} <- validate_fields(fields),
         {:ok, signature} <- non_empty_string(Utils.map_value(fields, {"signature", :signature})) do
      {:ok, Map.put(validated, "signature", signature)}
    end
  end

  def validate_proof(_fields), do: {:error, :invalid_payload}

  @spec take_required(map()) :: {:ok, map()} | {:error, :invalid_payload}
  defp take_required(fields) do
    Enum.reduce_while(@required_proof_fields, {:ok, %{}}, fn {wire_key, _atom} = keys,
                                                             {:ok, acc} ->
      case non_empty_string(Utils.map_value(fields, keys)) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, wire_key, value)}}
        {:error, _reason} -> {:halt, {:error, :invalid_payload}}
      end
    end)
  end

  @spec ensure_version(map()) :: :ok | {:error, :invalid_payload}
  defp ensure_version(%{"version" => @siwe_version}), do: :ok
  defp ensure_version(_fields), do: {:error, :invalid_payload}

  @spec take_optional(map()) :: {:ok, map()} | {:error, :invalid_payload}
  defp take_optional(fields) do
    Enum.reduce_while(@optional_proof_fields, {:ok, %{}}, fn {wire_key, _atom} = keys,
                                                             {:ok, acc} ->
      case take_optional_value(Utils.map_value(fields, keys)) do
        {:ok, nil} -> {:cont, {:ok, acc}}
        {:ok, value} -> {:cont, {:ok, Map.put(acc, wire_key, value)}}
        {:error, _reason} -> {:halt, {:error, :invalid_payload}}
      end
    end)
  end

  @spec take_optional_value(term()) :: {:ok, String.t() | nil} | {:error, :invalid_payload}
  defp take_optional_value(nil), do: {:ok, nil}
  defp take_optional_value(value), do: non_empty_string(value)

  @spec take_resources(map()) :: {:ok, [String.t()] | nil} | {:error, :invalid_payload}
  defp take_resources(fields) do
    case Utils.map_value(fields, {"resources", :resources}) do
      nil ->
        {:ok, nil}

      resources when is_list(resources) ->
        case Enum.all?(resources, &is_binary/1) do
          true -> {:ok, resources}
          false -> {:error, :invalid_payload}
        end

      _other ->
        {:error, :invalid_payload}
    end
  end

  @spec non_empty_string(term()) :: {:ok, String.t()} | {:error, :invalid_payload}
  defp non_empty_string(value) when is_binary(value) and value != "", do: {:ok, value}
  defp non_empty_string(_value), do: {:error, :invalid_payload}

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @spec maybe_put_resources(map(), term()) :: map()
  defp maybe_put_resources(map, resources) when is_list(resources) and resources != [],
    do: Map.put(map, "resources", resources)

  defp maybe_put_resources(map, _resources), do: map

  @doc since: "0.9.0", group: :verification
  @doc """
  Verifies a decoded (or raw) `SIGN-IN-WITH-X` proof against the server's
  configuration.

  Accepts the tuple `decode_signed/1` returns or the raw header value
  (which is decoded first; decode errors are returned as they are). The
  checks run in the spec's order and each failure carries one of the
  spec's machine-readable codes:

  | Code | Failed check |
  | --- | --- |
  | `:invalid_siwx_domain_mismatch` | `domain` differs from `:domain` |
  | `:invalid_siwx_uri_mismatch` | `uri` differs from `:uri` (trailing slash ignored) |
  | `:invalid_siwx_issued_at` | `issuedAt` is not ISO 8601 |
  | `:invalid_siwx_issued_at_too_old` | `issuedAt` is older than `:max_age_seconds` |
  | `:invalid_siwx_issued_at_in_future` | `issuedAt` is more than `:clock_skew_seconds` ahead of `:now` |
  | `:invalid_siwx_expiration_time` | `expirationTime` is not ISO 8601 |
  | `:invalid_siwx_expired` | `expirationTime` is not after `:now` |
  | `:invalid_siwx_not_before` | `notBefore` is not ISO 8601 |
  | `:invalid_siwx_not_yet_valid` | `notBefore` is after `:now` |
  | `:invalid_siwx_nonce` | `nonce` is not 32 lowercase hex characters, or — with `:nonce_cache` — was not issued or was already used |
  | `:invalid_siwx_chain_id` | `chainId` has a malformed reference |
  | `:invalid_siwx_unsupported_chain` | `chainId`/`type` is not in `:supported_chains` |
  | `:invalid_siwx_malformed_signature` | the address or signature encoding/length is invalid |
  | `:invalid_siwx_signature` | the signature does not verify for `address` |
  | `:invalid_siwx_verifier_error` | the verifier failed or raised |

  `:domain` and `:uri` must be the server's configured public origin —
  never values derived from the request's `Host` header, which the caller
  controls. With `:nonce_cache`, a nonce must have been recorded as issued
  (`X402.Extensions.SIWX.Server.remember_nonce/2`) and is atomically marked
  used after the signature verifies, so a proof authenticates at most once.
  Without it a nonce is only checked for format and the time window.

  Legacy `{:legacy, proof}` values are parsed with `decode/1` and verified
  by the same rules over the exact text that was signed (`type` is
  `"eip191"`).

  ## Options

  #{NimbleOptions.docs(Verification.opts_schema())}

  ## Examples

      iex> X402.Extensions.SIWX.verify("%%", domain: "api.example.com", uri: "https://api.example.com", supported_chains: [%{chain_id: "eip155:8453"}])
      {:error, :invalid_base64}
  """
  @spec verify(decoded() | String.t(), keyword()) ::
          {:ok, identity()} | {:error, verify_error()}
  def verify(header, opts) when is_binary(header) do
    with {:ok, decoded} <- decode_signed(header) do
      Verification.verify(decoded, opts)
    end
  end

  def verify({tag, _proof} = decoded, opts) when tag in [:spec, :legacy],
    do: Verification.verify(decoded, opts)

  def verify(_decoded, _opts), do: {:error, :invalid_payload}

  @doc false
  @spec legacy_notice(legacy_source()) :: :ok
  def legacy_notice(source) when source in [:gate] do
    X402.Telemetry.emit(:siwx, :legacy, :ok, %{source: source})
    warn_legacy_once()
  end

  @spec warn_legacy_once() :: :ok
  defp warn_legacy_once do
    key = {__MODULE__, :legacy_format_warned}

    unless :persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "[X402.Extensions.SIWX] received a SIGN-IN-WITH-X header in the deprecated " <>
          "{message, signature} format. Clients should send the spec proof fields; " <>
          "legacy support is removed in 1.0.0."
      )
    end

    :ok
  end

  # -- Legacy EIP-4361 text codec --------------------------------------------

  @doc since: "0.3.0"
  @doc """
  Encodes a SIWX payload into an EIP-4361 message.

  `:chain_id` accepts either `"eip155:<id>"` or a positive integer. This is
  the strict pre-0.7.0 codec (every field, including `:statement` and
  `:expiration_time`, is required); `message/1` builds the spec's message
  from proof fields.

  ## Examples

      iex> payload = %{
      ...>   domain: "example.com",
      ...>   address: "0x1111111111111111111111111111111111111111",
      ...>   statement: "Access purchased content",
      ...>   uri: "https://example.com/protected",
      ...>   version: "1",
      ...>   chain_id: "eip155:1",
      ...>   nonce: "abc12345",
      ...>   issued_at: "2026-02-16T12:00:00Z",
      ...>   expiration_time: "2026-02-16T13:00:00Z"
      ...> }
      iex> {:ok, message} = X402.Extensions.SIWX.encode(payload)
      iex> is_binary(message)
      true
  """
  @spec encode(map()) :: {:ok, String.t()} | {:error, encode_error()}
  def encode(payload) when is_map(payload) do
    with {:ok, normalized} <- normalize_payload(payload) do
      Message.build(%{
        "domain" => normalized.domain,
        "address" => normalized.address,
        "statement" => normalized.statement,
        "uri" => normalized.uri,
        "version" => normalized.version,
        "chainId" => normalized.chain_id,
        "nonce" => normalized.nonce,
        "issuedAt" => normalized.issued_at,
        "expirationTime" => normalized.expiration_time
      })
    end
  end

  def encode(_payload), do: {:error, :invalid_payload}

  @doc since: "0.3.0"
  @doc """
  Decodes an EIP-4361 SIWX message into payload fields.

  ## Examples

      iex> payload = %{
      ...>   domain: "example.com",
      ...>   address: "0x1111111111111111111111111111111111111111",
      ...>   statement: "Access purchased content",
      ...>   uri: "https://example.com/protected",
      ...>   version: "1",
      ...>   chain_id: "eip155:1",
      ...>   nonce: "abc12345",
      ...>   issued_at: "2026-02-16T12:00:00Z",
      ...>   expiration_time: "2026-02-16T13:00:00Z"
      ...> }
      iex> {:ok, message} = X402.Extensions.SIWX.encode(payload)
      iex> X402.Extensions.SIWX.decode(message)
      {:ok, payload}
  """
  @spec decode(String.t()) :: {:ok, message_payload()} | {:error, decode_error()}
  def decode(message) when is_binary(message) do
    with {:ok, payload} <- parse_message(message),
         {:ok, normalized} <- normalize_payload(payload) do
      {:ok,
       %{
         domain: normalized.domain,
         address: normalized.address,
         statement: normalized.statement,
         uri: normalized.uri,
         version: normalized.version,
         chain_id: normalized.chain_id,
         nonce: normalized.nonce,
         issued_at: normalized.issued_at,
         expiration_time: normalized.expiration_time
       }}
    else
      {:error, {:missing_fields, _missing}} -> {:error, :invalid_message}
      {:error, :invalid_payload} -> {:error, :invalid_message}
      {:error, reason} -> {:error, reason}
    end
  end

  def decode(_message), do: {:error, :invalid_message}

  @doc since: "0.3.0", group: :headers
  @deprecated "Use the spec proof format (sign/3, encode_signed/1); removed in 1.0.0"
  @doc """
  Encodes a legacy SIWX header payload with `message` and `signature` fields.

      {:ok, header} = X402.Extensions.SIWX.encode_header(%{message: "hello", signature: "0xabc"})
      {:ok, decoded} = X402.Extensions.SIWX.decode_header(header)
      decoded["message"]
      #=> "hello"
  """
  @spec encode_header(map()) :: {:ok, String.t()} | {:error, header_encode_error()}
  def encode_header(payload) when is_map(payload) do
    with {:ok, message} <- fetch_non_empty_binary(payload, :message),
         {:ok, signature} <- fetch_non_empty_binary(payload, :signature),
         {:ok, json} <- Jason.encode(%{"message" => message, "signature" => signature}) do
      {:ok, Base.encode64(json)}
    else
      {:error, :invalid_payload} = error ->
        error

      {:error, _reason} ->
        {:error, :invalid_json}
    end
  end

  def encode_header(_payload), do: {:error, :invalid_payload}

  @doc since: "0.3.0", group: :headers
  @deprecated "Use decode_signed/1, which also understands this format; removed in 1.0.0"
  @doc """
  Decodes a legacy `SIGN-IN-WITH-X` header into its `message` and `signature`.

      {:ok, encoded} = X402.Extensions.SIWX.encode_header(%{message: "hello", signature: "0xabc"})
      X402.Extensions.SIWX.decode_header(encoded)
      #=> {:ok, %{"message" => "hello", "signature" => "0xabc"}}

      X402.Extensions.SIWX.decode_header("%%")
      #=> {:error, :invalid_base64}
  """
  @spec decode_header(String.t()) :: {:ok, map()} | {:error, header_decode_error()}
  def decode_header(value) when is_binary(value) do
    with {:ok, json} <- decode_base64(value),
         {:ok, decoded} <- Jason.decode(json),
         true <- is_map(decoded),
         {:ok, message} <- fetch_non_empty_binary(decoded, :message),
         {:ok, signature} <- fetch_non_empty_binary(decoded, :signature) do
      {:ok, %{"message" => message, "signature" => signature}}
    else
      {:error, :invalid_base64} = error ->
        error

      {:error, %Jason.DecodeError{}} ->
        {:error, :invalid_json}

      false ->
        {:error, :invalid_json}

      {:error, :invalid_payload} = error ->
        error
    end
  end

  def decode_header(_value), do: {:error, :invalid_base64}

  @spec parse_message(String.t()) :: {:ok, map()} | {:error, decode_error()}
  defp parse_message(message) do
    case String.split(message, "\n", trim: false) do
      [
        domain_line,
        address,
        "",
        statement,
        "",
        uri_line,
        version_line,
        chain_id_line,
        nonce_line,
        issued_at_line,
        expiration_time_line
      ] ->
        with {:ok, domain} <- parse_domain(domain_line),
             {:ok, uri} <- parse_prefixed_value(uri_line, "URI: ", :uri),
             {:ok, version} <- parse_prefixed_value(version_line, "Version: ", :version),
             {:ok, chain_id} <- parse_chain_line(chain_id_line),
             {:ok, nonce} <- parse_prefixed_value(nonce_line, "Nonce: ", :nonce),
             {:ok, issued_at} <- parse_prefixed_value(issued_at_line, "Issued At: ", :issued_at),
             {:ok, expiration_time} <-
               parse_prefixed_value(expiration_time_line, "Expiration Time: ", :expiration_time) do
          {:ok,
           %{
             domain: domain,
             address: address,
             statement: statement,
             uri: uri,
             version: version,
             chain_id: chain_id,
             nonce: nonce,
             issued_at: issued_at,
             expiration_time: expiration_time
           }}
        end

      _other ->
        {:error, :invalid_message}
    end
  end

  @spec parse_domain(String.t()) :: {:ok, String.t()} | {:error, decode_error()}
  defp parse_domain(line) do
    case String.ends_with?(line, @domain_suffix) do
      true ->
        domain = String.replace_suffix(line, @domain_suffix, "")

        case domain do
          "" -> {:error, {:invalid_field, :domain}}
          _ -> {:ok, domain}
        end

      false ->
        {:error, :invalid_message}
    end
  end

  @spec parse_prefixed_value(String.t(), String.t(), atom()) ::
          {:ok, String.t()} | {:error, decode_error()}
  defp parse_prefixed_value(line, prefix, field) do
    case String.starts_with?(line, prefix) do
      true ->
        value = String.replace_prefix(line, prefix, "")

        case value do
          "" -> {:error, {:invalid_field, field}}
          _ -> {:ok, value}
        end

      false ->
        {:error, :invalid_message}
    end
  end

  @spec parse_chain_line(String.t()) :: {:ok, String.t()} | {:error, decode_error()}
  defp parse_chain_line(line) do
    with {:ok, chain_id_value} <- parse_prefixed_value(line, "Chain ID: ", :chain_id),
         {chain_ref, ""} <- Integer.parse(chain_id_value),
         true <- chain_ref > 0 do
      {:ok, "eip155:#{chain_ref}"}
    else
      _ -> {:error, {:invalid_field, :chain_id}}
    end
  end

  @spec normalize_payload(map()) :: {:ok, map()} | {:error, encode_error()}
  defp normalize_payload(payload) do
    missing =
      Enum.reject(@required_message_fields, fn field ->
        match?({:ok, _value}, fetch_required(payload, field))
      end)

    case missing do
      [] ->
        with {:ok, domain} <- fetch_non_empty_binary(payload, :domain),
             {:ok, address} <- validate_address(payload),
             {:ok, statement} <- validate_statement(payload),
             {:ok, uri} <- validate_uri(payload),
             {:ok, version} <- validate_version(payload),
             {:ok, {chain_id, chain_ref}} <- validate_chain_id(payload),
             {:ok, nonce} <- validate_nonce(payload),
             {:ok, issued_at_datetime} <- validate_datetime(payload, :issued_at),
             {:ok, expiration_datetime} <- validate_datetime(payload, :expiration_time),
             :ok <- validate_expiration(issued_at_datetime, expiration_datetime) do
          {:ok,
           %{
             domain: domain,
             address: address,
             statement: statement,
             uri: uri,
             version: version,
             chain_id: chain_id,
             chain_ref: chain_ref,
             nonce: nonce,
             issued_at: DateTime.to_iso8601(issued_at_datetime),
             expiration_time: DateTime.to_iso8601(expiration_datetime)
           }}
        end

      _missing ->
        {:error, {:missing_fields, missing}}
    end
  end

  @spec fetch_required(map(), atom()) :: {:ok, term()} | {:error, :invalid_payload}
  defp fetch_required(payload, field) do
    case Map.fetch(payload, field) do
      {:ok, value} -> {:ok, value}
      :error -> Map.fetch(payload, Atom.to_string(field))
    end
  end

  @spec fetch_non_empty_binary(map(), atom()) :: {:ok, String.t()} | {:error, :invalid_payload}
  defp fetch_non_empty_binary(payload, field) do
    with {:ok, value} <- fetch_required(payload, field),
         true <- is_binary(value),
         true <- value != "" do
      {:ok, value}
    else
      _ -> {:error, :invalid_payload}
    end
  end

  @spec validate_address(map()) :: {:ok, String.t()} | {:error, {:invalid_field, :address}}
  defp validate_address(payload) do
    case fetch_non_empty_binary(payload, :address) do
      {:ok, address} ->
        case Wallet.valid_evm?(address) do
          true -> {:ok, address}
          false -> {:error, {:invalid_field, :address}}
        end

      {:error, :invalid_payload} ->
        {:error, {:invalid_field, :address}}
    end
  end

  @spec validate_statement(map()) :: {:ok, String.t()} | {:error, {:invalid_field, :statement}}
  defp validate_statement(payload) do
    case fetch_non_empty_binary(payload, :statement) do
      {:ok, statement} ->
        case String.contains?(statement, "\n") do
          true -> {:error, {:invalid_field, :statement}}
          false -> {:ok, statement}
        end

      {:error, :invalid_payload} ->
        {:error, {:invalid_field, :statement}}
    end
  end

  @spec validate_uri(map()) :: {:ok, String.t()} | {:error, {:invalid_field, :uri}}
  defp validate_uri(payload) do
    case fetch_non_empty_binary(payload, :uri) do
      {:ok, uri} ->
        parsed = URI.parse(uri)

        case parsed.scheme do
          nil -> {:error, {:invalid_field, :uri}}
          _scheme -> {:ok, uri}
        end

      {:error, :invalid_payload} ->
        {:error, {:invalid_field, :uri}}
    end
  end

  @spec validate_version(map()) :: {:ok, String.t()} | {:error, {:invalid_field, :version}}
  defp validate_version(payload) do
    case fetch_non_empty_binary(payload, :version) do
      {:ok, @siwe_version = version} -> {:ok, version}
      _ -> {:error, {:invalid_field, :version}}
    end
  end

  @spec validate_chain_id(map()) ::
          {:ok, {String.t(), pos_integer()}} | {:error, {:invalid_field, :chain_id}}
  defp validate_chain_id(payload) do
    case fetch_required(payload, :chain_id) do
      {:ok, "eip155:" <> chain_reference} ->
        parse_chain_reference(chain_reference)

      {:ok, chain_reference} when is_integer(chain_reference) and chain_reference > 0 ->
        {:ok, {"eip155:#{chain_reference}", chain_reference}}

      {:ok, chain_reference} when is_binary(chain_reference) ->
        parse_chain_reference(chain_reference)

      _ ->
        {:error, {:invalid_field, :chain_id}}
    end
  end

  @spec parse_chain_reference(String.t()) ::
          {:ok, {String.t(), pos_integer()}} | {:error, {:invalid_field, :chain_id}}
  defp parse_chain_reference(chain_reference) do
    with {parsed, ""} <- Integer.parse(chain_reference),
         true <- parsed > 0 do
      {:ok, {"eip155:#{parsed}", parsed}}
    else
      _ -> {:error, {:invalid_field, :chain_id}}
    end
  end

  @spec validate_nonce(map()) :: {:ok, String.t()} | {:error, {:invalid_field, :nonce}}
  defp validate_nonce(payload) do
    case fetch_non_empty_binary(payload, :nonce) do
      {:ok, nonce} ->
        case nonce =~ @nonce_regex do
          true -> {:ok, nonce}
          false -> {:error, {:invalid_field, :nonce}}
        end

      {:error, :invalid_payload} ->
        {:error, {:invalid_field, :nonce}}
    end
  end

  @spec validate_datetime(map(), atom()) ::
          {:ok, DateTime.t()} | {:error, {:invalid_field, atom()}}
  defp validate_datetime(payload, field) do
    case fetch_non_empty_binary(payload, field) do
      {:ok, value} ->
        case DateTime.from_iso8601(value) do
          {:ok, datetime, _offset} -> {:ok, datetime}
          {:error, _reason} -> {:error, {:invalid_field, field}}
        end

      {:error, :invalid_payload} ->
        {:error, {:invalid_field, field}}
    end
  end

  @spec validate_expiration(DateTime.t(), DateTime.t()) ::
          :ok | {:error, {:invalid_field, :expiration_time}}
  defp validate_expiration(issued_at_datetime, expiration_datetime) do
    case DateTime.compare(expiration_datetime, issued_at_datetime) do
      :gt -> :ok
      _other -> {:error, {:invalid_field, :expiration_time}}
    end
  end

  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  defp decode_base64(""), do: {:error, :invalid_base64}

  defp decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end
end
