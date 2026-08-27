defmodule X402.EIP3009 do
  @moduledoc """
  EIP-3009 `TransferWithAuthorization` building and EIP-712 signing.

  Implements the client half of the x402 `exact` scheme on EVM networks with
  the default `eip3009` asset transfer method: building an authorization from
  v2 payment requirements, computing its EIP-712 digest, and signing it
  through the `X402.Signer` behaviour to produce the scheme `payload` map

      %{"signature" => "0x...", "authorization" => %{...}}

  carried inside a v2 `PaymentPayload` (see `X402.Client.build_payment/3` for
  the full envelope).

  The EIP-712 domain is derived from the payment requirements as specified by
  the exact-EVM scheme: `name`/`version` from `extra`, the chain id from the
  CAIP-2 `network`, and the verifying contract from `asset`.

  Cryptographic operations require the optional `ex_secp256k1` and
  `ex_keccak` dependencies and return `{:error, :missing_dependency}` when
  they are unavailable; the library itself compiles without them.
  """

  alias X402.Signer
  alias X402.Utils
  alias X402.Wallet

  @eip712_domain_type "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  @transfer_with_authorization_type "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"

  @typed_data_types %{
    "EIP712Domain" => [
      %{"name" => "name", "type" => "string"},
      %{"name" => "version", "type" => "string"},
      %{"name" => "chainId", "type" => "uint256"},
      %{"name" => "verifyingContract", "type" => "address"}
    ],
    "TransferWithAuthorization" => [
      %{"name" => "from", "type" => "address"},
      %{"name" => "to", "type" => "address"},
      %{"name" => "value", "type" => "uint256"},
      %{"name" => "validAfter", "type" => "uint256"},
      %{"name" => "validBefore", "type" => "uint256"},
      %{"name" => "nonce", "type" => "bytes32"}
    ]
  }

  @authorization_opts_schema [
    valid_after_buffer: [
      type: :non_neg_integer,
      default: 60,
      doc: """
      Seconds subtracted from the current time for the authorization's
      `validAfter`, tolerating clock skew between payer, facilitator, and
      chain.
      """
    ]
  ]

  @typedoc """
  An EIP-712 domain map with `:name`, `:version`, `:chain_id`, and
  `:verifying_contract` keys.

  Functions accepting a domain also take the wire-style keys
  (`"name"`, `"version"`, `"chainId"`, `"verifyingContract"`).
  """
  @type domain :: %{
          name: String.t(),
          version: String.t(),
          chain_id: non_neg_integer(),
          verifying_contract: String.t()
        }

  @typedoc """
  A `TransferWithAuthorization` authorization in wire shape: string keys
  `"from"`, `"to"`, `"value"`, `"validAfter"`, `"validBefore"`, `"nonce"`.
  """
  @type authorization :: %{optional(String.t()) => String.t()}

  @typedoc "The scheme `payload` map for a signed EIP-3009 payment."
  @type payload :: %{optional(String.t()) => String.t() | authorization()}

  @type domain_error ::
          :invalid_requirements
          | {:missing_extra, String.t()}
          | {:unsupported_transfer_method, term()}
          | :unsupported_network

  @type encode_error ::
          :missing_dependency
          | :invalid_address
          | :invalid_amount
          | :invalid_bytes32
          | {:missing_field, String.t()}

  @doc since: "0.6.0"
  @doc """
  Signs the `exact`/`eip3009` scheme payload for the given requirements.

  Derives the EIP-712 domain from the requirements, builds a fresh
  authorization from the signer's address (`from`), `payTo` (`to`), and
  `amount` (`value`) with a random 32-byte nonce, computes the EIP-712
  digest, and signs it through `signer`.

  ## Options

  #{NimbleOptions.docs(@authorization_opts_schema)}

  ## Examples

      {:ok, signer} = X402.Signer.LocalKey.new(private_key)

      {:ok, %{"signature" => _, "authorization" => _}} =
        X402.EIP3009.sign(
          %{
            "scheme" => "exact",
            "network" => "eip155:84532",
            "amount" => "10000",
            "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds" => 60,
            "extra" => %{"name" => "USDC", "version" => "2"}
          },
          signer
        )
  """
  @spec sign(map(), Signer.t(), keyword()) ::
          {:ok, payload()} | {:error, domain_error() | encode_error() | term()}
  def sign(requirements, signer, opts \\ []) when is_map(requirements) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @authorization_opts_schema)

    with {:ok, domain} <- domain(requirements),
         {:ok, from} <- Signer.address(signer),
         {:ok, authorization} <- build_authorization(requirements, from, opts),
         {:ok, signature} <- sign_authorization(signer, domain, authorization) do
      {:ok, %{"signature" => signature, "authorization" => authorization}}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Derives the EIP-712 domain from v2 payment requirements.

  Per the exact-EVM scheme specification, `extra.name` and `extra.version`
  are required, the chain id comes from the CAIP-2 `network`, and the
  verifying contract is the `asset` address. Requirements selecting a
  non-default `extra.assetTransferMethod` are rejected.

  ## Examples

      iex> X402.EIP3009.domain(%{
      ...>   "network" => "eip155:84532",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> })
      {:ok,
       %{
         name: "USDC",
         version: "2",
         chain_id: 84532,
         verifying_contract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
       }}

      iex> X402.EIP3009.domain(%{"network" => "eip155:84532", "asset" => "0xasset", "extra" => %{}})
      {:error, {:missing_extra, "name"}}
  """
  @spec domain(map()) :: {:ok, domain()} | {:error, domain_error()}
  def domain(requirements) when is_map(requirements) do
    extra = Utils.map_value(requirements, {"extra", :extra}) || %{}
    network = Utils.map_value(requirements, {"network", :network})
    asset = Utils.map_value(requirements, {"asset", :asset})

    with :ok <- ensure_map(extra),
         :ok <- ensure_transfer_method(extra),
         {:ok, name} <- fetch_extra(extra, {"name", :name}),
         {:ok, version} <- fetch_extra(extra, {"version", :version}),
         {:ok, chain_id} <- chain_id_from_caip2(network),
         :ok <- ensure_binary(asset) do
      {:ok, %{name: name, version: version, chain_id: chain_id, verifying_contract: asset}}
    end
  end

  def domain(_requirements), do: {:error, :invalid_requirements}

  @doc since: "0.6.0"
  @doc """
  Builds a `TransferWithAuthorization` authorization map in wire shape.

  `value` and `to` come from the requirements' `amount` and `payTo`;
  `validAfter` is `now - valid_after_buffer`, `validBefore` is
  `now + maxTimeoutSeconds`, and `nonce` is a fresh random 32-byte value.

  Field values are validated when the digest is computed, not here.

  ## Options

  #{NimbleOptions.docs(@authorization_opts_schema)}
  """
  @spec build_authorization(map(), String.t(), keyword()) ::
          {:ok, authorization()} | {:error, :invalid_requirements}
  def build_authorization(requirements, from, opts \\ [])
      when is_map(requirements) and is_binary(from) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @authorization_opts_schema)
    value = Utils.map_value(requirements, {"amount", :amount})
    to = Utils.map_value(requirements, {"payTo", :payTo})
    max_timeout = Utils.map_value(requirements, {"maxTimeoutSeconds", :maxTimeoutSeconds})

    if is_binary(value) and is_binary(to) and is_integer(max_timeout) and max_timeout > 0 do
      now = System.os_time(:second)

      {:ok,
       %{
         "from" => from,
         "to" => to,
         "value" => value,
         "validAfter" => Integer.to_string(now - Keyword.fetch!(opts, :valid_after_buffer)),
         "validBefore" => Integer.to_string(now + max_timeout),
         "nonce" => random_nonce()
       }}
    else
      {:error, :invalid_requirements}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Signs an authorization's EIP-712 digest with a signer.

  Returns the `0x`-prefixed 65-byte `r || s || v` signature.
  """
  @spec sign_authorization(Signer.t(), map(), map()) ::
          {:ok, String.t()} | {:error, encode_error() | term()}
  def sign_authorization(signer, domain, authorization)
      when is_map(domain) and is_map(authorization) do
    with {:ok, digest} <- eip712_digest(domain, authorization),
         {:ok, signature} <- Signer.sign_eip712(signer, digest, typed_data(domain, authorization)) do
      {:ok, "0x" <> Base.encode16(signature, case: :lower)}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes the EIP-712 digest of a `TransferWithAuthorization`.

  Returns `keccak256(0x19 0x01 || domainSeparator || structHash)` as a
  32-byte binary. `domain` and `authorization` accept both the internal
  snake-case atom keys and the wire-style string keys.
  """
  @spec eip712_digest(map(), map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def eip712_digest(domain, authorization) when is_map(domain) and is_map(authorization) do
    with {:ok, keccak_module} <- keccak_module(),
         {:ok, domain_separator} <- domain_separator(domain, keccak_module),
         {:ok, struct_hash} <- struct_hash(authorization, keccak_module) do
      {:ok, keccak_module.hash_256(<<0x19, 0x01>> <> domain_separator <> struct_hash)}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Derives the lowercase EVM address for a 32-byte secp256k1 private key.
  """
  @spec derive_address(binary()) ::
          {:ok, String.t()} | {:error, :missing_dependency | :invalid_private_key}
  def derive_address(private_key) when is_binary(private_key) and byte_size(private_key) == 32 do
    with {:ok, secp256k1_module, keccak_module} <- crypto_modules(),
         {:ok, public_key} <- create_public_key(secp256k1_module, private_key) do
      public_key_to_address(public_key, keccak_module)
    end
  end

  def derive_address(_private_key), do: {:error, :invalid_private_key}

  @doc since: "0.6.0"
  @doc """
  Converts a 65-byte uncompressed (or 64-byte) secp256k1 public key to a
  lowercase `0x`-prefixed EVM address.
  """
  @spec public_key_to_address(binary()) ::
          {:ok, String.t()} | {:error, :missing_dependency | :invalid_public_key}
  def public_key_to_address(public_key) when is_binary(public_key) do
    with {:ok, _secp256k1_module, keccak_module} <- crypto_modules() do
      public_key_to_address(public_key, keccak_module)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Recovers the signer address from an EIP-712 digest and a 65-byte signature.

  Accepts the `0x`-prefixed hex signature produced by `sign_authorization/3`
  or the raw 65-byte binary. Useful for verifying a signed payment locally.
  """
  @spec recover_signer(binary(), binary()) ::
          {:ok, String.t()} | {:error, :missing_dependency | :invalid_signature | term()}
  def recover_signer(digest, signature)
      when is_binary(digest) and byte_size(digest) == 32 and is_binary(signature) do
    with {:ok, secp256k1_module, keccak_module} <- crypto_modules(),
         {:ok, <<compact::binary-size(64), v>>} <- decode_signature(signature),
         {:ok, public_key} <- secp256k1_module.recover_compact(digest, compact, v - 27) do
      public_key_to_address(public_key, keccak_module)
    end
  end

  def recover_signer(_digest, _signature), do: {:error, :invalid_signature}

  @doc since: "0.6.0"
  @doc """
  Returns a fresh random 32-byte nonce as a `0x`-prefixed hex string.

  ## Examples

      iex> nonce = X402.EIP3009.random_nonce()
      iex> String.match?(nonce, ~r/^0x[0-9a-f]{64}$/)
      true
  """
  @spec random_nonce() :: String.t()
  def random_nonce do
    "0x" <> Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
  end

  @doc since: "0.6.0"
  @doc """
  Extracts the chain id from an `eip155:<chainId>` CAIP-2 network identifier.

  ## Examples

      iex> X402.EIP3009.chain_id_from_caip2("eip155:84532")
      {:ok, 84532}

      iex> X402.EIP3009.chain_id_from_caip2("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      {:error, :unsupported_network}
  """
  @spec chain_id_from_caip2(term()) :: {:ok, non_neg_integer()} | {:error, :unsupported_network}
  def chain_id_from_caip2("eip155:" <> chain_id) do
    case Integer.parse(chain_id) do
      {parsed, ""} when parsed >= 0 -> {:ok, parsed}
      _parsed -> {:error, :unsupported_network}
    end
  end

  def chain_id_from_caip2(_network), do: {:error, :unsupported_network}

  @doc since: "0.6.0"
  @doc """
  ABI-encodes a `0x`-prefixed EVM address into a 32-byte word.

  ## Examples

      iex> {:ok, word} = X402.EIP3009.encode_address("0x1111111111111111111111111111111111111111")
      iex> byte_size(word)
      32

      iex> X402.EIP3009.encode_address("0x123")
      {:error, :invalid_address}
  """
  @spec encode_address(term()) :: {:ok, <<_::256>>} | {:error, :invalid_address}
  def encode_address(address) when is_binary(address) do
    case Wallet.valid_evm?(address) do
      true ->
        "0x" <> hex = address
        {:ok, bytes} = Base.decode16(hex, case: :mixed)
        {:ok, <<0::unsigned-big-integer-size(96), bytes::binary>>}

      false ->
        {:error, :invalid_address}
    end
  end

  def encode_address(_address), do: {:error, :invalid_address}

  @doc since: "0.6.0"
  @doc """
  ABI-encodes a non-negative integer (or decimal string) into a 32-byte word.

  ## Examples

      iex> X402.EIP3009.encode_uint256(1)
      {:ok, <<1::unsigned-big-integer-size(256)>>}

      iex> X402.EIP3009.encode_uint256("not a number")
      {:error, :invalid_amount}
  """
  @spec encode_uint256(term()) :: {:ok, <<_::256>>} | {:error, :invalid_amount}
  def encode_uint256(integer) when is_integer(integer) and integer >= 0,
    do: {:ok, <<integer::unsigned-big-integer-size(256)>>}

  def encode_uint256(string) when is_binary(string) do
    case Integer.parse(string) do
      {integer, ""} when integer >= 0 -> encode_uint256(integer)
      _parsed -> {:error, :invalid_amount}
    end
  end

  def encode_uint256(_value), do: {:error, :invalid_amount}

  @doc since: "0.6.0"
  @doc """
  Decodes a `0x`-prefixed hex string into a 32-byte binary.

  ## Examples

      iex> {:ok, bytes} = X402.EIP3009.encode_bytes32("0x" <> String.duplicate("ab", 32))
      iex> byte_size(bytes)
      32

      iex> X402.EIP3009.encode_bytes32("0xdead")
      {:error, :invalid_bytes32}
  """
  @spec encode_bytes32(term()) :: {:ok, <<_::256>>} | {:error, :invalid_bytes32}
  def encode_bytes32("0x" <> hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} when byte_size(bytes) == 32 -> {:ok, bytes}
      _decoded -> {:error, :invalid_bytes32}
    end
  end

  def encode_bytes32(_value), do: {:error, :invalid_bytes32}

  # -- Domain / struct hashing ------------------------------------------------

  @spec domain_separator(map(), module()) :: {:ok, binary()} | {:error, encode_error()}
  defp domain_separator(domain, keccak_module) do
    with {:ok, name} <- fetch_field(domain, {"name", :name}),
         {:ok, version} <- fetch_field(domain, {"version", :version}),
         {:ok, chain_id} <- fetch_chain_id(domain),
         {:ok, contract} <- fetch_field(domain, {"verifyingContract", :verifying_contract}),
         {:ok, chain_id_word} <- encode_uint256(chain_id),
         {:ok, contract_word} <- encode_address(contract) do
      {:ok,
       keccak_module.hash_256(
         keccak_module.hash_256(@eip712_domain_type) <>
           keccak_module.hash_256(name) <>
           keccak_module.hash_256(version) <>
           chain_id_word <>
           contract_word
       )}
    end
  end

  @spec struct_hash(map(), module()) :: {:ok, binary()} | {:error, encode_error()}
  defp struct_hash(authorization, keccak_module) do
    with {:ok, from} <- fetch_field(authorization, {"from", :from}),
         {:ok, to} <- fetch_field(authorization, {"to", :to}),
         {:ok, value} <- fetch_field(authorization, {"value", :value}),
         {:ok, valid_after} <- fetch_field(authorization, {"validAfter", :valid_after}),
         {:ok, valid_before} <- fetch_field(authorization, {"validBefore", :valid_before}),
         {:ok, nonce} <- fetch_field(authorization, {"nonce", :nonce}),
         {:ok, from_word} <- encode_address(from),
         {:ok, to_word} <- encode_address(to),
         {:ok, value_word} <- encode_uint256(value),
         {:ok, valid_after_word} <- encode_uint256(valid_after),
         {:ok, valid_before_word} <- encode_uint256(valid_before),
         {:ok, nonce_word} <- encode_bytes32(nonce) do
      {:ok,
       keccak_module.hash_256(
         keccak_module.hash_256(@transfer_with_authorization_type) <>
           from_word <>
           to_word <>
           value_word <>
           valid_after_word <>
           valid_before_word <>
           nonce_word
       )}
    end
  end

  @spec typed_data(map(), map()) :: Signer.typed_data()
  defp typed_data(domain, authorization) do
    %{
      "types" => @typed_data_types,
      "primaryType" => "TransferWithAuthorization",
      "domain" => %{
        "name" => Utils.map_value(domain, {"name", :name}),
        "version" => Utils.map_value(domain, {"version", :version}),
        "chainId" => Utils.map_value(domain, {"chainId", :chain_id}),
        "verifyingContract" => Utils.map_value(domain, {"verifyingContract", :verifying_contract})
      },
      "message" => %{
        "from" => Utils.map_value(authorization, {"from", :from}),
        "to" => Utils.map_value(authorization, {"to", :to}),
        "value" => Utils.map_value(authorization, {"value", :value}),
        "validAfter" => Utils.map_value(authorization, {"validAfter", :valid_after}),
        "validBefore" => Utils.map_value(authorization, {"validBefore", :valid_before}),
        "nonce" => Utils.map_value(authorization, {"nonce", :nonce})
      }
    }
  end

  # -- Field access -----------------------------------------------------------

  @spec fetch_field(map(), {String.t(), atom()}) ::
          {:ok, term()} | {:error, {:missing_field, String.t()}}
  defp fetch_field(map, {string_key, _atom_key} = key) do
    case Utils.map_value(map, key) do
      nil -> {:error, {:missing_field, string_key}}
      value -> {:ok, value}
    end
  end

  @spec fetch_chain_id(map()) :: {:ok, term()} | {:error, {:missing_field, String.t()}}
  defp fetch_chain_id(domain) do
    case Utils.map_value(domain, {"chainId", :chain_id}) do
      nil -> {:error, {:missing_field, "chainId"}}
      value -> {:ok, value}
    end
  end

  @spec fetch_extra(map(), {String.t(), atom()}) ::
          {:ok, String.t()} | {:error, {:missing_extra, String.t()}}
  defp fetch_extra(extra, {string_key, _atom_key} = key) do
    case Utils.map_value(extra, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _value -> {:error, {:missing_extra, string_key}}
    end
  end

  @spec ensure_map(term()) :: :ok | {:error, :invalid_requirements}
  defp ensure_map(value) when is_map(value), do: :ok
  defp ensure_map(_value), do: {:error, :invalid_requirements}

  @spec ensure_binary(term()) :: :ok | {:error, :invalid_requirements}
  defp ensure_binary(value) when is_binary(value) and value != "", do: :ok
  defp ensure_binary(_value), do: {:error, :invalid_requirements}

  @spec ensure_transfer_method(map()) :: :ok | {:error, {:unsupported_transfer_method, term()}}
  defp ensure_transfer_method(extra) do
    case Utils.map_value(extra, {"assetTransferMethod", :assetTransferMethod}) do
      nil -> :ok
      "eip3009" -> :ok
      method -> {:error, {:unsupported_transfer_method, method}}
    end
  end

  @spec decode_signature(binary()) :: {:ok, binary()} | {:error, :invalid_signature}
  defp decode_signature("0x" <> hex), do: decode_signature_hex(hex)

  defp decode_signature(signature) when byte_size(signature) == 65,
    do: check_recovery_byte(signature)

  defp decode_signature(_signature), do: {:error, :invalid_signature}

  @spec decode_signature_hex(binary()) :: {:ok, binary()} | {:error, :invalid_signature}
  defp decode_signature_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, signature} when byte_size(signature) == 65 -> check_recovery_byte(signature)
      _decoded -> {:error, :invalid_signature}
    end
  end

  @spec check_recovery_byte(binary()) :: {:ok, binary()} | {:error, :invalid_signature}
  defp check_recovery_byte(<<_compact::binary-size(64), v>> = signature) when v in [27, 28],
    do: {:ok, signature}

  defp check_recovery_byte(<<compact::binary-size(64), v>>) when v in [0, 1],
    do: {:ok, compact <> <<v + 27>>}

  defp check_recovery_byte(_signature), do: {:error, :invalid_signature}

  # -- Optional dependency resolution ----------------------------------------
  #
  # Modules are resolved at runtime via Module.concat so the library compiles
  # without ex_secp256k1/ex_keccak (same pattern as
  # X402.Extensions.SIWX.Verifier.Default and X402.Facilitator.HTTP).

  @spec public_key_to_address(binary(), module()) ::
          {:ok, String.t()} | {:error, :invalid_public_key}
  defp public_key_to_address(<<4, public_key::binary-size(64)>>, keccak_module),
    do: hashed_public_key_to_address(public_key, keccak_module)

  defp public_key_to_address(<<public_key::binary-size(64)>>, keccak_module),
    do: hashed_public_key_to_address(public_key, keccak_module)

  defp public_key_to_address(_public_key, _keccak_module), do: {:error, :invalid_public_key}

  @spec hashed_public_key_to_address(binary(), module()) :: {:ok, String.t()}
  defp hashed_public_key_to_address(public_key, keccak_module) do
    hash = keccak_module.hash_256(public_key)
    address = binary_part(hash, byte_size(hash) - 20, 20)
    {:ok, "0x" <> Base.encode16(address, case: :lower)}
  end

  @spec create_public_key(module(), binary()) ::
          {:ok, binary()} | {:error, :invalid_private_key}
  defp create_public_key(secp256k1_module, private_key) do
    case secp256k1_module.create_public_key(private_key) do
      {:ok, public_key} -> {:ok, public_key}
      {:error, _reason} -> {:error, :invalid_private_key}
    end
  end

  @spec crypto_modules() :: {:ok, module(), module()} | {:error, :missing_dependency}
  defp crypto_modules do
    secp256k1_module = Module.concat(["ExSecp256k1"])

    with {:ok, keccak_module} <- keccak_module(),
         true <-
           Code.ensure_loaded?(secp256k1_module) and
             function_exported?(secp256k1_module, :create_public_key, 1) and
             function_exported?(secp256k1_module, :recover_compact, 3) do
      {:ok, secp256k1_module, keccak_module}
    else
      _unavailable -> {:error, :missing_dependency}
    end
  end

  @spec keccak_module() :: {:ok, module()} | {:error, :missing_dependency}
  defp keccak_module do
    keccak_module = Module.concat(["ExKeccak"])

    case Code.ensure_loaded?(keccak_module) and function_exported?(keccak_module, :hash_256, 1) do
      true -> {:ok, keccak_module}
      false -> {:error, :missing_dependency}
    end
  end
end
