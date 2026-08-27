defmodule X402.EIP712 do
  @moduledoc """
  Generic [EIP-712](https://eips.ethereum.org/EIPS/eip-712) hashing primitives.

  Shared by the x402 signing modules: `X402.EIP3009` hashes
  `TransferWithAuthorization` structs with these primitives,
  `X402.Permit2` hashes Permit2 `PermitWitnessTransferFrom` structs, and
  `X402.Extensions.EIP2612GasSponsoring` hashes EIP-2612 `Permit` structs.
  The module covers the common x402 domain shape
  (`name`/`version`/`chainId`/`verifyingContract`, the version optional
  for version-less domains such as Permit2's) and the generic
  `hash_struct/2` / `digest/2` combination

      digest = keccak256(0x19 0x01 || domainSeparator || structHash)

  together with the ABI word encoders the struct hashes are built from.

  Cryptographic hashing requires the optional `ex_keccak` dependency and
  returns `{:error, :missing_dependency}` when it is unavailable; the library
  itself compiles without it.
  """

  alias X402.Utils
  alias X402.Wallet

  @domain_type "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  @domain_type_no_version "EIP712Domain(string name,uint256 chainId,address verifyingContract)"

  @typedoc """
  An EIP-712 domain map with `:name`, `:version`, `:chain_id`, and
  `:verifying_contract` keys.

  Functions accepting a domain also take the wire-style keys
  (`"name"`, `"version"`, `"chainId"`, `"verifyingContract"`). Domains
  whose contracts declare no version (for example the canonical Permit2
  contract) omit the version key entirely; `domain_separator/1` then hashes
  the three-field `EIP712Domain` type.
  """
  @type domain :: %{
          optional(:version) => String.t(),
          name: String.t(),
          chain_id: non_neg_integer(),
          verifying_contract: String.t()
        }

  @type domain_error ::
          :invalid_requirements
          | {:missing_extra, String.t()}
          | :unsupported_network

  @type encode_error ::
          :missing_dependency
          | :invalid_address
          | :invalid_amount
          | :invalid_bytes32
          | :invalid_word
          | {:missing_field, String.t()}

  @doc since: "0.6.0"
  @doc """
  Derives the EIP-712 domain from v2 payment requirements.

  Per the exact-EVM scheme specification, `extra.name` and `extra.version`
  are required, the chain id comes from the CAIP-2 `network`, and the
  verifying contract is the `asset` address. Unlike `X402.EIP3009.domain/1`,
  the `extra.assetTransferMethod` is not restricted, so the same derivation
  serves EIP-3009, Permit2, and extension signing.

  ## Examples

      iex> X402.EIP712.domain(%{
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

      iex> X402.EIP712.domain(%{"network" => "eip155:84532", "asset" => "0xasset", "extra" => %{}})
      {:error, {:missing_extra, "name"}}
  """
  @spec domain(map()) :: {:ok, domain()} | {:error, domain_error()}
  def domain(requirements) when is_map(requirements) do
    extra = Utils.map_value(requirements, {"extra", :extra}) || %{}
    network = Utils.map_value(requirements, {"network", :network})
    asset = Utils.map_value(requirements, {"asset", :asset})

    with :ok <- ensure_map(extra),
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
  Computes the EIP-712 domain separator for a domain map.

  Returns `keccak256(typeHash || keccak256(name) || keccak256(version) ||
  chainId || verifyingContract)` as a 32-byte binary. When the domain has
  no version (absent or `nil` — for example the canonical Permit2
  contract), the version-less three-field `EIP712Domain` type is hashed
  instead, per EIP-712's rule that absent fields are dropped from the
  domain type.
  """
  @spec domain_separator(map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def domain_separator(domain) when is_map(domain) do
    with {:ok, keccak_module} <- keccak_module(),
         {:ok, name} <- fetch_field(domain, {"name", :name}),
         {:ok, chain_id} <- fetch_field(domain, {"chainId", :chain_id}),
         {:ok, contract} <- fetch_field(domain, {"verifyingContract", :verifying_contract}),
         {:ok, chain_id_word} <- encode_uint256(chain_id),
         {:ok, contract_word} <- encode_address(contract) do
      {type_hash, version_word} =
        case Utils.map_value(domain, {"version", :version}) do
          nil -> {keccak_module.hash_256(@domain_type_no_version), ""}
          version -> {keccak_module.hash_256(@domain_type), keccak_module.hash_256(version)}
        end

      {:ok,
       keccak_module.hash_256(
         type_hash <>
           keccak_module.hash_256(name) <>
           version_word <>
           chain_id_word <>
           contract_word
       )}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes an EIP-712 struct hash from a type string and encoded words.

  `type` is the full encoded type (for example
  `"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"`)
  and `words` the ABI-encoded 32-byte field values, in declaration order —
  see `encode_address/1`, `encode_uint256/1`, and `encode_bytes32/1`.
  """
  @spec hash_struct(String.t(), [<<_::256>>]) ::
          {:ok, <<_::256>>} | {:error, :missing_dependency | :invalid_word}
  def hash_struct(type, words) when is_binary(type) and is_list(words) do
    with {:ok, keccak_module} <- keccak_module(),
         :ok <- ensure_words(words) do
      {:ok, keccak_module.hash_256(IO.iodata_to_binary([keccak_module.hash_256(type) | words]))}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes the final EIP-712 digest for a domain and a struct hash.

  Returns `keccak256(0x19 0x01 || domainSeparator || structHash)` as a
  32-byte binary — the value a signer signs.
  """
  @spec digest(map(), <<_::256>>) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def digest(domain, struct_hash)
      when is_map(domain) and is_binary(struct_hash) and byte_size(struct_hash) == 32 do
    with {:ok, keccak_module} <- keccak_module(),
         {:ok, domain_separator} <- domain_separator(domain) do
      {:ok, keccak_module.hash_256(<<0x19, 0x01>> <> domain_separator <> struct_hash)}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Extracts the chain id from an `eip155:<chainId>` CAIP-2 network identifier.

  ## Examples

      iex> X402.EIP712.chain_id_from_caip2("eip155:84532")
      {:ok, 84532}

      iex> X402.EIP712.chain_id_from_caip2("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
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

      iex> {:ok, word} = X402.EIP712.encode_address("0x1111111111111111111111111111111111111111")
      iex> byte_size(word)
      32

      iex> X402.EIP712.encode_address("0x123")
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

      iex> X402.EIP712.encode_uint256(1)
      {:ok, <<1::unsigned-big-integer-size(256)>>}

      iex> X402.EIP712.encode_uint256("not a number")
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

      iex> {:ok, bytes} = X402.EIP712.encode_bytes32("0x" <> String.duplicate("ab", 32))
      iex> byte_size(bytes)
      32

      iex> X402.EIP712.encode_bytes32("0xdead")
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

  @doc since: "0.6.0"
  @doc """
  ABI-encodes a dynamic `bytes` value: a 32-byte length word followed by the
  bytes right-padded to a 32-byte boundary.

  Used to build calldata for functions taking `bytes` arguments
  (`isValidSignature`, the `bytes`-signature `transferWithAuthorization`
  variant, `aggregate3`).

  ## Examples

      iex> X402.EIP712.encode_dynamic_bytes(<<0xAB>>)
      <<1::unsigned-big-integer-size(256), 0xAB, 0::unsigned-big-integer-size(248)>>
  """
  @spec encode_dynamic_bytes(binary()) :: binary()
  def encode_dynamic_bytes(bytes) when is_binary(bytes) do
    <<byte_size(bytes)::unsigned-big-integer-size(256)>> <> pad_right(bytes)
  end

  @spec pad_right(binary()) :: binary()
  defp pad_right(bytes) do
    case rem(byte_size(bytes), 32) do
      0 -> bytes
      remainder -> bytes <> :binary.copy(<<0>>, 32 - remainder)
    end
  end

  # -- Optional dependency resolution ----------------------------------------
  #
  # The module is resolved at runtime via Module.concat so the library
  # compiles without ex_keccak (same pattern as X402.Facilitator.HTTP).

  @doc false
  @spec keccak_module() :: {:ok, module()} | {:error, :missing_dependency}
  def keccak_module do
    keccak_module = Module.concat(["ExKeccak"])

    case Code.ensure_loaded?(keccak_module) and function_exported?(keccak_module, :hash_256, 1) do
      true -> {:ok, keccak_module}
      false -> {:error, :missing_dependency}
    end
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

  @spec fetch_extra(map(), {String.t(), atom()}) ::
          {:ok, String.t()} | {:error, {:missing_extra, String.t()}}
  defp fetch_extra(extra, {string_key, _atom_key} = key) do
    case Utils.map_value(extra, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _value -> {:error, {:missing_extra, string_key}}
    end
  end

  @spec ensure_words([term()]) :: :ok | {:error, :invalid_word}
  defp ensure_words(words) do
    case Enum.all?(words, &(is_binary(&1) and byte_size(&1) == 32)) do
      true -> :ok
      false -> {:error, :invalid_word}
    end
  end

  @spec ensure_map(term()) :: :ok | {:error, :invalid_requirements}
  defp ensure_map(value) when is_map(value), do: :ok
  defp ensure_map(_value), do: {:error, :invalid_requirements}

  @spec ensure_binary(term()) :: :ok | {:error, :invalid_requirements}
  defp ensure_binary(value) when is_binary(value) and value != "", do: :ok
  defp ensure_binary(_value), do: {:error, :invalid_requirements}
end
