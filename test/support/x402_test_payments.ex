defmodule X402.TestPayments do
  @moduledoc false

  # Builds real x402 v2 exact-EVM payment payloads and requirements for
  # facilitator smoke tests, including EIP-3009 `TransferWithAuthorization`
  # signing (EIP-712).
  #
  # Configuration lives in the `X402.TestPayments.Config` struct. `config/1`
  # builds one from keyword defaults, while `from_env/1` is the single place
  # that reads the facilitator-agnostic `X402_*` environment variables — the
  # live smoke test is its only consumer. Facilitator credentials stay
  # facilitator-specific (e.g. `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` are
  # read by the CDP live test, not here).
  #
  # Receivers are never hardcoded, never the payer itself, and never the zero
  # address: USDC's `transferWithAuthorization` reverts on `to == address(0)`.
  # End-to-end payloads default to a fresh throwaway ("burner") wallet derived
  # from `receiver_key` so the payer never sends to itself. The zero address is
  # reserved for auth-only payloads, where a rejected payment is the point.
  #
  # The burner key lives in the `Config` so the receiver is resolved once and
  # `payload/2` and `requirements/1` agree even when called separately.

  alias ExKeccak
  alias ExSecp256k1

  @eip712_domain_type "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
  @transfer_with_authorization_type "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
  @zero_address "0x0000000000000000000000000000000000000000"

  defmodule Config do
    @moduledoc false

    @enforce_keys []
    defstruct payer_key: nil,
              receiver_key: nil,
              receiver: nil,
              network: "eip155:84532",
              contract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
              amount: "10000",
              resource: "https://x402.org/smoke-test",
              max_timeout: 300,
              token_name: "USDC",
              token_version: "2",
              settle?: false

    @type t :: %__MODULE__{
            payer_key: binary() | nil,
            receiver_key: binary() | nil,
            receiver: String.t() | nil,
            network: String.t(),
            contract: String.t(),
            amount: String.t(),
            resource: String.t(),
            max_timeout: pos_integer(),
            token_name: String.t(),
            token_version: String.t(),
            settle?: boolean()
          }
  end

  @doc """
  Returns a `Config` with default values.
  """
  @spec config() :: Config.t()
  def config, do: struct(Config, [])

  @doc """
  Returns a `Config` with the given keyword `overrides` applied on top of the
  defaults.
  """
  @spec config(keyword()) :: Config.t()
  def config(overrides) when is_list(overrides), do: struct(Config, overrides)

  @doc """
  Reads the facilitator-agnostic `X402_*` environment configuration.

  `env` is a function of arity 1 (defaults to `System.get_env/1`) so tests
  can inject a map of values. Only payment-relevant values are read here —
  facilitator credentials (`CDP_*`) belong to the facilitator-specific live
  test, and the receiver is never configured from the environment.

  When a payer key is present, a fresh burner `receiver_key` is generated so
  end-to-end payloads are never self-sends.
  """
  @spec from_env((String.t() -> String.t() | nil)) :: Config.t()
  def from_env(env \\ &System.get_env/1) do
    opts = [
      payer_key: env |> fetch("X402_PAYER_KEY") |> decode_hex(),
      network: fetch(env, "X402_NETWORK"),
      contract: fetch(env, "X402_CONTRACT"),
      resource: fetch(env, "X402_RESOURCE"),
      max_timeout: env |> fetch("X402_MAX_TIMEOUT") |> int(),
      token_name: fetch(env, "X402_TOKEN_NAME"),
      token_version: fetch(env, "X402_TOKEN_VERSION"),
      settle?: if(fetch(env, "X402_SETTLE") == "1", do: true, else: nil)
    ]

    config = struct(Config, Enum.reject(opts, fn {_key, value} -> is_nil(value) end))
    if is_binary(config.payer_key), do: %{config | receiver_key: burner_key()}, else: config
  end

  @doc """
  Returns the well-known EVM zero address, used as the `payTo` receiver for
  auth-only payloads where a rejected payment is the point.
  """
  @spec zero_address() :: String.t()
  def zero_address, do: @zero_address

  @doc """
  Returns a fresh 32-byte private key for a throwaway ("burner") wallet.

  The burner's derived address is the default `payTo` receiver for end-to-end
  payloads: it is never the payer itself, and — unlike the zero address — it is
  a valid USDC recipient (Circle's FiatToken reverts on `to == address(0)`).
  """
  @spec burner_key() :: binary()
  def burner_key, do: :crypto.strong_rand_bytes(32)

  @doc """
  Builds the v2 `paymentRequirements` map for the given config.
  """
  @spec requirements(Config.t()) :: map()
  def requirements(%Config{} = config) do
    %{
      "scheme" => "exact",
      "network" => config.network,
      "asset" => config.contract,
      "amount" => config.amount,
      "payTo" => receiver_for(config),
      "maxTimeoutSeconds" => config.max_timeout,
      "extra" => %{"name" => config.token_name, "version" => config.token_version}
    }
  end

  @doc """
  Builds a v2 `paymentPayload` map, signing the EIP-3009 authorization with
  `signer_key` (a 32-byte secp256k1 private key).

  The `from` address is always derived from `signer_key`; the `payTo`
  receiver is the configured one, then the burner wallet derived from
  `receiver_key`, falling back to the zero address.
  """
  @spec payload(Config.t(), binary()) :: map()
  def payload(%Config{} = config, signer_key) when is_binary(signer_key) do
    from = derive_address(signer_key)
    now = System.os_time(:second)

    authorization = %{
      from: from,
      to: receiver_for(config),
      value: config.amount,
      valid_after: Integer.to_string(now - 60),
      valid_before: Integer.to_string(now + config.max_timeout),
      nonce: random_nonce()
    }

    domain = %{
      name: config.token_name,
      version: config.token_version,
      chain_id: chain_id_from_caip2(config.network),
      verifying_contract: config.contract
    }

    %{
      "x402Version" => 2,
      "accepted" => requirements(config),
      "payload" => %{
        "signature" => sign_transfer_with_authorization(signer_key, domain, authorization),
        "authorization" => authorization_map(authorization)
      },
      "resource" => %{
        "url" => config.resource,
        "mimeType" => "application/json"
      }
    }
  end

  @doc """
  Builds a structurally-valid payment payload signed by a throwaway key.

  Used by the auth-only smoke test: the payload is well-formed enough that the
  facilitator rejects the *payment* rather than the JWT, proving
  authentication works without a funded payer wallet.
  """
  @spec auth_payload(Config.t()) :: map()
  def auth_payload(%Config{} = config), do: payload(config, :crypto.strong_rand_bytes(32))

  @doc """
  Signs an EIP-3009 `TransferWithAuthorization` message and returns the
  `0x`-prefixed `r || s || v` signature (65 bytes).
  """
  @spec sign_transfer_with_authorization(binary(), map(), map()) :: String.t()
  def sign_transfer_with_authorization(private_key, domain, authorization) do
    digest = eip712_digest(domain, authorization)
    {:ok, {signature, recovery_id}} = ExSecp256k1.sign_compact(digest, private_key)
    "0x" <> Base.encode16(signature <> <<recovery_id + 27>>, case: :lower)
  end

  @doc """
  Returns the EIP-712 digest (`keccak256(0x19 0x01 || domainSeparator || structHash)`).
  """
  @spec eip712_digest(map(), map()) :: binary()
  def eip712_digest(domain, authorization) do
    ExKeccak.hash_256(<<0x19, 0x01>> <> domain_separator(domain) <> struct_hash(authorization))
  end

  @doc """
  Derives the lowercase EVM address for a secp256k1 private key.
  """
  @spec derive_address(binary()) :: String.t()
  def derive_address(private_key) do
    {:ok, public_key} = ExSecp256k1.create_public_key(private_key)
    public_key_to_address(public_key)
  end

  @doc """
  Converts a 65-byte uncompressed (or 64-byte) secp256k1 public key to a
  lowercase `0x`-prefixed EVM address.
  """
  @spec public_key_to_address(binary()) :: String.t()
  def public_key_to_address(<<4, public_key::binary-size(64)>>), do: hash_to_address(public_key)
  def public_key_to_address(<<public_key::binary-size(64)>>), do: hash_to_address(public_key)

  @doc """
  Returns a fresh random 32-byte nonce as a `0x`-prefixed hex string.
  """
  @spec random_nonce() :: String.t()
  def random_nonce do
    "0x" <> Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
  end

  @doc """
  Extracts the chain id from an `eip155:<chainId>` CAIP-2 network identifier.
  """
  @spec chain_id_from_caip2(String.t()) :: non_neg_integer()
  def chain_id_from_caip2("eip155:" <> chain_id) when chain_id != "",
    do: String.to_integer(chain_id)

  def chain_id_from_caip2(other),
    do: raise(ArgumentError, "expected an eip155: CAIP-2 network, got: #{inspect(other)}")

  @doc """
  ABI-encodes an address into a 32-byte word.
  """
  @spec encode_address(String.t()) :: binary()
  def encode_address("0x" <> hex) do
    {:ok, address} = Base.decode16(String.upcase(hex), case: :mixed)

    case byte_size(address) do
      20 -> <<0::unsigned-big-integer-size(96), address::binary>>
      _ -> raise(ArgumentError, "invalid EVM address: 0x#{hex}")
    end
  end

  @doc """
  ABI-encodes a non-negative integer (or decimal string) into a 32-byte word.
  """
  @spec encode_uint256(integer() | String.t()) :: binary()
  def encode_uint256(integer) when is_integer(integer) and integer >= 0,
    do: <<integer::unsigned-big-integer-size(256)>>

  def encode_uint256(string) when is_binary(string),
    do: encode_uint256(String.to_integer(string))

  @doc """
  Decodes a `0x`-prefixed hex string into its raw bytes.
  """
  @spec encode_bytes32(String.t()) :: binary()
  def encode_bytes32("0x" <> hex) do
    {:ok, bytes} = Base.decode16(String.upcase(hex), case: :mixed)
    bytes
  end

  defp receiver_for(%Config{receiver: receiver}) when is_binary(receiver), do: receiver
  defp receiver_for(%Config{receiver_key: key}) when is_binary(key), do: derive_address(key)
  defp receiver_for(%Config{}), do: @zero_address

  defp domain_separator(domain) do
    ExKeccak.hash_256(
      ExKeccak.hash_256(@eip712_domain_type) <>
        ExKeccak.hash_256(domain.name) <>
        ExKeccak.hash_256(domain.version) <>
        encode_uint256(domain.chain_id) <>
        encode_address(domain.verifying_contract)
    )
  end

  defp struct_hash(authorization) do
    ExKeccak.hash_256(
      ExKeccak.hash_256(@transfer_with_authorization_type) <>
        encode_address(authorization.from) <>
        encode_address(authorization.to) <>
        encode_uint256(authorization.value) <>
        encode_uint256(authorization.valid_after) <>
        encode_uint256(authorization.valid_before) <>
        encode_bytes32(authorization.nonce)
    )
  end

  defp authorization_map(authorization) do
    %{
      "from" => authorization.from,
      "to" => authorization.to,
      "value" => authorization.value,
      "validAfter" => authorization.valid_after,
      "validBefore" => authorization.valid_before,
      "nonce" => authorization.nonce
    }
  end

  defp hash_to_address(public_key) do
    hash = ExKeccak.hash_256(public_key)
    address = binary_part(hash, byte_size(hash) - 20, 20)
    "0x" <> Base.encode16(address, case: :lower)
  end

  defp fetch(env, name) do
    case env.(name) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp decode_hex(nil), do: nil

  defp decode_hex("0x" <> hex), do: decode_hex(hex)

  defp decode_hex(hex) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} when byte_size(bytes) == 32 -> bytes
      _ -> nil
    end
  end

  defp int(nil), do: nil

  defp int(string) do
    case Integer.parse(string) do
      {integer, ""} when integer >= 0 -> integer
      _ -> nil
    end
  end
end
