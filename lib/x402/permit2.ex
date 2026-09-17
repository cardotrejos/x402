defmodule X402.Permit2 do
  @moduledoc """
  Permit2 `PermitWitnessTransferFrom` building, EIP-712 signing, and proxy
  settlement calldata for the x402 `exact` (Permit2 transfer method) and
  `upto` schemes on EVM networks.

  Implements the client half of both Permit2-based payment flows: building a
  Permit2 authorization from v2 payment requirements, computing its EIP-712
  digest against the canonical Permit2 domain, and signing it through the
  `X402.Signer` behaviour to produce the scheme `payload` map

      %{"signature" => "0x...", "permit2Authorization" => %{...}}

  carried inside a v2 `PaymentPayload` (see `X402.Client.build_payment/3`
  for the full envelope). It also ABI-encodes the `settle` calls the
  facilitator broadcasts to the x402 proxy contracts
  (`exact_settle_calldata/2`, `upto_settle_calldata/3`), shared by
  `X402.Verify.EVM`'s simulation and `X402.Facilitator.Engine`'s settlement.

  ## The authorizations

  In both flows the client signs a `PermitWitnessTransferFrom` message for
  the canonical [Permit2](https://github.com/Uniswap/permit2) contract
  (`#{"0x000000000022D473030F116dDEE9F6B43aC78BA3"}`) where
  `permitted.token` / `permitted.amount` are the requirements' `asset` and
  `amount`, and the `spender` is an x402 proxy contract deployed at the
  same address on every supported EVM chain via `CREATE2`. The proxy is the
  only party that can consume the permit, and it enforces the witness:

  * **exact** (`extra.assetTransferMethod` `"permit2"`) — the spender is
    the `x402ExactPermit2Proxy`
    (`#{"0x402085c248EeA27D92E8b30b2C58ed07f9E20001"}`) and the witness
    `Witness(address to,uint256 validAfter)` binds the requirements'
    `payTo`. The permitted amount is the exact amount settled.
  * **upto** — the spender is the `x402UptoPermit2Proxy`
    (`#{"0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"}`) and the witness
    `Witness(address to,address facilitator,uint256 validAfter)` binds
    `payTo` and the facilitator announced in `extra.facilitatorAddress`, so
    no other party can settle. The permitted amount is a **maximum**; the
    facilitator settles the actual usage up to that ceiling.

  The witness shape selects the typed-data variant: an authorization whose
  witness carries a `facilitator` field hashes as the upto type, otherwise
  as the exact type.

  The EIP-712 domain is the canonical Permit2 domain — name `"Permit2"`,
  the chain id from the CAIP-2 `network`, the Permit2 contract as the
  verifying contract, and **no version field**.

  Cryptographic operations require the optional `ex_secp256k1` and
  `ex_keccak` dependencies and return `{:error, :missing_dependency}` when
  they are unavailable; the library itself compiles without them.
  """

  alias X402.EIP712
  alias X402.Signer
  alias X402.Utils

  @permit2_address "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  @exact_proxy_address "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
  @upto_proxy_address "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"

  @token_permissions_type "TokenPermissions(address token,uint256 amount)"
  @exact_witness_type "Witness(address to,uint256 validAfter)"
  @upto_witness_type "Witness(address to,address facilitator,uint256 validAfter)"

  # EIP-712 encodeType: referenced struct types are appended in alphabetical
  # order (TokenPermissions before Witness).
  @permit_type_stub "PermitWitnessTransferFrom(TokenPermissions permitted,address spender," <>
                      "uint256 nonce,uint256 deadline,Witness witness)"
  @exact_permit_type @permit_type_stub <> @token_permissions_type <> @exact_witness_type
  @upto_permit_type @permit_type_stub <> @token_permissions_type <> @upto_witness_type

  # settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)
  @selector_exact_settle <<0x13, 0xCD, 0x3B, 0x53>>
  # settle(((address,uint256),uint256,uint256),uint256,address,(address,address,uint256),bytes)
  @selector_upto_settle <<0xFF, 0x11, 0xE7, 0xB4>>

  @base_typed_data_types %{
    "EIP712Domain" => [
      %{"name" => "name", "type" => "string"},
      %{"name" => "chainId", "type" => "uint256"},
      %{"name" => "verifyingContract", "type" => "address"}
    ],
    "PermitWitnessTransferFrom" => [
      %{"name" => "permitted", "type" => "TokenPermissions"},
      %{"name" => "spender", "type" => "address"},
      %{"name" => "nonce", "type" => "uint256"},
      %{"name" => "deadline", "type" => "uint256"},
      %{"name" => "witness", "type" => "Witness"}
    ],
    "TokenPermissions" => [
      %{"name" => "token", "type" => "address"},
      %{"name" => "amount", "type" => "uint256"}
    ]
  }

  @exact_typed_data_types Map.put(@base_typed_data_types, "Witness", [
                            %{"name" => "to", "type" => "address"},
                            %{"name" => "validAfter", "type" => "uint256"}
                          ])

  @upto_typed_data_types Map.put(@base_typed_data_types, "Witness", [
                           %{"name" => "to", "type" => "address"},
                           %{"name" => "facilitator", "type" => "address"},
                           %{"name" => "validAfter", "type" => "uint256"}
                         ])

  @typedoc """
  A Permit2 `PermitWitnessTransferFrom` authorization in wire shape.

  String keys `"from"`, `"permitted"` (`%{"token", "amount"}`),
  `"spender"`, `"nonce"`, `"deadline"`, and `"witness"`
  (`%{"to", "validAfter"}` for exact, `%{"to", "facilitator", "validAfter"}`
  for upto).
  """
  @type authorization :: %{optional(String.t()) => String.t() | map()}

  @typedoc "The scheme `payload` map for a signed Permit2 payment."
  @type payload :: %{optional(String.t()) => String.t() | authorization()}

  @type domain_error :: :invalid_requirements | :unsupported_network

  @type authorization_error ::
          :invalid_requirements | {:missing_extra, String.t()}

  @type encode_error :: EIP712.encode_error()

  @doc since: "0.6.0"
  @doc """
  Returns the canonical Permit2 contract address.

  ## Examples

      iex> X402.Permit2.permit2_address()
      "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  """
  @spec permit2_address() :: String.t()
  def permit2_address, do: @permit2_address

  @doc since: "0.8.0"
  @doc """
  Returns the `x402ExactPermit2Proxy` contract address — the spender of
  `exact` payments using the Permit2 transfer method.

  Deployed at the same address on every supported EVM chain via `CREATE2`.

  ## Examples

      iex> X402.Permit2.exact_proxy_address()
      "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
  """
  @spec exact_proxy_address() :: String.t()
  def exact_proxy_address, do: @exact_proxy_address

  @doc since: "0.6.0"
  @doc """
  Returns the `x402UptoPermit2Proxy` contract address — the upto spender.

  Deployed at the same address on every supported EVM chain via `CREATE2`.

  ## Examples

      iex> X402.Permit2.upto_proxy_address()
      "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"
  """
  @spec upto_proxy_address() :: String.t()
  def upto_proxy_address, do: @upto_proxy_address

  @doc since: "0.8.0"
  @doc """
  Signs the `exact` Permit2 scheme payload for the given requirements.

  Derives the canonical Permit2 domain from the requirements' `network`,
  builds a fresh authorization from the signer's address (`from`), the
  requirements' `asset`/`amount` (`permitted`), `payTo` (the witness), and
  `maxTimeoutSeconds` (the `deadline`), computes the EIP-712 digest, and
  signs it through `signer`.

  ## Examples

      {:ok, signer} = X402.Signer.LocalKey.new(private_key)

      {:ok, %{"signature" => _, "permit2Authorization" => _}} =
        X402.Permit2.sign_exact(
          %{
            "scheme" => "exact",
            "network" => "eip155:84532",
            "amount" => "10000",
            "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds" => 60,
            "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
          },
          signer
        )
  """
  @spec sign_exact(map(), Signer.t()) ::
          {:ok, payload()}
          | {:error, domain_error() | authorization_error() | encode_error() | term()}
  def sign_exact(requirements, signer) when is_map(requirements) do
    with {:ok, domain} <- domain(requirements),
         {:ok, from} <- Signer.address(signer),
         {:ok, authorization} <- build_exact_authorization(requirements, from),
         {:ok, signature} <- sign_authorization(signer, domain, authorization) do
      {:ok, %{"signature" => signature, "permit2Authorization" => authorization}}
    end
  end

  def sign_exact(_requirements, _signer), do: {:error, :invalid_requirements}

  @doc since: "0.6.0"
  @doc """
  Signs the `upto` Permit2 scheme payload for the given requirements.

  Derives the canonical Permit2 domain from the requirements' `network`,
  builds a fresh authorization from the signer's address (`from`), the
  requirements' `asset`/`amount` (`permitted`), `payTo` and
  `extra.facilitatorAddress` (the witness), and `maxTimeoutSeconds` (the
  `deadline`), computes the EIP-712 digest, and signs it through `signer`.

  Requirements without `extra.facilitatorAddress` return
  `{:error, {:missing_extra, "facilitatorAddress"}}` — the facilitator
  address is required so the witness can bind settlement to it.

  ## Examples

      {:ok, signer} = X402.Signer.LocalKey.new(private_key)

      {:ok, %{"signature" => _, "permit2Authorization" => _}} =
        X402.Permit2.sign_upto(
          %{
            "scheme" => "upto",
            "network" => "eip155:84532",
            "amount" => "5000000",
            "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds" => 300,
            "extra" => %{
              "name" => "USDC",
              "version" => "2",
              "facilitatorAddress" => "0x2222222222222222222222222222222222222222"
            }
          },
          signer
        )
  """
  @spec sign_upto(map(), Signer.t()) ::
          {:ok, payload()}
          | {:error, domain_error() | authorization_error() | encode_error() | term()}
  def sign_upto(requirements, signer) when is_map(requirements) do
    with {:ok, domain} <- domain(requirements),
         {:ok, from} <- Signer.address(signer),
         {:ok, authorization} <- build_upto_authorization(requirements, from),
         {:ok, signature} <- sign_authorization(signer, domain, authorization) do
      {:ok, %{"signature" => signature, "permit2Authorization" => authorization}}
    end
  end

  def sign_upto(_requirements, _signer), do: {:error, :invalid_requirements}

  @doc since: "0.8.0"
  @doc """
  Derives the canonical Permit2 EIP-712 domain from v2 payment requirements.

  The domain is `name: "Permit2"`, the chain id from the CAIP-2 `network`,
  and the canonical Permit2 contract as the verifying contract. Permit2
  declares no domain version, so the returned map carries no `:version`
  key and `X402.EIP712.domain_separator/1` hashes the three-field
  `EIP712Domain` type. The same domain serves the exact and upto flows.

  ## Examples

      iex> X402.Permit2.domain(%{"network" => "eip155:84532"})
      {:ok,
       %{
         name: "Permit2",
         chain_id: 84532,
         verifying_contract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
       }}

      iex> X402.Permit2.domain(%{"network" => "solana:mainnet"})
      {:error, :unsupported_network}
  """
  @spec domain(map()) :: {:ok, EIP712.domain()} | {:error, domain_error()}
  def domain(requirements) when is_map(requirements) do
    network = Utils.map_value(requirements, {"network", :network})

    with {:ok, chain_id} <- EIP712.chain_id_from_caip2(network) do
      {:ok, %{name: "Permit2", chain_id: chain_id, verifying_contract: @permit2_address}}
    end
  end

  def domain(_requirements), do: {:error, :invalid_requirements}

  @doc since: "0.6.0"
  @doc """
  Derives the canonical Permit2 EIP-712 domain — same as `domain/1`.

  ## Examples

      iex> X402.Permit2.upto_domain(%{"network" => "eip155:84532"})
      {:ok,
       %{
         name: "Permit2",
         chain_id: 84532,
         verifying_contract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
       }}

      iex> X402.Permit2.upto_domain(%{"network" => "solana:mainnet"})
      {:error, :unsupported_network}
  """
  @spec upto_domain(map()) :: {:ok, EIP712.domain()} | {:error, domain_error()}
  def upto_domain(requirements), do: domain(requirements)

  @doc since: "0.6.0"
  @doc """
  Fetches the facilitator address from the requirements' `extra`.

  The upto scheme requires `extra.facilitatorAddress` — the facilitator
  announces it via `GET /supported` (`X402.Facilitator.supported/1`) and
  the resource server forwards it in each upto requirements entry; the
  client binds it into the signed witness.

  ## Examples

      iex> X402.Permit2.facilitator_address(%{
      ...>   "extra" => %{"facilitatorAddress" => "0x2222222222222222222222222222222222222222"}
      ...> })
      {:ok, "0x2222222222222222222222222222222222222222"}

      iex> X402.Permit2.facilitator_address(%{"extra" => %{}})
      {:error, {:missing_extra, "facilitatorAddress"}}
  """
  @spec facilitator_address(map()) ::
          {:ok, String.t()} | {:error, {:missing_extra, String.t()}}
  def facilitator_address(requirements) when is_map(requirements) do
    extra = Utils.map_value(requirements, {"extra", :extra}) || %{}

    case is_map(extra) && Utils.map_value(extra, {"facilitatorAddress", :facilitatorAddress}) do
      address when is_binary(address) and address != "" -> {:ok, address}
      _missing -> {:error, {:missing_extra, "facilitatorAddress"}}
    end
  end

  def facilitator_address(_requirements), do: {:error, {:missing_extra, "facilitatorAddress"}}

  @doc since: "0.8.0"
  @doc """
  Builds an exact `PermitWitnessTransferFrom` authorization in wire shape.

  `permitted` carries the requirements' `asset` and exact `amount`; the
  `spender` is the `x402ExactPermit2Proxy`; the `nonce` is a fresh random
  uint256; the `deadline` is now plus `maxTimeoutSeconds`; and the witness
  binds `payTo` (`to`) with `validAfter` `"0"` (immediately valid),
  mirroring the reference SDKs.

  Field values are validated when the digest is computed, not here.
  """
  @spec build_exact_authorization(map(), String.t()) ::
          {:ok, authorization()} | {:error, :invalid_requirements}
  def build_exact_authorization(requirements, from)
      when is_map(requirements) and is_binary(from) do
    with {:ok, base} <- base_authorization(requirements, from, @exact_proxy_address) do
      pay_to = Utils.map_value(requirements, {"payTo", :payTo})
      {:ok, Map.put(base, "witness", %{"to" => pay_to, "validAfter" => "0"})}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Builds an upto `PermitWitnessTransferFrom` authorization in wire shape.

  `permitted` carries the requirements' `asset` and maximum `amount`; the
  `spender` is the `x402UptoPermit2Proxy`; the `nonce` is a fresh random
  uint256; the `deadline` is now plus `maxTimeoutSeconds`; and the witness
  binds `payTo` (`to`), `extra.facilitatorAddress` (`facilitator`), and
  `validAfter` `"0"` (immediately valid), mirroring the reference SDKs.

  Field values are validated when the digest is computed, not here.
  """
  @spec build_upto_authorization(map(), String.t()) ::
          {:ok, authorization()} | {:error, authorization_error()}
  def build_upto_authorization(requirements, from)
      when is_map(requirements) and is_binary(from) do
    with {:ok, facilitator} <- facilitator_address(requirements),
         {:ok, base} <- base_authorization(requirements, from, @upto_proxy_address) do
      pay_to = Utils.map_value(requirements, {"payTo", :payTo})

      {:ok,
       Map.put(base, "witness", %{
         "to" => pay_to,
         "facilitator" => facilitator,
         "validAfter" => "0"
       })}
    end
  end

  @spec base_authorization(map(), String.t(), String.t()) ::
          {:ok, map()} | {:error, :invalid_requirements}
  defp base_authorization(requirements, from, spender) do
    amount = Utils.map_value(requirements, {"amount", :amount})
    asset = Utils.map_value(requirements, {"asset", :asset})
    pay_to = Utils.map_value(requirements, {"payTo", :payTo})
    max_timeout = Utils.map_value(requirements, {"maxTimeoutSeconds", :maxTimeoutSeconds})

    if is_binary(amount) and is_binary(asset) and is_binary(pay_to) and
         is_integer(max_timeout) and max_timeout > 0 do
      {:ok,
       %{
         "from" => from,
         "permitted" => %{"token" => asset, "amount" => amount},
         "spender" => spender,
         "nonce" => random_nonce(),
         "deadline" => Integer.to_string(System.os_time(:second) + max_timeout)
       }}
    else
      {:error, :invalid_requirements}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Signs an authorization's EIP-712 digest with a signer.

  The witness shape selects the exact or upto typed data (see the module
  documentation). Returns the `0x`-prefixed 65-byte `r || s || v`
  signature.
  """
  @spec sign_authorization(Signer.t(), map(), map()) ::
          {:ok, String.t()} | {:error, encode_error() | term()}
  def sign_authorization(signer, domain, authorization)
      when is_map(domain) and is_map(authorization) do
    with {:ok, digest} <- digest(domain, authorization),
         {:ok, signature} <- Signer.sign_eip712(signer, digest, typed_data(domain, authorization)) do
      {:ok, "0x" <> Base.encode16(signature, case: :lower)}
    end
  end

  @doc since: "0.8.0"
  @doc """
  Computes the EIP-712 digest of a `PermitWitnessTransferFrom`.

  Returns `keccak256(0x19 0x01 || domainSeparator || structHash)` as a
  32-byte binary — the value the client signs and the value to recover
  the payer address from (`X402.EIP3009.recover_signer/2`). The witness
  shape selects the type string: a witness with a `facilitator` field
  hashes as the upto `Witness(address to,address facilitator,uint256
  validAfter)`, otherwise as the exact `Witness(address to,uint256
  validAfter)`. `domain` and `authorization` accept both the internal
  snake-case atom keys and the wire-style string keys; the authorization's
  `from` is not part of the signed struct (Permit2 recovers the owner from
  the signature).
  """
  @spec digest(map(), map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def digest(domain, authorization) when is_map(domain) and is_map(authorization) do
    with {:ok, struct_hash} <- struct_hash(authorization) do
      EIP712.digest(domain, struct_hash)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes the EIP-712 digest of a `PermitWitnessTransferFrom` — same as
  `digest/2`.
  """
  @spec upto_digest(map(), map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def upto_digest(domain, authorization), do: digest(domain, authorization)

  @doc since: "0.6.0"
  @doc """
  Returns a fresh random uint256 nonce as a decimal string.

  Permit2 uses unordered nonces; the reference SDKs draw 32 random bytes
  per authorization, making collisions negligible.

  ## Examples

      iex> nonce = X402.Permit2.random_nonce()
      iex> String.match?(nonce, ~r/^[0-9]+$/)
      true
  """
  @spec random_nonce() :: String.t()
  def random_nonce do
    32 |> :crypto.strong_rand_bytes() |> :binary.decode_unsigned() |> Integer.to_string()
  end

  @doc since: "0.8.0"
  @doc group: :settlement
  @doc """
  Builds the `x402ExactPermit2Proxy.settle` calldata for an exact
  authorization and its raw (inner) signature bytes.

  Encodes `settle(PermitTransferFrom permit, address owner, Witness witness,
  bytes signature)` (selector `0x13cd3b53`) where `permit` is
  `((permitted.token, permitted.amount), nonce, deadline)`, `owner` is the
  authorization's `from`, and the witness is `(witness.to,
  witness.validAfter)`. The proxy forwards the call to Permit2's
  `permitWitnessTransferFrom` with `permitted.amount` as the requested
  amount. Shared by `X402.Verify.EVM`'s `eth_call` simulation and
  `X402.Facilitator.Engine`'s settlement transaction.

  ## Examples

      iex> asset = "0x2222222222222222222222222222222222222222"
      iex> authorization = %{
      ...>   "from" => "0x1111111111111111111111111111111111111111",
      ...>   "permitted" => %{"token" => asset, "amount" => "10000"},
      ...>   "spender" => "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
      ...>   "nonce" => "7",
      ...>   "deadline" => "99999999999",
      ...>   "witness" => %{"to" => "0x3333333333333333333333333333333333333333", "validAfter" => "0"}
      ...> }
      iex> {:ok, calldata} = X402.Permit2.exact_settle_calldata(authorization, <<1::520>>)
      iex> {binary_part(calldata, 0, 4), byte_size(calldata)}
      {<<0x13, 0xCD, 0x3B, 0x53>>, 4 + 8 * 32 + 32 + 96}

      iex> X402.Permit2.exact_settle_calldata(%{}, <<1::520>>)
      {:error, {:missing_field, "permitted"}}
  """
  @spec exact_settle_calldata(map(), binary()) ::
          {:ok, binary()} | {:error, encode_error() | :invalid_signature}
  def exact_settle_calldata(authorization, signature)
      when is_map(authorization) and is_binary(signature) do
    with {:ok, permit_words} <- permit_words(authorization),
         {:ok, owner_word} <- owner_word(authorization),
         {:ok, witness} <- fetch_field(authorization, {"witness", :witness}),
         {:ok, to_word} <- witness_address(witness, {"to", :to}),
         {:ok, valid_after_word} <- witness_uint(witness),
         :ok <- ensure_signature(signature) do
      head = permit_words <> owner_word <> to_word <> valid_after_word
      {:ok, @selector_exact_settle <> head <> dynamic_tail(head, signature)}
    end
  end

  @doc since: "0.8.0"
  @doc group: :settlement
  @doc """
  Builds the `x402UptoPermit2Proxy.settle` calldata for an upto
  authorization, the amount to settle, and the raw (inner) signature bytes.

  Encodes `settle(PermitTransferFrom permit, uint256 amount, address owner,
  Witness witness, bytes signature)` (selector `0xff11e7b4`) where the
  witness is `(witness.to, witness.facilitator, witness.validAfter)` and
  `amount` is the actual settlement amount — at most `permitted.amount`,
  which the proxy enforces (`AmountExceedsPermitted`). The proxy also
  requires `msg.sender` to equal `witness.facilitator`
  (`UnauthorizedFacilitator`).

  ## Examples

      iex> asset = "0x2222222222222222222222222222222222222222"
      iex> authorization = %{
      ...>   "from" => "0x1111111111111111111111111111111111111111",
      ...>   "permitted" => %{"token" => asset, "amount" => "10000"},
      ...>   "spender" => "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002",
      ...>   "nonce" => "7",
      ...>   "deadline" => "99999999999",
      ...>   "witness" => %{
      ...>     "to" => "0x3333333333333333333333333333333333333333",
      ...>     "facilitator" => "0x4444444444444444444444444444444444444444",
      ...>     "validAfter" => "0"
      ...>   }
      ...> }
      iex> {:ok, calldata} = X402.Permit2.upto_settle_calldata(authorization, "9000", <<1::520>>)
      iex> {binary_part(calldata, 0, 4), byte_size(calldata)}
      {<<0xFF, 0x11, 0xE7, 0xB4>>, 4 + 10 * 32 + 32 + 96}

      iex> X402.Permit2.upto_settle_calldata(%{}, "1", <<1::520>>)
      {:error, {:missing_field, "permitted"}}
  """
  @spec upto_settle_calldata(map(), String.t() | non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, encode_error() | :invalid_signature}
  def upto_settle_calldata(authorization, amount, signature)
      when is_map(authorization) and is_binary(signature) do
    with {:ok, permit_words} <- permit_words(authorization),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, owner_word} <- owner_word(authorization),
         {:ok, witness} <- fetch_field(authorization, {"witness", :witness}),
         {:ok, to_word} <- witness_address(witness, {"to", :to}),
         {:ok, facilitator_word} <- witness_address(witness, {"facilitator", :facilitator}),
         {:ok, valid_after_word} <- witness_uint(witness),
         :ok <- ensure_signature(signature) do
      head =
        permit_words <>
          amount_word <> owner_word <> to_word <> facilitator_word <> valid_after_word

      {:ok, @selector_upto_settle <> head <> dynamic_tail(head, signature)}
    end
  end

  # -- ABI encoding -----------------------------------------------------------

  # PermitTransferFrom is a fully static tuple: ((token, amount), nonce,
  # deadline) encodes inline as four words.
  @spec permit_words(map()) :: {:ok, binary()} | {:error, encode_error()}
  defp permit_words(authorization) do
    with {:ok, permitted} <- fetch_field(authorization, {"permitted", :permitted}),
         {:ok, {token_word, amount_word}} <- token_permission_words(permitted),
         {:ok, nonce} <- fetch_field(authorization, {"nonce", :nonce}),
         {:ok, deadline} <- fetch_field(authorization, {"deadline", :deadline}),
         {:ok, nonce_word} <- EIP712.encode_uint256(nonce),
         {:ok, deadline_word} <- EIP712.encode_uint256(deadline) do
      {:ok, token_word <> amount_word <> nonce_word <> deadline_word}
    end
  end

  @spec owner_word(map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defp owner_word(authorization) do
    with {:ok, from} <- fetch_field(authorization, {"from", :from}) do
      EIP712.encode_address(from)
    end
  end

  @spec witness_address(term(), {String.t(), atom()}) ::
          {:ok, <<_::256>>} | {:error, encode_error()}
  defp witness_address(witness, key) when is_map(witness) do
    with {:ok, address} <- fetch_field(witness, key) do
      EIP712.encode_address(address)
    end
  end

  defp witness_address(_witness, _key), do: {:error, {:missing_field, "witness"}}

  @spec witness_uint(map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defp witness_uint(witness) do
    with {:ok, valid_after} <- fetch_field(witness, {"validAfter", :validAfter}) do
      EIP712.encode_uint256(valid_after)
    end
  end

  @spec ensure_signature(binary()) :: :ok | {:error, :invalid_signature}
  defp ensure_signature(signature) when byte_size(signature) > 0, do: :ok
  defp ensure_signature(_signature), do: {:error, :invalid_signature}

  # The single dynamic argument (bytes signature) sits last: its head word
  # is the offset of the tail, which begins right after the head.
  @spec dynamic_tail(binary(), binary()) :: binary()
  defp dynamic_tail(head, signature) do
    offset = byte_size(head) + 32
    <<offset::unsigned-big-integer-size(256)>> <> EIP712.encode_dynamic_bytes(signature)
  end

  # -- Struct hashing ---------------------------------------------------------

  @spec struct_hash(map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defp struct_hash(authorization) do
    with {:ok, permitted} <- fetch_field(authorization, {"permitted", :permitted}),
         {:ok, spender} <- fetch_field(authorization, {"spender", :spender}),
         {:ok, nonce} <- fetch_field(authorization, {"nonce", :nonce}),
         {:ok, deadline} <- fetch_field(authorization, {"deadline", :deadline}),
         {:ok, witness} <- fetch_field(authorization, {"witness", :witness}),
         {:ok, permitted_hash} <- token_permissions_hash(permitted),
         {:ok, {permit_type, witness_hash}} <- witness_hash(witness),
         {:ok, spender_word} <- EIP712.encode_address(spender),
         {:ok, nonce_word} <- EIP712.encode_uint256(nonce),
         {:ok, deadline_word} <- EIP712.encode_uint256(deadline) do
      EIP712.hash_struct(permit_type, [
        permitted_hash,
        spender_word,
        nonce_word,
        deadline_word,
        witness_hash
      ])
    end
  end

  @spec token_permission_words(term()) ::
          {:ok, {<<_::256>>, <<_::256>>}} | {:error, encode_error()}
  defp token_permission_words(permitted) when is_map(permitted) do
    with {:ok, token} <- fetch_field(permitted, {"token", :token}),
         {:ok, amount} <- fetch_field(permitted, {"amount", :amount}),
         {:ok, token_word} <- EIP712.encode_address(token),
         {:ok, amount_word} <- EIP712.encode_uint256(amount) do
      {:ok, {token_word, amount_word}}
    end
  end

  defp token_permission_words(_permitted), do: {:error, {:missing_field, "permitted"}}

  @spec token_permissions_hash(term()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defp token_permissions_hash(permitted) do
    with {:ok, {token_word, amount_word}} <- token_permission_words(permitted) do
      EIP712.hash_struct(@token_permissions_type, [token_word, amount_word])
    end
  end

  # The witness shape selects the type string and therefore the full
  # PermitWitnessTransferFrom encodeType.
  @spec witness_hash(term()) :: {:ok, {String.t(), <<_::256>>}} | {:error, encode_error()}
  defp witness_hash(witness) when is_map(witness) do
    case upto_witness?(witness) do
      true -> upto_witness_hash(witness)
      false -> exact_witness_hash(witness)
    end
  end

  defp witness_hash(_witness), do: {:error, {:missing_field, "witness"}}

  @spec upto_witness?(map()) :: boolean()
  defp upto_witness?(witness),
    do: not is_nil(Utils.map_value(witness, {"facilitator", :facilitator}))

  @spec exact_witness_hash(map()) :: {:ok, {String.t(), <<_::256>>}} | {:error, encode_error()}
  defp exact_witness_hash(witness) do
    with {:ok, to_word} <- witness_address(witness, {"to", :to}),
         {:ok, valid_after_word} <- witness_uint(witness),
         {:ok, hash} <- EIP712.hash_struct(@exact_witness_type, [to_word, valid_after_word]) do
      {:ok, {@exact_permit_type, hash}}
    end
  end

  @spec upto_witness_hash(map()) :: {:ok, {String.t(), <<_::256>>}} | {:error, encode_error()}
  defp upto_witness_hash(witness) do
    with {:ok, to_word} <- witness_address(witness, {"to", :to}),
         {:ok, facilitator_word} <- witness_address(witness, {"facilitator", :facilitator}),
         {:ok, valid_after_word} <- witness_uint(witness),
         {:ok, hash} <-
           EIP712.hash_struct(@upto_witness_type, [to_word, facilitator_word, valid_after_word]) do
      {:ok, {@upto_permit_type, hash}}
    end
  end

  @spec typed_data(map(), map()) :: Signer.typed_data()
  defp typed_data(domain, authorization) do
    witness = Utils.map_value(authorization, {"witness", :witness})

    types =
      case is_map(witness) and upto_witness?(witness) do
        true -> @upto_typed_data_types
        false -> @exact_typed_data_types
      end

    %{
      "types" => types,
      "primaryType" => "PermitWitnessTransferFrom",
      "domain" => %{
        "name" => Utils.map_value(domain, {"name", :name}),
        "chainId" => Utils.map_value(domain, {"chainId", :chain_id}),
        "verifyingContract" => Utils.map_value(domain, {"verifyingContract", :verifying_contract})
      },
      "message" => %{
        "permitted" => Utils.map_value(authorization, {"permitted", :permitted}),
        "spender" => Utils.map_value(authorization, {"spender", :spender}),
        "nonce" => Utils.map_value(authorization, {"nonce", :nonce}),
        "deadline" => Utils.map_value(authorization, {"deadline", :deadline}),
        "witness" => witness
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
end
