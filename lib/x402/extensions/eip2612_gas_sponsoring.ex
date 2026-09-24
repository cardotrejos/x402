defmodule X402.Extensions.EIP2612GasSponsoring do
  @moduledoc """
  Builds, signs, and validates the `eip2612GasSponsoring` extension.

  The extension enables a gasless approval flow for tokens that implement
  [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612): instead of paying gas
  for an `approve` transaction, the client signs an off-chain EIP-2612
  `Permit` authorizing the canonical
  [Permit2](https://github.com/Uniswap/permit2) contract as spender, and the
  facilitator submits it on-chain (paying the gas) via
  `x402Permit2Proxy.settleWithPermit`.

  Server side, `build_extension/0` declares support under
  `extensions.eip2612GasSponsoring` in a `PAYMENT-REQUIRED` response, and
  `extract_info/1` / `validate_info/1` check the client-populated data echoed
  back in a `PaymentPayload`.

  Client side, `sign_permit/3` signs the `Permit` typed data for a selected
  payment requirements entry through the `X402.Signer` behaviour, and
  `put_info/2` attaches the resulting info to a payload's extensions.
  `enricher/2` packages both for `X402.Client.build_payment/3`:

      {:ok, payload} =
        X402.Client.build_payment(payment_required, signer,
          extensions: [
            X402.Extensions.EIP2612GasSponsoring.enricher(signer, nonce: "0")
          ]
        )

  The library has no chain access, so the owner's current EIP-2612 `:nonce`
  (read from the token contract's `nonces(owner)`) must be supplied by the
  caller.

  See the
  [eip2612GasSponsoring extension spec](https://github.com/x402-foundation/x402/blob/main/specs/extensions/eip2612_gas_sponsoring.md).
  """

  alias X402.EIP712
  alias X402.Signer
  alias X402.Utils
  alias X402.Wallet

  @extension_key "eip2612GasSponsoring"
  @permit2_address "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  @info_version "1"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"

  @permit_type "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"

  @typed_data_types %{
    "EIP712Domain" => [
      %{"name" => "name", "type" => "string"},
      %{"name" => "version", "type" => "string"},
      %{"name" => "chainId", "type" => "uint256"},
      %{"name" => "verifyingContract", "type" => "address"}
    ],
    "Permit" => [
      %{"name" => "owner", "type" => "address"},
      %{"name" => "spender", "type" => "address"},
      %{"name" => "value", "type" => "uint256"},
      %{"name" => "nonce", "type" => "uint256"},
      %{"name" => "deadline", "type" => "uint256"}
    ]
  }

  @required_fields ~w(from asset spender amount nonce deadline signature version)

  @sign_opts_schema [
    nonce: [
      type: {:or, [:non_neg_integer, :string]},
      required: true,
      doc: """
      The owner's current EIP-2612 nonce on the token contract (the value of
      `nonces(owner)`), as an integer or decimal string. The library has no
      chain access, so the caller must read it.
      """
    ],
    deadline: [
      type: {:or, [:non_neg_integer, :string]},
      doc: """
      Unix timestamp at which the permit signature expires. Defaults to the
      current time plus the requirements' `maxTimeoutSeconds`.
      """
    ],
    amount: [
      type: {:or, [:non_neg_integer, :string]},
      doc: """
      Approval amount in atomic units. Defaults to the requirements'
      `amount` — `x402Permit2Proxy.settleWithPermit` enforces that the
      permit value matches the Permit2 permitted amount exactly.
      """
    ],
    spender: [
      type: :string,
      doc: "The approved spender. Defaults to the canonical Permit2 contract."
    ]
  ]

  @typedoc "A built `extensions.eip2612GasSponsoring` declaration (`info` + `schema`)."
  @type t :: %{binary() => map()}

  @typedoc """
  Client-populated extension info in wire shape: string keys `"from"`,
  `"asset"`, `"spender"`, `"amount"`, `"nonce"`, `"deadline"`,
  `"signature"`, and `"version"`.
  """
  @type info :: %{optional(binary()) => binary()}

  @type info_error ::
          :extension_missing
          | {:missing_info_field, String.t()}
          | {:invalid_info_field, String.t()}

  @type sign_error ::
          :invalid_nonce
          | :invalid_deadline
          | :invalid_amount
          | :invalid_requirements
          | EIP712.domain_error()
          | EIP712.encode_error()
          | term()

  @doc since: "0.6.0"
  @doc """
  Returns the extension key, `"eip2612GasSponsoring"`.

  ## Examples

      iex> X402.Extensions.EIP2612GasSponsoring.key()
      "eip2612GasSponsoring"
  """
  @spec key() :: String.t()
  def key, do: @extension_key

  @doc since: "0.6.0"
  @doc """
  Returns the canonical Permit2 contract address — the default spender.

  ## Examples

      iex> X402.Extensions.EIP2612GasSponsoring.permit2_address()
      "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  """
  @spec permit2_address() :: String.t()
  def permit2_address, do: @permit2_address

  @doc since: "0.6.0"
  @doc """
  Builds the server-side extension declaration (`info` + `schema`).

  Resource servers advertise support by placing the declaration under
  `extensions.eip2612GasSponsoring` in a `PAYMENT-REQUIRED` response; the
  client populates the actual permit data.

  ## Examples

      iex> ext = X402.Extensions.EIP2612GasSponsoring.build_extension()
      iex> ext["info"]["version"]
      "1"
      iex> ext["schema"]["required"]
      ["from", "asset", "spender", "amount", "nonce", "deadline", "signature", "version"]
  """
  @spec build_extension() :: t()
  def build_extension do
    %{
      "info" => %{
        "description" =>
          "The facilitator accepts EIP-2612 gasless Permit to `Permit2` canonical contract.",
        "version" => @info_version
      },
      "schema" => schema()
    }
  end

  @doc since: "0.6.0"
  @doc """
  Returns the JSON Schema (Draft 2020-12) for the client-populated info.
  """
  @spec schema() :: map()
  def schema do
    %{
      "$schema" => @schema_uri,
      "type" => "object",
      "properties" => %{
        "from" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]{40}$",
          "description" => "The address of the sender."
        },
        "asset" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]{40}$",
          "description" => "The address of the ERC-20 token contract."
        },
        "spender" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]{40}$",
          "description" => "The address of the spender (Canonical Permit2)."
        },
        "amount" => %{
          "type" => "string",
          "pattern" => "^[0-9]+$",
          "description" => "The amount to approve (uint256). Typically MaxUint."
        },
        "nonce" => %{
          "type" => "string",
          "pattern" => "^[0-9]+$",
          "description" => "The current nonce of the sender."
        },
        "deadline" => %{
          "type" => "string",
          "pattern" => "^[0-9]+$",
          "description" => "The timestamp at which the signature expires."
        },
        "signature" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]+$",
          "description" => "The 65-byte concatenated signature (r, s, v) as a hex string."
        },
        "version" => %{
          "type" => "string",
          "pattern" => "^[0-9]+(\\.[0-9]+)*$",
          "description" => "Schema version identifier."
        }
      },
      "required" => @required_fields
    }
  end

  @doc since: "0.6.0"
  @doc """
  Signs an EIP-2612 `Permit` for a payment requirements entry.

  The EIP-712 domain is the token's: `extra.name` / `extra.version`, the
  chain id from the CAIP-2 `network`, and the `asset` contract as verifying
  contract. The permit authorizes `:spender` (canonical Permit2 by default)
  to spend `:amount` (the requirements' `amount` by default) of the owner's
  tokens until `:deadline`.

  Returns the client-populated extension info in wire shape, ready for
  `put_info/2`.

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}

  ## Examples

      {:ok, signer} = X402.Signer.LocalKey.new(private_key)

      {:ok, %{"signature" => _, "spender" => _} = info} =
        X402.Extensions.EIP2612GasSponsoring.sign_permit(
          %{
            "scheme" => "exact",
            "network" => "eip155:84532",
            "amount" => "10000",
            "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds" => 60,
            "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
          },
          signer,
          nonce: "0"
        )
  """
  @spec sign_permit(map(), Signer.t(), keyword()) :: {:ok, info()} | {:error, sign_error()}
  def sign_permit(requirements, signer, opts) when is_map(requirements) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)

    with {:ok, domain} <- EIP712.domain(requirements),
         {:ok, owner} <- Signer.address(signer),
         {:ok, nonce} <- normalize_uint(Keyword.fetch!(opts, :nonce), :invalid_nonce),
         {:ok, deadline} <- resolve_deadline(requirements, opts),
         {:ok, amount} <- resolve_amount(requirements, opts) do
      spender = Keyword.get(opts, :spender, @permit2_address)

      permit = %{
        "owner" => owner,
        "spender" => spender,
        "value" => amount,
        "nonce" => nonce,
        "deadline" => deadline
      }

      with {:ok, digest} <- permit_digest(domain, permit),
           {:ok, signature} <- Signer.sign_eip712(signer, digest, typed_data(domain, permit)) do
        {:ok,
         %{
           "from" => owner,
           "asset" => domain.verifying_contract,
           "spender" => spender,
           "amount" => amount,
           "nonce" => nonce,
           "deadline" => deadline,
           "signature" => "0x" <> Base.encode16(signature, case: :lower),
           "version" => @info_version
         }}
      end
    end
  end

  @doc since: "0.6.0"
  @doc """
  Computes the EIP-712 digest of an EIP-2612 `Permit` message.

  `domain` is the token's EIP-712 domain (see `X402.EIP712.domain/1`) and
  `permit` a map with `"owner"`, `"spender"`, `"value"`, `"nonce"`, and
  `"deadline"` keys (snake-case atom keys are also accepted). Useful for
  verifying a signed permit with `X402.EIP3009.recover_signer/2`.
  """
  @spec permit_digest(map(), map()) :: {:ok, <<_::256>>} | {:error, EIP712.encode_error()}
  def permit_digest(domain, permit) when is_map(domain) and is_map(permit) do
    with {:ok, owner} <- fetch_field(permit, {"owner", :owner}),
         {:ok, spender} <- fetch_field(permit, {"spender", :spender}),
         {:ok, value} <- fetch_field(permit, {"value", :value}),
         {:ok, nonce} <- fetch_field(permit, {"nonce", :nonce}),
         {:ok, deadline} <- fetch_field(permit, {"deadline", :deadline}),
         {:ok, owner_word} <- EIP712.encode_address(owner),
         {:ok, spender_word} <- EIP712.encode_address(spender),
         {:ok, value_word} <- EIP712.encode_uint256(value),
         {:ok, nonce_word} <- EIP712.encode_uint256(nonce),
         {:ok, deadline_word} <- EIP712.encode_uint256(deadline),
         {:ok, struct_hash} <-
           EIP712.hash_struct(@permit_type, [
             owner_word,
             spender_word,
             value_word,
             nonce_word,
             deadline_word
           ]) do
      EIP712.digest(domain, struct_hash)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Attaches client-populated info to a payload's extensions.

  Places the info under `extensions.eip2612GasSponsoring.info`, following
  the append-only rule: when the payload already echoes the server's
  declaration, server-declared info fields are preserved (they win over
  client values) and the declared `schema` is kept; the client's fields are
  added alongside them.

  ## Examples

      iex> info = %{"from" => "0x1111111111111111111111111111111111111111"}
      iex> payload = X402.Extensions.EIP2612GasSponsoring.put_info(%{"payload" => %{}}, info)
      iex> payload["extensions"]["eip2612GasSponsoring"]["info"]["from"]
      "0x1111111111111111111111111111111111111111"
  """
  @spec put_info(map(), info()) :: map()
  def put_info(payload, info) when is_map(payload) and is_map(info) do
    extensions = ensure_extensions(Utils.map_value(payload, {"extensions", :extensions}))
    declaration = ensure_declaration(Map.get(extensions, @extension_key))
    server_info = ensure_declaration(Map.get(declaration, "info"))
    merged = Map.put(declaration, "info", Map.merge(info, server_info))
    Map.put(payload, "extensions", Map.put(extensions, @extension_key, merged))
  end

  @doc since: "0.6.0"
  @doc """
  Extracts the client-populated info from a `PaymentPayload` map.

  Returns the info when the extension is present and every required field
  is populated. Field formats are not checked here — see `validate_info/1`.

  ## Examples

      iex> X402.Extensions.EIP2612GasSponsoring.extract_info(%{"payload" => %{}})
      {:error, :extension_missing}
  """
  @spec extract_info(map()) :: {:ok, info()} | {:error, info_error()}
  def extract_info(payload) when is_map(payload) do
    extensions = Utils.map_value(payload, {"extensions", :extensions})

    with {:ok, info} <- fetch_info(extensions),
         :ok <- ensure_fields_present(info) do
      {:ok, info}
    end
  end

  def extract_info(_payload), do: {:error, :extension_missing}

  @doc since: "0.6.0"
  @doc """
  Validates the format of client-populated info.

  Checks that addresses match `^0x[a-fA-F0-9]{40}$`, that `amount`,
  `nonce`, and `deadline` are decimal strings, that `signature` is a
  `0x`-prefixed hex string, and that `version` is a dotted numeric version.

  ## Examples

      iex> X402.Extensions.EIP2612GasSponsoring.validate_info(%{
      ...>   "from" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "spender" => "0x000000000022D473030F116dDEE9F6B43aC78BA3",
      ...>   "amount" => "10000",
      ...>   "nonce" => "0",
      ...>   "deadline" => "1740672154",
      ...>   "signature" => "0xabcdef",
      ...>   "version" => "1"
      ...> })
      :ok

      iex> X402.Extensions.EIP2612GasSponsoring.validate_info(%{"from" => "0x123"})
      {:error, {:invalid_info_field, "from"}}
  """
  @spec validate_info(term()) :: :ok | {:error, info_error()}
  def validate_info(info) when is_map(info) do
    Enum.reduce_while(@required_fields, :ok, fn field, :ok ->
      case Map.get(info, field) do
        nil -> {:halt, {:error, {:missing_info_field, field}}}
        value -> validate_field(field, value)
      end
    end)
  end

  def validate_info(_info), do: {:error, :extension_missing}

  @doc since: "0.6.0"
  @doc """
  Returns an enricher for `X402.Client.build_payment/3`'s `:extensions`.

  The enricher signs an EIP-2612 permit for the payload's accepted
  requirements and attaches it via `put_info/2` — but only when the server
  advertised `eip2612GasSponsoring` in the `PaymentRequired` extensions;
  otherwise the payload passes through unchanged.

  Takes the same options as `sign_permit/3` (`:nonce` is required).
  """
  @spec enricher(Signer.t(), keyword()) ::
          (map(), map() | nil -> {:ok, map()} | {:error, sign_error()})
  def enricher(signer, opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)
    fn payload, payment_required -> enrich(payload, payment_required, signer, opts) end
  end

  # -- Enrichment -------------------------------------------------------------

  @spec enrich(map(), map() | nil, Signer.t(), keyword()) ::
          {:ok, map()} | {:error, sign_error()}
  defp enrich(payload, payment_required, signer, opts) do
    if advertised?(payment_required) do
      requirements = Utils.map_value(payload, {"accepted", :accepted}) || %{}

      with {:ok, info} <- sign_permit(requirements, signer, opts) do
        {:ok, put_info(payload, info)}
      end
    else
      {:ok, payload}
    end
  end

  @spec advertised?(term()) :: boolean()
  defp advertised?(payment_required) when is_map(payment_required) do
    case Utils.map_value(payment_required, {"extensions", :extensions}) do
      extensions when is_map(extensions) -> Map.has_key?(extensions, @extension_key)
      _extensions -> false
    end
  end

  defp advertised?(_payment_required), do: false

  # -- Signing helpers --------------------------------------------------------

  @spec typed_data(map(), map()) :: Signer.typed_data()
  defp typed_data(domain, permit) do
    %{
      "types" => @typed_data_types,
      "primaryType" => "Permit",
      "domain" => %{
        "name" => Utils.map_value(domain, {"name", :name}),
        "version" => Utils.map_value(domain, {"version", :version}),
        "chainId" => Utils.map_value(domain, {"chainId", :chain_id}),
        "verifyingContract" => Utils.map_value(domain, {"verifyingContract", :verifying_contract})
      },
      "message" => permit
    }
  end

  @spec resolve_deadline(map(), keyword()) ::
          {:ok, String.t()} | {:error, :invalid_deadline | :invalid_requirements}
  defp resolve_deadline(requirements, opts) do
    case Keyword.fetch(opts, :deadline) do
      {:ok, deadline} ->
        normalize_uint(deadline, :invalid_deadline)

      :error ->
        case Utils.map_value(requirements, {"maxTimeoutSeconds", :maxTimeoutSeconds}) do
          timeout when is_integer(timeout) and timeout > 0 ->
            {:ok, Integer.to_string(System.os_time(:second) + timeout)}

          _timeout ->
            {:error, :invalid_requirements}
        end
    end
  end

  @spec resolve_amount(map(), keyword()) ::
          {:ok, String.t()} | {:error, :invalid_amount | :invalid_requirements}
  defp resolve_amount(requirements, opts) do
    case Keyword.fetch(opts, :amount) do
      {:ok, amount} ->
        normalize_uint(amount, :invalid_amount)

      :error ->
        case Utils.map_value(requirements, {"amount", :amount}) do
          nil -> {:error, :invalid_requirements}
          amount -> normalize_uint(amount, :invalid_amount)
        end
    end
  end

  @spec normalize_uint(term(), atom()) :: {:ok, String.t()} | {:error, atom()}
  defp normalize_uint(value, _error) when is_integer(value) and value >= 0,
    do: {:ok, Integer.to_string(value)}

  defp normalize_uint(value, error) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer >= 0 -> {:ok, Integer.to_string(integer)}
      _parsed -> {:error, error}
    end
  end

  defp normalize_uint(_value, error), do: {:error, error}

  @spec fetch_field(map(), {String.t(), atom()}) ::
          {:ok, term()} | {:error, {:missing_field, String.t()}}
  defp fetch_field(map, {string_key, _atom_key} = key) do
    case Utils.map_value(map, key) do
      nil -> {:error, {:missing_field, string_key}}
      value -> {:ok, value}
    end
  end

  # -- Info validation --------------------------------------------------------

  @spec fetch_info(term()) :: {:ok, map()} | {:error, :extension_missing}
  defp fetch_info(extensions) when is_map(extensions) do
    with %{} = extension <- Map.get(extensions, @extension_key),
         %{} = info <- Map.get(extension, "info") do
      {:ok, info}
    else
      _missing -> {:error, :extension_missing}
    end
  end

  defp fetch_info(_extensions), do: {:error, :extension_missing}

  @spec ensure_fields_present(map()) :: :ok | {:error, {:missing_info_field, String.t()}}
  defp ensure_fields_present(info) do
    Enum.reduce_while(@required_fields, :ok, fn field, :ok ->
      case Map.get(info, field) do
        nil -> {:halt, {:error, {:missing_info_field, field}}}
        "" -> {:halt, {:error, {:missing_info_field, field}}}
        _value -> {:cont, :ok}
      end
    end)
  end

  @spec validate_field(String.t(), term()) ::
          {:cont, :ok} | {:halt, {:error, {:invalid_info_field, String.t()}}}
  defp validate_field(field, value) do
    case valid_field?(field, value) do
      true -> {:cont, :ok}
      false -> {:halt, {:error, {:invalid_info_field, field}}}
    end
  end

  @spec valid_field?(String.t(), term()) :: boolean()
  defp valid_field?(field, value) when field in ~w(from asset spender),
    do: Wallet.valid_evm?(value)

  defp valid_field?(field, value) when field in ~w(amount nonce deadline),
    do: is_binary(value) and value =~ ~r/^[0-9]+$/

  defp valid_field?("signature", value),
    do: is_binary(value) and value =~ ~r/^0x[a-fA-F0-9]+$/

  defp valid_field?("version", value),
    do: is_binary(value) and value =~ ~r/^[0-9]+(\.[0-9]+)*$/

  # -- Payload helpers --------------------------------------------------------

  @spec ensure_extensions(term()) :: map()
  defp ensure_extensions(extensions) when is_map(extensions), do: extensions
  defp ensure_extensions(_extensions), do: %{}

  @spec ensure_declaration(term()) :: map()
  defp ensure_declaration(declaration) when is_map(declaration), do: declaration
  defp ensure_declaration(_declaration), do: %{}
end
