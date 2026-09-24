defmodule X402.Extensions.ERC20ApprovalGasSponsoring do
  @moduledoc """
  Builds and validates the `erc20ApprovalGasSponsoring` extension.

  The extension enables a gasless [Permit2](https://github.com/Uniswap/permit2)
  approval flow for ERC-20 tokens that do **not** implement EIP-2612. The
  client signs — but does not broadcast — a normal EVM transaction calling
  `approve(Permit2, amount)`; the facilitator funds the wallet's gas if
  needed, broadcasts the approval, and settles via `x402Permit2Proxy` in one
  atomic bundle.

  Unlike `X402.Extensions.EIP2612GasSponsoring`, nothing here is EIP-712
  typed data: the signed artifact is a full RLP-encoded transaction whose
  `nonce` must match the wallet's current on-chain nonce and whose fees must
  match live network prices. Producing it therefore requires chain access
  and transaction-signing tooling outside this library — this module builds,
  validates, and attaches the extension data *around* a pre-signed
  transaction supplied by the caller.

  Server side, `build_extension/0` declares support under
  `extensions.erc20ApprovalGasSponsoring` in a `PAYMENT-REQUIRED` response,
  and `extract_info/1` / `validate_info/1` check the client-populated data
  echoed back in a `PaymentPayload`.

  Client side, `build_info/1` assembles the wire info for a pre-signed
  approval transaction, `put_info/2` attaches it to a payload's extensions,
  and `enricher/1` packages both for `X402.Client.build_payment/3`:

      {:ok, payload} =
        X402.Client.build_payment(payment_required, signer,
          extensions: [
            X402.Extensions.ERC20ApprovalGasSponsoring.enricher(
              from: wallet_address,
              signed_transaction: signed_approve_tx_hex
            )
          ]
        )

  See the
  [erc20ApprovalGasSponsoring extension spec](https://github.com/x402-foundation/x402/blob/main/specs/extensions/erc20_gas_sponsoring.md).
  """

  alias X402.Utils
  alias X402.Wallet

  @extension_key "erc20ApprovalGasSponsoring"
  @permit2_address "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  @info_version "1"
  @schema_uri "https://json-schema.org/draft/2020-12/schema"
  @max_uint256 Integer.to_string(Integer.pow(2, 256) - 1)

  @required_fields ~w(from asset spender amount signedTransaction version)

  @shared_opts [
    from: [
      type: :string,
      required: true,
      doc: "The address of the wallet that signed the approval transaction."
    ],
    signed_transaction: [
      type: :string,
      required: true,
      doc: """
      The RLP-encoded signed EIP-1559 transaction calling
      `approve(spender, amount)`, as a `0x`-prefixed hex string. Its signer,
      target contract, calldata, nonce, and fees are verified on-chain by the
      facilitator.
      """
    ],
    amount: [
      type: {:or, [:non_neg_integer, :string]},
      doc: """
      The approval amount declared alongside the transaction, in atomic
      units. Must match the amount in the transaction's calldata. Defaults
      to MaxUint256, matching the reference client implementations.
      """
    ],
    spender: [
      type: :string,
      doc: """
      The approved spender declared alongside the transaction. Must match
      the spender in the transaction's calldata. Defaults to the canonical
      Permit2 contract.
      """
    ]
  ]

  @info_opts_schema @shared_opts ++
                      [
                        asset: [
                          type: :string,
                          required: true,
                          doc: "The ERC-20 token contract the transaction approves."
                        ]
                      ]

  @enrich_opts_schema @shared_opts ++
                        [
                          asset: [
                            type: :string,
                            doc: """
                            The ERC-20 token contract the transaction
                            approves. Defaults to the accepted payment
                            requirements' `asset`.
                            """
                          ]
                        ]

  @typedoc "A built `extensions.erc20ApprovalGasSponsoring` declaration (`info` + `schema`)."
  @type t :: %{binary() => map()}

  @typedoc """
  Client-populated extension info in wire shape: string keys `"from"`,
  `"asset"`, `"spender"`, `"amount"`, `"signedTransaction"`, and
  `"version"`.
  """
  @type info :: %{optional(binary()) => binary()}

  @type info_error ::
          :extension_missing
          | {:missing_info_field, String.t()}
          | {:invalid_info_field, String.t()}

  @doc since: "0.6.0"
  @doc """
  Returns the extension key, `"erc20ApprovalGasSponsoring"`.

  ## Examples

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.key()
      "erc20ApprovalGasSponsoring"
  """
  @spec key() :: String.t()
  def key, do: @extension_key

  @doc since: "0.6.0"
  @doc """
  Returns the canonical Permit2 contract address — the default spender.

  ## Examples

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.permit2_address()
      "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  """
  @spec permit2_address() :: String.t()
  def permit2_address, do: @permit2_address

  @doc since: "0.6.0"
  @doc """
  Returns MaxUint256 as a decimal string — the default approval amount.

  ## Examples

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.max_uint256()
      "115792089237316195423570985008687907853269984665640564039457584007913129639935"
  """
  @spec max_uint256() :: String.t()
  def max_uint256, do: @max_uint256

  @doc since: "0.6.0"
  @doc """
  Builds the server-side extension declaration (`info` + `schema`).

  Resource servers advertise support by placing the declaration under
  `extensions.erc20ApprovalGasSponsoring` in a `PAYMENT-REQUIRED` response;
  the client populates the actual approval data.

  ## Examples

      iex> ext = X402.Extensions.ERC20ApprovalGasSponsoring.build_extension()
      iex> ext["info"]["version"]
      "1"
      iex> ext["schema"]["required"]
      ["from", "asset", "spender", "amount", "signedTransaction", "version"]
  """
  @spec build_extension() :: t()
  def build_extension do
    %{
      "info" => %{
        "description" =>
          "The facilitator accepts a raw signed approval transaction and will sponsor the gas fees.",
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
          "description" => "The ERC-20 token contract address to approve."
        },
        "spender" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]{40}$",
          "description" => "The address of the spender (Canonical Permit2)."
        },
        "amount" => %{
          "type" => "string",
          "pattern" => "^[0-9]+$",
          "description" => "Approval amount (uint256). Typically MaxUint."
        },
        "signedTransaction" => %{
          "type" => "string",
          "pattern" => "^0x[a-fA-F0-9]+$",
          "description" => "RLP-encoded signed transaction calling ERC20.approve()."
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
  Builds the client-populated info for a pre-signed approval transaction.

  Validates the declared fields structurally (the transaction itself is
  opaque to this library — the facilitator decodes and verifies it against
  the declared `from`, `asset`, `spender`, and `amount`) and returns the
  wire-shaped info, ready for `put_info/2`.

  ## Options

  #{NimbleOptions.docs(@info_opts_schema)}

  ## Examples

      iex> {:ok, info} =
      ...>   X402.Extensions.ERC20ApprovalGasSponsoring.build_info(
      ...>     from: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>     asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>     signed_transaction: "0x02f8" <> String.duplicate("ab", 100)
      ...>   )
      iex> info["spender"]
      "0x000000000022D473030F116dDEE9F6B43aC78BA3"
      iex> info["version"]
      "1"

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.build_info(
      ...>   from: "0x123",
      ...>   asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   signed_transaction: "0xabcd"
      ...> )
      {:error, {:invalid_info_field, "from"}}
  """
  @spec build_info(keyword()) :: {:ok, info()} | {:error, {:invalid_info_field, String.t()}}
  def build_info(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @info_opts_schema)

    from = Keyword.fetch!(opts, :from)
    asset = Keyword.fetch!(opts, :asset)
    spender = Keyword.get(opts, :spender, @permit2_address)
    signed_transaction = Keyword.fetch!(opts, :signed_transaction)

    with :ok <- validate_address("from", from),
         :ok <- validate_address("asset", asset),
         :ok <- validate_address("spender", spender),
         {:ok, amount} <- normalize_amount(Keyword.get(opts, :amount, @max_uint256)),
         :ok <- validate_signed_transaction(signed_transaction) do
      {:ok,
       %{
         "from" => from,
         "asset" => asset,
         "spender" => spender,
         "amount" => amount,
         "signedTransaction" => signed_transaction,
         "version" => @info_version
       }}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Attaches client-populated info to a payload's extensions.

  Places the info under `extensions.erc20ApprovalGasSponsoring.info`,
  following the append-only rule: when the payload already echoes the
  server's declaration, server-declared info fields are preserved (they win
  over client values) and the declared `schema` is kept; the client's
  fields are added alongside them.

  ## Examples

      iex> info = %{"from" => "0x1111111111111111111111111111111111111111"}
      iex> payload = X402.Extensions.ERC20ApprovalGasSponsoring.put_info(%{"payload" => %{}}, info)
      iex> payload["extensions"]["erc20ApprovalGasSponsoring"]["info"]["from"]
      "0x1111111111111111111111111111111111111111"
  """
  @spec put_info(map(), info()) :: map()
  def put_info(payload, info) when is_map(payload) and is_map(info) do
    extensions = ensure_map(Utils.map_value(payload, {"extensions", :extensions}))
    declaration = ensure_map(Map.get(extensions, @extension_key))
    server_info = ensure_map(Map.get(declaration, "info"))
    merged = Map.put(declaration, "info", Map.merge(info, server_info))
    Map.put(payload, "extensions", Map.put(extensions, @extension_key, merged))
  end

  @doc since: "0.6.0"
  @doc """
  Extracts the client-populated info from a `PaymentPayload` map.

  Returns the info when the extension is present and every required field
  is populated. Field formats are not checked here — see `validate_info/1`.

  ## Examples

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.extract_info(%{"payload" => %{}})
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

  Checks that addresses match `^0x[a-fA-F0-9]{40}$`, that `amount` is a
  decimal string, that `signedTransaction` is a `0x`-prefixed hex string,
  and that `version` is a dotted numeric version.

  ## Examples

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.validate_info(%{
      ...>   "from" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "spender" => "0x000000000022D473030F116dDEE9F6B43aC78BA3",
      ...>   "amount" => "10000",
      ...>   "signedTransaction" => "0xabcdef",
      ...>   "version" => "1"
      ...> })
      :ok

      iex> X402.Extensions.ERC20ApprovalGasSponsoring.validate_info(%{"from" => "0x123"})
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

  The enricher attaches the pre-signed approval transaction via
  `build_info/1` and `put_info/2` — but only when the server advertised
  `erc20ApprovalGasSponsoring` in the `PaymentRequired` extensions;
  otherwise the payload passes through unchanged. `:asset` defaults to the
  accepted requirements' `asset`.

  ## Options

  #{NimbleOptions.docs(@enrich_opts_schema)}
  """
  @spec enricher(keyword()) ::
          (map(), map() | nil ->
             {:ok, map()} | {:error, {:invalid_info_field, String.t()} | :invalid_requirements})
  def enricher(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @enrich_opts_schema)
    fn payload, payment_required -> enrich(payload, payment_required, opts) end
  end

  # -- Enrichment -------------------------------------------------------------

  @spec enrich(map(), map() | nil, keyword()) ::
          {:ok, map()} | {:error, {:invalid_info_field, String.t()} | :invalid_requirements}
  defp enrich(payload, payment_required, opts) do
    if advertised?(payment_required) do
      with {:ok, opts} <- resolve_asset(opts, payload),
           {:ok, info} <- build_info(opts) do
        {:ok, put_info(payload, info)}
      end
    else
      {:ok, payload}
    end
  end

  @spec resolve_asset(keyword(), map()) :: {:ok, keyword()} | {:error, :invalid_requirements}
  defp resolve_asset(opts, payload) do
    if Keyword.has_key?(opts, :asset) do
      {:ok, opts}
    else
      requirements = Utils.map_value(payload, {"accepted", :accepted}) || %{}

      case Utils.map_value(requirements, {"asset", :asset}) do
        asset when is_binary(asset) and asset != "" -> {:ok, Keyword.put(opts, :asset, asset)}
        _asset -> {:error, :invalid_requirements}
      end
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

  # -- Info validation --------------------------------------------------------

  @spec validate_address(String.t(), term()) ::
          :ok | {:error, {:invalid_info_field, String.t()}}
  defp validate_address(field, value) do
    case Wallet.valid_evm?(value) do
      true -> :ok
      false -> {:error, {:invalid_info_field, field}}
    end
  end

  @spec normalize_amount(term()) ::
          {:ok, String.t()} | {:error, {:invalid_info_field, String.t()}}
  defp normalize_amount(value) when is_integer(value) and value >= 0,
    do: {:ok, Integer.to_string(value)}

  defp normalize_amount(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer >= 0 -> {:ok, Integer.to_string(integer)}
      _parsed -> {:error, {:invalid_info_field, "amount"}}
    end
  end

  defp normalize_amount(_value), do: {:error, {:invalid_info_field, "amount"}}

  @spec validate_signed_transaction(term()) ::
          :ok | {:error, {:invalid_info_field, String.t()}}
  defp validate_signed_transaction(value) do
    if is_binary(value) and value =~ ~r/^0x[a-fA-F0-9]+$/ do
      :ok
    else
      {:error, {:invalid_info_field, "signedTransaction"}}
    end
  end

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

  defp valid_field?("amount", value),
    do: is_binary(value) and value =~ ~r/^[0-9]+$/

  defp valid_field?("signedTransaction", value),
    do: is_binary(value) and value =~ ~r/^0x[a-fA-F0-9]+$/

  defp valid_field?("version", value),
    do: is_binary(value) and value =~ ~r/^[0-9]+(\.[0-9]+)*$/

  # -- Payload helpers --------------------------------------------------------

  @spec ensure_map(term()) :: map()
  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_value), do: %{}
end
