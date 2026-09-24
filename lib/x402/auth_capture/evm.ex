defmodule X402.AuthCapture.EVM do
  @moduledoc """
  EVM binding primitives for the `auth-capture` scheme: commerce-payments
  deployments, `PaymentInfo` hashing, authorizer typed data, and
  `AuthCaptureEscrow` calldata.

  Everything here is pure: the module hashes, encodes, signs, and decodes
  but never talks to a node. `X402.Verify.AuthCaptureEVM` layers the RPC
  checks on top. These primitives do not submit transactions or provide
  durable lifecycle orchestration.

  ## PaymentInfo

  The escrow's struct keeps its canonical Solidity names on the wire so its
  EIP-712 typehash matches the contract byte for byte. Maps use string keys:

      %{
        "operator" => "0x...",            # extra.captureAuthorizer
        "payer" => "0x...",               # the payload's `from`
        "receiver" => "0x...",            # requirements.payTo
        "token" => "0x...",               # requirements.asset
        "maxAmount" => "1000000",         # requirements.amount
        "preApprovalExpiry" => 1_740_675_754,
        "authorizationExpiry" => 1_740_758_554,
        "refundExpiry" => 1_741_276_954,
        "minFeeBps" => 100,
        "maxFeeBps" => 100,
        "feeReceiver" => "0x...",         # extra.feeRecipient
        "salt" => "0x..."                 # 32-byte hex, zero-padded
      }

  Integer fields accept integers or decimal strings; `salt` is always the
  `0x`-prefixed 32-byte hex spelling the spec pins.

  ## Payment identity

  Two hashes derive from the struct and are not interchangeable:

  * `signature_nonce/3` — `keccak256(abi.encode(chainId, escrow,
    keccak256(abi.encode(TYPEHASH, info with payer = 0))))`, the nonce
    inside the client's token authorization.
  * `payment_info_hash/3` — `AuthCaptureEscrow.getHash(info)`, the escrow's
    canonical identifier keyed over the real payer.

  Requires the optional `ex_keccak` dependency (and `ex_secp256k1` for
  signing and recovery).
  """

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.Signer
  alias X402.Utils
  alias X402.Wallet

  @zero_address "0x0000000000000000000000000000000000000000"

  @v1_1 %{
    version: :v1_1,
    escrow: "0xf96815976523E00e65Be8f34cA5e64b4f41EB19c",
    eip3009_collector: "0x8612dfdc421f80336cd14E8EF9cb1E765dB5ab88",
    permit2_collector: "0xD69831Aed5bfe262067ec4c751f4F830EcdD446e",
    refund_collector: "0x7a03443724d14798c4AB4622F1DAAcA761Fea486"
  }

  @v1_0 %{
    version: :v1_0,
    escrow: "0xBdEA0D1bcC5966192B070Fdf62aB4EF5b4420cff",
    eip3009_collector: "0x0E3dF9510de65469C4518D7843919c0b8C7A7757",
    permit2_collector: "0x992476B9Ee81d52a5BdA0622C333938D0Af0aB26",
    refund_collector: "0x934907bffd0901b6A21e398B9C53A4A38F02fa5d"
  }

  @payment_info_type "PaymentInfo(address operator,address payer,address receiver," <>
                       "address token,uint120 maxAmount,uint48 preApprovalExpiry," <>
                       "uint48 authorizationExpiry,uint48 refundExpiry,uint16 minFeeBps," <>
                       "uint16 maxFeeBps,address feeReceiver,uint256 salt)"

  @salt_binding_type "x402AuthCaptureSaltBinding(address receiverAuthorizer,address policy," <>
                       "uint256 saltNonce)"

  @receive_type "ReceiveWithAuthorization(address from,address to,uint256 value," <>
                  "uint256 validAfter,uint256 validBefore,bytes32 nonce)"

  @permit_type "PermitTransferFrom(TokenPermissions permitted,address spender," <>
                 "uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"

  @token_permissions_type "TokenPermissions(address token,uint256 amount)"

  @operator_domain_name "x402 Auth Capture Operator"
  @operator_domain_version "1"

  @charge_type %{
    v1_1:
      "Charge(bytes32 paymentInfoHash,uint256 amount,address tokenCollector," <>
        "bytes32 collectorDataHash,uint256 feeAmount,address feeReceiver)",
    v1_0:
      "Charge(bytes32 paymentInfoHash,uint256 amount,address tokenCollector," <>
        "bytes32 collectorDataHash,uint16 feeBps,address feeReceiver)"
  }

  @capture_type %{
    v1_1:
      "Capture(bytes32 paymentInfoHash,uint256 amount,uint256 feeAmount,address feeReceiver," <>
        "uint256 expectedCapturableAmount,uint256 expectedRefundableAmount)",
    v1_0:
      "Capture(bytes32 paymentInfoHash,uint256 amount,uint16 feeBps,address feeReceiver," <>
        "uint256 expectedCapturableAmount,uint256 expectedRefundableAmount)"
  }

  @void_type "Void(bytes32 paymentInfoHash)"

  @refund_type "Refund(bytes32 paymentInfoHash,uint256 amount,address tokenCollector," <>
                 "uint256 expectedCapturableAmount,uint256 expectedRefundableAmount)"

  @wire_types Map.new(
                [
                  @receive_type,
                  @permit_type,
                  @void_type,
                  @refund_type
                  | Map.values(@charge_type) ++ Map.values(@capture_type)
                ],
                fn type ->
                  definitions =
                    Map.new(Regex.scan(~r/(\w+)\(([^)]*)\)/, type), fn [_, name, fields] ->
                      {name,
                       Enum.map(String.split(fields, ","), fn field ->
                         [type, name] = String.split(field, " ")
                         %{"name" => name, "type" => type}
                       end)}
                    end)

                  {type, definitions}
                end
              )

  # Function selectors of the AuthCaptureEscrow ABI (keccak256 of the
  # canonical signature, first four bytes); X402.AuthCapture.EVMTest
  # recomputes every one with ExKeccak.
  @selectors %{
    authorize: <<0x41, 0xD6, 0x62, 0x02>>,
    charge_v1_1: <<0xC4, 0x49, 0xD1, 0x7C>>,
    charge_v1_0: <<0x9E, 0x65, 0x81, 0x9F>>,
    capture_v1_1: <<0x3E, 0xFA, 0x46, 0xE1>>,
    capture_v1_0: <<0x64, 0x4C, 0xD7, 0x9A>>,
    void: <<0xFA, 0x1C, 0xAD, 0x17>>,
    reclaim: <<0xE1, 0xA2, 0xA6, 0x6D>>,
    refund: <<0xD4, 0x58, 0xDB, 0x5A>>,
    payment_state: <<0x34, 0xB7, 0x78, 0xED>>,
    get_hash: <<0x06, 0x3A, 0x70, 0xFF>>
  }

  @event_topics %{
    authorized: "0x1c81fb2e3bab27f6bb09bee9a0dddf61600b7cbaf2c12683e4864e0cbdb9d284",
    charged_v1_1: "0x137b0e73e4453f43c2e1ad2552980a0e0c7e988764619974ca26d37a7159940c",
    charged_v1_0: "0x943ae4341dd799d7aeedc501f616cd26b134639e0bc2ec059581ba3ebbf1e7d0",
    captured_v1_1: "0xac1e0db1957daedbc6944bcb4c8dc947ff8101d710671ac2ec26309f7f38d58e",
    captured_v1_0: "0xe749f7bbd01b49bb05abf26ca492cb4dfdea6bedeada8a40fdccd478c73a74e2",
    voided: "0xcadce8c3acb008e3e1c64ca7f60d22a3c87069183182b7dbb9e4d8cfb3a15842",
    refunded: "0x1bf415371b303ca6b8bbb4ce479b177cba5ad15dbe0c9a7750a588aa6bcd25b2"
  }

  # Custom-error selectors of both escrow deployments, mapped onto the
  # spec's typed simulation reverts.
  @custom_errors %{
    <<0xC4, 0x6C, 0xF6, 0x0F>> => {"AfterPreApprovalExpiry", :authorization_expired},
    <<0x88, 0xEF, 0x07, 0x60>> => {"InvalidExpiries", :deadline_ordering},
    <<0x09, 0x2A, 0xF1, 0x9E>> => {"ExceedsMaxAmount", :amount_mismatch},
    <<0xAD, 0x7C, 0x14, 0x5A>> => {"PaymentAlreadyCollected", :payment_already_collected},
    <<0x3C, 0x73, 0xC4, 0xA0>> => {"TokenCollectionFailed", :token_collection_failed},
    <<0x53, 0x13, 0x28, 0x7D>> => {"InvalidCollectorForOperation", :collector},
    <<0xE1, 0x13, 0x0D, 0xBA>> => {"InvalidSender", :operator_mismatch},
    <<0x1F, 0x2A, 0x20, 0x05>> => {"ZeroAmount", :amount_mismatch},
    <<0x6C, 0x04, 0x42, 0xA2>> => {"AmountOverflow", :amount_overflow},
    <<0xBF, 0x47, 0xE3, 0xF7>> => {"FeeBpsOverflow", :fee_bps},
    <<0x09, 0x50, 0xD5, 0xD0>> => {"InvalidFeeBpsRange", :fee_bps_range},
    <<0x0B, 0x34, 0x5F, 0x0C>> => {"FeeBpsOutOfRange", :fee_bps_out_of_range},
    <<0x7C, 0x2D, 0xCC, 0x22>> => {"FeeAmountOutOfRange", :fee_bps_out_of_range},
    <<0xB6, 0x80, 0x2B, 0x7F>> => {"ZeroFeeReceiver", :zero_fee_receiver},
    <<0x4C, 0xAF, 0x6A, 0x34>> => {"InvalidFeeReceiver", :fee_receiver},
    <<0x36, 0xF2, 0xD2, 0x11>> => {"AfterAuthorizationExpiry", :capture_deadline_expired},
    <<0x60, 0x4B, 0x09, 0x47>> => {"InsufficientAuthorization", :insufficient_authorization},
    <<0x93, 0xBB, 0x7A, 0x12>> => {"ZeroAuthorization", :zero_authorization},
    <<0x94, 0x27, 0x1B, 0xDE>> => {"AfterRefundExpiry", :refund_deadline_expired},
    <<0x62, 0x95, 0xD6, 0x04>> => {"RefundExceedsCapture", :refund_exceeds_capture},
    <<0xAA, 0x56, 0x74, 0xAD>> => {"BeforeAuthorizationExpiry", :before_authorization_expiry}
  }

  @max_uint120 Integer.pow(2, 120) - 1
  @max_uint48 Integer.pow(2, 48) - 1
  @max_uint16 Integer.pow(2, 16) - 1
  @max_uint256 Integer.pow(2, 256) - 1
  @max_bps 10_000

  @typedoc "A resolved commerce-payments deployment."
  @type deployment :: %{
          version: :v1_1 | :v1_0,
          escrow: String.t(),
          eip3009_collector: String.t(),
          permit2_collector: String.t(),
          refund_collector: String.t()
        }

  @typedoc "A `PaymentInfo` struct in wire spelling (string keys)."
  @type payment_info :: %{optional(String.t()) => term()}

  @typedoc "An authorizer-signed operation."
  @type operation :: :charge | :capture | :void | :refund

  @typedoc "The decoded `paymentState(bytes32)` tuple."
  @type payment_state :: %{
          collected?: boolean(),
          capturable_amount: non_neg_integer(),
          refundable_amount: non_neg_integer()
        }

  @typedoc "Encoding failures shared by the hashing and calldata helpers."
  @type encode_error ::
          :missing_dependency
          | :invalid_address
          | :invalid_amount
          | :invalid_bytes32
          | :invalid_word
          | {:invalid_payment_info, String.t()}
          | {:missing_field, String.t()}

  # -- Deployments ------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :deployments
  @doc """
  The zero address, which the scheme reads for every absent operator field.

  ## Examples

      iex> X402.AuthCapture.EVM.zero_address()
      "0x0000000000000000000000000000000000000000"
  """
  @spec zero_address() :: String.t()
  def zero_address, do: @zero_address

  @doc since: "0.9.0"
  @doc group: :deployments
  @doc """
  Returns a canonical commerce-payments deployment by version.

  ## Examples

      iex> X402.AuthCapture.EVM.deployment(:v1_1).escrow
      "0xf96815976523E00e65Be8f34cA5e64b4f41EB19c"

      iex> X402.AuthCapture.EVM.deployment(:v1_0).eip3009_collector
      "0x0E3dF9510de65469C4518D7843919c0b8C7A7757"
  """
  @spec deployment(:v1_1 | :v1_0) :: deployment()
  def deployment(:v1_1), do: @v1_1
  def deployment(:v1_0), do: @v1_0

  @doc since: "0.9.0"
  @doc group: :deployments
  @doc """
  Resolves the deployment a requirements entry (or its `extra`) selects.

  An absent `extra.authCaptureEscrow` is the v1.1 escrow; either canonical
  escrow address (case-insensitive) selects its deployment; any other value
  is `{:error, :invalid_escrow}`.

  ## Examples

      iex> {:ok, deployment} = X402.AuthCapture.EVM.resolve_deployment(%{"extra" => %{}})
      iex> deployment.version
      :v1_1

      iex> {:ok, deployment} =
      ...>   X402.AuthCapture.EVM.resolve_deployment(%{
      ...>     "extra" => %{"authCaptureEscrow" => "0xbdea0d1bcc5966192b070fdf62ab4ef5b4420cff"}
      ...>   })
      iex> deployment.version
      :v1_0

      iex> X402.AuthCapture.EVM.resolve_deployment(%{
      ...>   "extra" => %{"authCaptureEscrow" => "0x1111111111111111111111111111111111111111"}
      ...> })
      {:error, :invalid_escrow}
  """
  @spec resolve_deployment(map()) :: {:ok, deployment()} | {:error, :invalid_escrow}
  def resolve_deployment(requirements) when is_map(requirements) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      nil -> resolve_extra_deployment(requirements)
      %{} = extra -> resolve_extra_deployment(extra)
      _other -> {:error, :invalid_escrow}
    end
  end

  @spec resolve_extra_deployment(map()) :: {:ok, deployment()} | {:error, :invalid_escrow}
  defp resolve_extra_deployment(extra) do
    case Utils.map_value(extra, {"authCaptureEscrow", :authCaptureEscrow}) do
      nil -> {:ok, @v1_1}
      escrow when is_binary(escrow) -> deployment_by_escrow(String.downcase(escrow))
      _other -> {:error, :invalid_escrow}
    end
  end

  @doc since: "0.9.0"
  @doc group: :deployments
  @doc """
  Whether salt binding is on: `extra.receiverAuthorizer` or `extra.policy`
  is a non-zero address.

  ## Examples

      iex> X402.AuthCapture.EVM.bound?(%{"extra" => %{}})
      false

      iex> X402.AuthCapture.EVM.bound?(%{
      ...>   "extra" => %{"receiverAuthorizer" => "0x2222222222222222222222222222222222222222"}
      ...> })
      true
  """
  @spec bound?(map()) :: boolean()
  def bound?(requirements) when is_map(requirements) do
    extra = extra(requirements)

    nonzero_address?(Utils.map_value(extra, {"receiverAuthorizer", :receiverAuthorizer})) or
      nonzero_address?(Utils.map_value(extra, {"policy", :policy}))
  end

  @doc since: "0.9.0"
  @doc group: :deployments
  @doc """
  Whether the value is a well-formed, non-zero EVM address.

  ## Examples

      iex> X402.AuthCapture.EVM.nonzero_address?("0x2222222222222222222222222222222222222222")
      true

      iex> X402.AuthCapture.EVM.nonzero_address?("0x0000000000000000000000000000000000000000")
      false

      iex> X402.AuthCapture.EVM.nonzero_address?(nil)
      false
  """
  @spec nonzero_address?(term()) :: boolean()
  def nonzero_address?(address) when is_binary(address) and byte_size(address) == 42,
    do: Wallet.valid_evm?(address) and String.downcase(address) != @zero_address

  def nonzero_address?(_address), do: false

  # -- PaymentInfo ------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  The `PaymentInfo` EIP-712 type string, whose keccak256 is the escrow's
  `PAYMENT_INFO_TYPEHASH`.
  """
  @spec payment_info_type() :: String.t()
  def payment_info_type, do: @payment_info_type

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  The salt-binding type string (`SALT_BINDING_TYPEHASH` preimage).
  """
  @spec salt_binding_type() :: String.t()
  def salt_binding_type, do: @salt_binding_type

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Builds the `PaymentInfo` struct for a payment from its requirements.

  `payer` is the client address, `pre_approval_expiry` the authorization's
  `validBefore` / `deadline`, and `salt` the wire `payload.salt`. Every
  other field comes from `requirements` and its `extra`, as the spec's
  PaymentInfo appendix sets out.

  ## Examples

      iex> requirements = %{
      ...>   "amount" => "10000",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "extra" => %{
      ...>     "captureAuthorizer" => "0x1563915e194d8cfba1943570603f7606a3115508",
      ...>     "feeRecipient" => "0x0000000000000000000000000000000000000000",
      ...>     "captureDeadline" => 1_800_000_000,
      ...>     "refundDeadline" => 1_800_100_000,
      ...>     "minFeeBps" => 0,
      ...>     "maxFeeBps" => 0
      ...>   }
      ...> }
      iex> {:ok, info} =
      ...>   X402.AuthCapture.EVM.payment_info(
      ...>     requirements,
      ...>     "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
      ...>     1_799_000_000,
      ...>     "0x" <> String.duplicate("ab", 32)
      ...>   )
      iex> {info["operator"], info["maxAmount"], info["authorizationExpiry"]}
      {"0x1563915e194d8cfba1943570603f7606a3115508", "10000", 1800000000}

      iex> X402.AuthCapture.EVM.payment_info(%{"extra" => %{}}, "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a", 1, "0x00")
      {:error, {:missing_field, "captureAuthorizer"}}
  """
  @spec payment_info(map(), String.t(), non_neg_integer(), String.t()) ::
          {:ok, payment_info()} | {:error, {:missing_field, String.t()}}
  def payment_info(requirements, payer, pre_approval_expiry, salt) when is_map(requirements) do
    extra = extra(requirements)

    with {:ok, operator} <- fetch(extra, "captureAuthorizer"),
         {:ok, fee_receiver} <- fetch(extra, "feeRecipient"),
         {:ok, capture_deadline} <- fetch(extra, "captureDeadline"),
         {:ok, refund_deadline} <- fetch(extra, "refundDeadline"),
         {:ok, min_fee_bps} <- fetch(extra, "minFeeBps"),
         {:ok, max_fee_bps} <- fetch(extra, "maxFeeBps"),
         {:ok, receiver} <- fetch(requirements, "payTo"),
         {:ok, token} <- fetch(requirements, "asset"),
         {:ok, amount} <- fetch(requirements, "amount") do
      {:ok,
       %{
         "operator" => operator,
         "payer" => payer,
         "receiver" => receiver,
         "token" => token,
         "maxAmount" => amount,
         "preApprovalExpiry" => pre_approval_expiry,
         "authorizationExpiry" => capture_deadline,
         "refundExpiry" => refund_deadline,
         "minFeeBps" => min_fee_bps,
         "maxFeeBps" => max_fee_bps,
         "feeReceiver" => fee_receiver,
         "salt" => salt
       }}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Reconstructs the `PaymentInfo` a client payment payload commits to.

  Accepts the full v2 envelope or the inner `payload` map. The payer and
  `preApprovalExpiry` come from the EIP-3009 `authorization` (`from`,
  `validBefore`) or the `permit2Authorization` (`from`, `deadline`), and
  the salt from `payload.salt`.
  """
  @spec payment_info_from_payload(map(), map()) ::
          {:ok, payment_info()} | {:error, :payload_format | {:missing_field, String.t()}}
  def payment_info_from_payload(payload, requirements)
      when is_map(payload) and is_map(requirements) do
    inner = inner_payload(payload)

    with {:ok, payer, expiry} <- payer_and_expiry(inner),
         salt when is_binary(salt) <- Utils.map_value(inner, {"salt", :salt}) do
      payment_info(requirements, payer, expiry, salt)
    else
      {:error, reason} -> {:error, reason}
      _other -> {:error, :payload_format}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Checks stored `PaymentInfo` against its original requirements.

  Reconstructs and compares the canonical ABI encoding, including every
  Solidity width, and checks expiry ordering. The payer, preapproval expiry
  and salt must come from retained client state; this does not verify their
  signature, salt commitment, or onchain existence.

  ## Examples

      iex> X402.AuthCapture.EVM.match_payment_info(%{}, %{})
      {:error, {:missing_field, "captureAuthorizer"}}
  """
  @spec match_payment_info(map(), map()) :: :ok | {:error, term()}
  def match_payment_info(requirements, info) when is_map(requirements) and is_map(info) do
    with {:ok, expected} <-
           payment_info(
             requirements,
             Utils.map_value(info, {"payer", :payer}),
             Utils.map_value(info, {"preApprovalExpiry", :preApprovalExpiry}),
             Utils.map_value(info, {"salt", :salt})
           ),
         {:ok, expected_bytes} <- encode_payment_info(expected),
         {:ok, actual_bytes} <- encode_payment_info(info),
         true <- actual_bytes == expected_bytes,
         {:ok, preapproval} <- parse_uint256(expected["preApprovalExpiry"]),
         {:ok, capture} <- parse_uint256(expected["authorizationExpiry"]),
         {:ok, refund} <- parse_uint256(expected["refundExpiry"]),
         true <- preapproval <= capture and capture <= refund do
      :ok
    else
      false -> {:error, :payload_format}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Parses a non-negative uint256 integer or decimal string.

  Rejects signs, whitespace and strings longer than 78 digits before
  integer conversion. Hex input is reserved for the bytes32 helpers.

  ## Examples

      iex> X402.AuthCapture.EVM.parse_uint256("1000")
      {:ok, 1000}

      iex> X402.AuthCapture.EVM.parse_uint256("+1")
      {:error, :invalid_amount}
  """
  @spec parse_uint256(term()) :: {:ok, non_neg_integer()} | {:error, :invalid_amount}
  def parse_uint256(value) when is_integer(value) and value >= 0 and value <= @max_uint256,
    do: {:ok, value}

  def parse_uint256(value) when is_binary(value) and byte_size(value) in 1..78 do
    if Regex.match?(~r/\A[0-9]+\z/, value),
      do: parse_uint256(String.to_integer(value)),
      else: {:error, :invalid_amount}
  end

  def parse_uint256(_value), do: {:error, :invalid_amount}

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  ABI-encodes a `PaymentInfo` struct into its twelve 32-byte words.

  Validates each field against its Solidity width (`uint120`, `uint48`,
  `uint16`) and returns `{:error, {:invalid_payment_info, field}}` for the
  first field that does not fit.

  ## Examples

      iex> info = %{
      ...>   "operator" => "0x1563915e194d8cfba1943570603f7606a3115508",
      ...>   "payer" => "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
      ...>   "receiver" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "token" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "maxAmount" => "10000",
      ...>   "preApprovalExpiry" => 1,
      ...>   "authorizationExpiry" => 2,
      ...>   "refundExpiry" => 3,
      ...>   "minFeeBps" => 0,
      ...>   "maxFeeBps" => 100,
      ...>   "feeReceiver" => "0x0000000000000000000000000000000000000000",
      ...>   "salt" => "0x" <> String.duplicate("00", 31) <> "01"
      ...> }
      iex> {:ok, encoded} = X402.AuthCapture.EVM.encode_payment_info(info)
      iex> byte_size(encoded)
      384

      iex> X402.AuthCapture.EVM.encode_payment_info(%{"operator" => "0x1"})
      {:error, {:invalid_payment_info, "operator"}}
  """
  @spec encode_payment_info(map()) ::
          {:ok, binary()} | {:error, {:invalid_payment_info, String.t()}}
  def encode_payment_info(info) when is_map(info) do
    with {:ok, operator} <- field(info, "operator", :address),
         {:ok, payer} <- field(info, "payer", :address),
         {:ok, receiver} <- field(info, "receiver", :address),
         {:ok, token} <- field(info, "token", :address),
         {:ok, max_amount} <- field(info, "maxAmount", {:uint, @max_uint120}),
         {:ok, pre_approval} <- field(info, "preApprovalExpiry", {:uint, @max_uint48}),
         {:ok, authorization} <- field(info, "authorizationExpiry", {:uint, @max_uint48}),
         {:ok, refund} <- field(info, "refundExpiry", {:uint, @max_uint48}),
         {:ok, min_fee} <- field(info, "minFeeBps", {:uint, @max_uint16}),
         {:ok, max_fee} <- field(info, "maxFeeBps", {:uint, @max_uint16}),
         {:ok, fee_receiver} <- field(info, "feeReceiver", :address),
         {:ok, salt} <- field(info, "salt", :bytes32) do
      {:ok,
       operator <>
         payer <>
         receiver <>
         token <>
         max_amount <>
         pre_approval <>
         authorization <>
         refund <>
         min_fee <>
         max_fee <>
         fee_receiver <>
         salt}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Computes `AuthCaptureEscrow.getHash(paymentInfo)` — the escrow's canonical
  payment identifier, as `0x`-prefixed hex.

  `keccak256(abi.encode(chainId, escrow, keccak256(abi.encode(PAYMENT_INFO_TYPEHASH, info))))`.
  """
  @spec payment_info_hash(non_neg_integer(), String.t(), map()) ::
          {:ok, String.t()} | {:error, encode_error()}
  def payment_info_hash(chain_id, escrow, info)
      when is_integer(chain_id) and is_binary(escrow) and is_map(info) do
    with {:ok, keccak} <- EIP712.keccak_module(),
         {:ok, chain_word} <- EIP712.encode_uint256(chain_id),
         {:ok, encoded} <- encode_payment_info(info),
         {:ok, escrow_word} <- EIP712.encode_address(escrow) do
      struct_hash = keccak.hash_256(keccak.hash_256(@payment_info_type) <> encoded)

      {:ok, hex(keccak.hash_256(chain_word <> escrow_word <> struct_hash))}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Computes the payment's `signatureNonce`: the payer-agnostic identity that
  becomes the EIP-3009 `nonce` (as `0x` hex) and the Permit2 `nonce` (as the
  decimal `uint256`, see `permit2_nonce/1`).

  The struct is hashed with `payer` zeroed and every other field holding
  its onchain value.
  """
  @spec signature_nonce(non_neg_integer(), String.t(), map()) ::
          {:ok, String.t()} | {:error, encode_error()}
  def signature_nonce(chain_id, escrow, info) when is_map(info),
    do: payment_info_hash(chain_id, escrow, Map.put(info, "payer", @zero_address))

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Spells a 32-byte hex value as the decimal `uint256` string Permit2 nonces
  use on the wire.

  ## Examples

      iex> X402.AuthCapture.EVM.permit2_nonce("0x" <> String.duplicate("00", 31) <> "ff")
      {:ok, "255"}

      iex> X402.AuthCapture.EVM.permit2_nonce("0xzz")
      {:error, :invalid_bytes32}
  """
  @spec permit2_nonce(String.t()) :: {:ok, String.t()} | {:error, :invalid_bytes32}
  def permit2_nonce(hex) do
    with {:ok, <<value::unsigned-big-integer-size(256)>>} <- EIP712.encode_bytes32(hex) do
      {:ok, Integer.to_string(value)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Spells a `uint256` (integer or decimal string) as the zero-padded 32-byte
  hex the scheme pins for `salt` and `saltNonce`.

  ## Examples

      iex> X402.AuthCapture.EVM.bytes32_hex(255)
      {:ok, "0x00000000000000000000000000000000000000000000000000000000000000ff"}

      iex> X402.AuthCapture.EVM.bytes32_hex("0x" <> String.duplicate("ab", 32))
      {:ok, "0x" <> String.duplicate("ab", 32)}

      iex> X402.AuthCapture.EVM.bytes32_hex("nope")
      {:error, :invalid_bytes32}
  """
  @spec bytes32_hex(term()) :: {:ok, String.t()} | {:error, :invalid_bytes32}
  def bytes32_hex("0x" <> _rest = value) do
    with {:ok, bytes} <- EIP712.encode_bytes32(value), do: {:ok, hex(bytes)}
  end

  def bytes32_hex(value) when is_integer(value) and value >= 0 and value <= @max_uint256,
    do: {:ok, hex(<<value::unsigned-big-integer-size(256)>>)}

  def bytes32_hex(value) when is_binary(value) do
    case parse_uint256(value) do
      {:ok, integer} -> bytes32_hex(integer)
      {:error, _reason} -> {:error, :invalid_bytes32}
    end
  end

  def bytes32_hex(_value), do: {:error, :invalid_bytes32}

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Computes the bound salt:
  `keccak256(abi.encode(SALT_BINDING_TYPEHASH, receiverAuthorizer, policy, saltNonce))`.

  Absent addresses are the zero address; `salt_nonce` is 32-byte hex.
  """
  @spec bound_salt(String.t() | nil, String.t() | nil, String.t()) ::
          {:ok, String.t()} | {:error, encode_error()}
  def bound_salt(receiver_authorizer, policy, salt_nonce) do
    with {:ok, keccak} <- EIP712.keccak_module(),
         {:ok, authorizer_word} <- EIP712.encode_address(receiver_authorizer || @zero_address),
         {:ok, policy_word} <- EIP712.encode_address(policy || @zero_address),
         {:ok, nonce_word} <- EIP712.encode_bytes32(salt_nonce) do
      {:ok,
       hex(
         keccak.hash_256(
           keccak.hash_256(@salt_binding_type) <> authorizer_word <> policy_word <> nonce_word
         )
       )}
    end
  end

  @doc since: "0.9.0"
  @doc group: :payment_info
  @doc """
  Returns fresh random 32 bytes as zero-padded `0x` hex — a `salt` when
  unbound, a `saltNonce` when bound.

  ## Examples

      iex> X402.AuthCapture.EVM.random_bytes32() =~ ~r/^0x[0-9a-f]{64}$/
      true
  """
  @spec random_bytes32() :: String.t()
  def random_bytes32, do: hex(:crypto.strong_rand_bytes(32))

  # -- Client signing digests -------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :client
  @doc """
  Computes the EIP-712 digest of an EIP-3009 `ReceiveWithAuthorization`.

  Same field layout as `TransferWithAuthorization`, different type name —
  the token collector calls `receiveWithAuthorization`. `domain` is the
  token's EIP-712 domain (see `X402.EIP712.domain/1`).
  """
  @spec receive_authorization_digest(map(), map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defdelegate receive_authorization_digest(domain, authorization), to: EIP3009

  @doc since: "0.9.0"
  @doc group: :client
  @doc """
  Computes the EIP-712 digest of a witness-less Permit2 `PermitTransferFrom`.

  `domain` is the canonical Permit2 domain (see `X402.Permit2.domain/1`);
  the authorization carries `permitted.token`, `permitted.amount`,
  `spender`, `nonce` (decimal `uint256`), and `deadline`.
  """
  @spec permit_transfer_digest(map(), map()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  def permit_transfer_digest(domain, authorization)
      when is_map(domain) and is_map(authorization) do
    with %{} = permitted <- Utils.map_value(authorization, {"permitted", :permitted}),
         {:ok, token} <- EIP712.encode_address(Utils.map_value(permitted, {"token", :token})),
         {:ok, amount} <- EIP712.encode_uint256(Utils.map_value(permitted, {"amount", :amount})),
         {:ok, permitted_hash} <- EIP712.hash_struct(@token_permissions_type, [token, amount]),
         {:ok, spender} <-
           EIP712.encode_address(Utils.map_value(authorization, {"spender", :spender})),
         {:ok, nonce} <- EIP712.encode_uint256(Utils.map_value(authorization, {"nonce", :nonce})),
         {:ok, deadline} <-
           EIP712.encode_uint256(Utils.map_value(authorization, {"deadline", :deadline})),
         {:ok, struct_hash} <-
           EIP712.hash_struct(@permit_type, [permitted_hash, spender, nonce, deadline]) do
      EIP712.digest(domain, struct_hash)
    else
      {:error, reason} -> {:error, reason}
      _other -> {:error, :invalid_amount}
    end
  end

  @doc since: "0.9.0"
  @doc group: :client
  @doc """
  Returns standard EIP-712 JSON for the client's token authorization.

  Includes `types`, `primaryType`, a camel-case `domain`, and only the
  signed message fields. Permit2 has no domain version or signed `from`.
  """
  @spec authorization_typed_data(:eip3009 | :permit2, map(), map()) :: map()
  def authorization_typed_data(:eip3009, domain, authorization),
    do: typed_data(@receive_type, domain, authorization)

  def authorization_typed_data(:permit2, domain, authorization),
    do: typed_data(@permit_type, domain, authorization)

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes the signature bytes for the selected token collector.

  EIP-3009 takes the original bytes; Permit2 takes `abi.encode(bytes)`.
  An ERC-6492 wrapper remains intact inside those bytes.

  ## Examples

      iex> X402.AuthCapture.EVM.collector_data(:eip3009, <<1, 2>>)
      <<1, 2>>

      iex> byte_size(X402.AuthCapture.EVM.collector_data(:permit2, <<1, 2>>))
      96
  """
  @spec collector_data(:eip3009 | :permit2, binary()) :: binary()
  def collector_data(:eip3009, signature) when is_binary(signature), do: signature

  def collector_data(:permit2, signature) when is_binary(signature),
    do: word(32) <> EIP712.encode_dynamic_bytes(signature)

  # -- Authorizer typed data --------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  The EIP-712 domain every authorizer signature uses, with the capture
  authorizer as `verifyingContract`.

  ## Examples

      iex> X402.AuthCapture.EVM.operator_domain(84532, "0x1563915e194d8cfba1943570603f7606a3115508")
      %{
        name: "x402 Auth Capture Operator",
        version: "1",
        chain_id: 84532,
        verifying_contract: "0x1563915e194d8cfba1943570603f7606a3115508"
      }
  """
  @spec operator_domain(non_neg_integer(), String.t()) :: map()
  def operator_domain(chain_id, capture_authorizer) do
    %{
      name: @operator_domain_name,
      version: @operator_domain_version,
      chain_id: chain_id,
      verifying_contract: capture_authorizer
    }
  end

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  The submitted fee field a deployment takes on `charge` and `capture`.

  ## Examples

      iex> X402.AuthCapture.EVM.fee_field(:v1_1)
      "feeAmount"

      iex> X402.AuthCapture.EVM.fee_field(:v1_0)
      "feeBps"
  """
  @spec fee_field(:v1_1 | :v1_0) :: String.t()
  def fee_field(:v1_1), do: "feeAmount"
  def fee_field(:v1_0), do: "feeBps"

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  The EIP-712 type string an operation's consent is signed over.

  ## Examples

      iex> X402.AuthCapture.EVM.consent_type(:void, :v1_1)
      "Void(bytes32 paymentInfoHash)"
  """
  @spec consent_type(operation(), :v1_1 | :v1_0) :: String.t()
  def consent_type(:charge, version), do: Map.fetch!(@charge_type, version)
  def consent_type(:capture, version), do: Map.fetch!(@capture_type, version)
  def consent_type(:void, _version), do: @void_type
  def consent_type(:refund, _version), do: @refund_type

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  Computes the EIP-712 digest an authorizer signs for an operation.

  `params` uses the wire field names of the signed type: `paymentInfoHash`,
  `amount`, `tokenCollector`, `collectorDataHash`, `feeAmount` (v1.1) or
  `feeBps` (v1.0), `feeReceiver`, `expectedCapturableAmount`, and
  `expectedRefundableAmount` — each operation reads the subset its type
  declares. `Void` needs only `paymentInfoHash`.
  """
  @spec consent_digest(operation(), map(), map(), :v1_1 | :v1_0) ::
          {:ok, <<_::256>>} | {:error, encode_error()}
  def consent_digest(operation, params, domain, version)
      when is_map(params) and is_map(domain) and version in [:v1_1, :v1_0] do
    with {:ok, words} <- consent_words(operation, params, version),
         {:ok, struct_hash} <- EIP712.hash_struct(consent_type(operation, version), words) do
      EIP712.digest(domain, struct_hash)
    end
  end

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  Signs an operation's consent digest with the receiver authorizer's signer.

  Returns the `0x`-prefixed 65-byte signature.
  """
  @spec sign_consent(Signer.t(), operation(), map(), map(), :v1_1 | :v1_0) ::
          {:ok, String.t()} | {:error, term()}
  def sign_consent(signer, operation, params, domain, version) do
    with {:ok, digest} <- consent_digest(operation, params, domain, version),
         {:ok, signature} <-
           Signer.sign_eip712(
             signer,
             digest,
             typed_data(consent_type(operation, version), domain, params)
           ) do
      {:ok, hex(signature)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :authorizer
  @doc """
  Recovers the ECDSA signer of an operation's consent signature.

  ERC-1271 authorizers need a node call and are handled by
  `X402.Verify.AuthCaptureEVM`.
  """
  @spec recover_consent(operation(), map(), map(), :v1_1 | :v1_0, binary()) ::
          {:ok, String.t()} | {:error, term()}
  def recover_consent(operation, params, domain, version, signature) do
    with {:ok, digest} <- consent_digest(operation, params, domain, version) do
      EIP3009.recover_signer(digest, signature)
    end
  end

  # -- Fees -------------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :fees
  @doc """
  The escrow's fee arithmetic: `amount * bps / 10000` with integer division.

  ## Examples

      iex> X402.AuthCapture.EVM.fee_amount(750_000, 100)
      7500

      iex> X402.AuthCapture.EVM.fee_amount(999, 100)
      9
  """
  @spec fee_amount(non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  def fee_amount(amount, bps) when is_integer(amount) and is_integer(bps),
    do: div(amount * bps, @max_bps)

  @doc since: "0.9.0"
  @doc group: :fees
  @doc """
  Checks the submitted fee and fee receiver against the client-signed
  bounds, per the spec's fee system.

  v1.1 requires `amount * minFeeBps / 10000 <= feeAmount <= amount * maxFeeBps / 10000`;
  v1.0 requires `minFeeBps <= feeBps <= maxFeeBps`. A non-zero
  `PaymentInfo.feeReceiver` must equal the submitted one; a zero one admits
  any non-zero address, and a zero submitted receiver with a non-zero fee
  reverts onchain.

  ## Examples

      iex> X402.AuthCapture.EVM.check_fee(:v1_1, 750_000, 7500, "0x2222222222222222222222222222222222222222", 100, 100, "0x2222222222222222222222222222222222222222")
      :ok

      iex> X402.AuthCapture.EVM.check_fee(:v1_1, 750_000, 7501, "0x2222222222222222222222222222222222222222", 100, 100, "0x2222222222222222222222222222222222222222")
      {:error, :fee_bps_out_of_range}

      iex> X402.AuthCapture.EVM.check_fee(:v1_0, 750_000, 50, "0x2222222222222222222222222222222222222222", 100, 100, "0x2222222222222222222222222222222222222222")
      {:error, :fee_bps_out_of_range}

      iex> X402.AuthCapture.EVM.check_fee(:v1_1, 750_000, 7500, "0x3333333333333333333333333333333333333333", 100, 100, "0x2222222222222222222222222222222222222222")
      {:error, :fee_receiver}
  """
  @spec check_fee(
          :v1_1 | :v1_0,
          non_neg_integer(),
          non_neg_integer(),
          String.t() | nil,
          non_neg_integer(),
          non_neg_integer(),
          String.t()
        ) :: :ok | {:error, :fee_bps_out_of_range | :fee_receiver | :zero_fee_receiver}
  def check_fee(version, amount, fee, submitted_receiver, min_bps, max_bps, signed_receiver) do
    cond do
      not fee_in_range?(version, amount, fee, min_bps, max_bps) ->
        {:error, :fee_bps_out_of_range}

      nonzero_address?(signed_receiver) and not same_address?(signed_receiver, submitted_receiver) ->
        {:error, :fee_receiver}

      fee > 0 and not nonzero_address?(submitted_receiver) ->
        {:error, :zero_fee_receiver}

      true ->
        :ok
    end
  end

  @spec fee_in_range?(
          :v1_1 | :v1_0,
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer()
        ) :: boolean()
  defp fee_in_range?(:v1_1, amount, fee, min_bps, max_bps),
    do: fee >= fee_amount(amount, min_bps) and fee <= fee_amount(amount, max_bps)

  defp fee_in_range?(:v1_0, _amount, fee, min_bps, max_bps),
    do: fee >= min_bps and fee <= max_bps

  # -- Calldata ---------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Returns the four-byte selector of an escrow function.

  ## Examples

      iex> X402.AuthCapture.EVM.selector(:void)
      <<0xFA, 0x1C, 0xAD, 0x17>>

      iex> X402.AuthCapture.EVM.selector(:payment_state)
      <<0x34, 0xB7, 0x78, 0xED>>
  """
  @spec selector(atom()) :: <<_::32>>
  def selector(name), do: Map.fetch!(@selectors, name)

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Returns the `0x` topic of an escrow event.

  ## Examples

      iex> X402.AuthCapture.EVM.event_topic(:voided)
      "0xcadce8c3acb008e3e1c64ca7f60d22a3c87069183182b7dbb9e4d8cfb3a15842"
  """
  @spec event_topic(atom()) :: String.t()
  def event_topic(name), do: Map.fetch!(@event_topics, name)

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `authorize(PaymentInfo, uint256 amount, address tokenCollector, bytes collectorData)`.
  """
  @spec authorize_calldata(map(), term(), String.t(), binary()) ::
          {:ok, binary()} | {:error, encode_error()}
  def authorize_calldata(info, amount, collector, collector_data)
      when is_map(info) and is_binary(collector_data) do
    with {:ok, encoded} <- encode_payment_info(info),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, collector_word} <- EIP712.encode_address(collector) do
      # Head: 12 struct words + amount + collector + bytes offset (15 words).
      head = encoded <> amount_word <> collector_word <> word(15 * 32)
      {:ok, selector(:authorize) <> head <> EIP712.encode_dynamic_bytes(collector_data)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `charge(PaymentInfo, uint256 amount, address tokenCollector, bytes collectorData, <fee>, address feeReceiver)`.

  The fee argument is `uint256 feeAmount` on v1.1 and `uint16 feeBps` on
  v1.0 — the value passes through untouched, so pass the field the
  deployment takes.
  """
  @spec charge_calldata(:v1_1 | :v1_0, map(), term(), String.t(), binary(), term(), String.t()) ::
          {:ok, binary()} | {:error, encode_error()}
  def charge_calldata(version, info, amount, collector, collector_data, fee, fee_receiver)
      when is_map(info) and is_binary(collector_data) do
    with {:ok, encoded} <- encode_payment_info(info),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, collector_word} <- EIP712.encode_address(collector),
         {:ok, fee_word} <- fee_word(version, fee),
         {:ok, receiver_word} <- EIP712.encode_address(fee_receiver) do
      # Head: 12 struct words + amount + collector + bytes offset + fee +
      # feeReceiver (17 words).
      head =
        encoded <> amount_word <> collector_word <> word(17 * 32) <> fee_word <> receiver_word

      {:ok, charge_selector(version) <> head <> EIP712.encode_dynamic_bytes(collector_data)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `capture(PaymentInfo, uint256 amount, <fee>, address feeReceiver)`
  (fee argument per `charge_calldata/7`).
  """
  @spec capture_calldata(:v1_1 | :v1_0, map(), term(), term(), String.t()) ::
          {:ok, binary()} | {:error, encode_error()}
  def capture_calldata(version, info, amount, fee, fee_receiver) when is_map(info) do
    with {:ok, encoded} <- encode_payment_info(info),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, fee_word} <- fee_word(version, fee),
         {:ok, receiver_word} <- EIP712.encode_address(fee_receiver) do
      {:ok, capture_selector(version) <> encoded <> amount_word <> fee_word <> receiver_word}
    end
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `void(PaymentInfo)`.
  """
  @spec void_calldata(map()) :: {:ok, binary()} | {:error, encode_error()}
  def void_calldata(info) when is_map(info) do
    with {:ok, encoded} <- encode_payment_info(info), do: {:ok, selector(:void) <> encoded}
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `reclaim(PaymentInfo)` — the payer's own call after the capture
  deadline, never relayed by a facilitator.
  """
  @spec reclaim_calldata(map()) :: {:ok, binary()} | {:error, encode_error()}
  def reclaim_calldata(info) when is_map(info) do
    with {:ok, encoded} <- encode_payment_info(info), do: {:ok, selector(:reclaim) <> encoded}
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `refund(PaymentInfo, uint256 amount, address tokenCollector, bytes collectorData)`.

  Facilitator-relayed refunds use the deployment's operator refund
  collector with empty `collectorData`.
  """
  @spec refund_calldata(map(), term(), String.t(), binary()) ::
          {:ok, binary()} | {:error, encode_error()}
  def refund_calldata(info, amount, collector, collector_data \\ <<>>)
      when is_map(info) and is_binary(collector_data) do
    with {:ok, encoded} <- encode_payment_info(info),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, collector_word} <- EIP712.encode_address(collector) do
      head = encoded <> amount_word <> collector_word <> word(15 * 32)
      {:ok, selector(:refund) <> head <> EIP712.encode_dynamic_bytes(collector_data)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Encodes `paymentState(bytes32 paymentInfoHash)`.
  """
  @spec payment_state_calldata(String.t()) :: {:ok, binary()} | {:error, :invalid_bytes32}
  def payment_state_calldata(payment_info_hash) do
    with {:ok, hash} <- EIP712.encode_bytes32(payment_info_hash) do
      {:ok, selector(:payment_state) <> hash}
    end
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Decodes the `paymentState(bytes32)` return data.

  ## Examples

      iex> X402.AuthCapture.EVM.decode_payment_state(
      ...>   "0x" <> String.duplicate("00", 31) <> "01" <>
      ...>     String.duplicate("00", 30) <> "2710" <> String.duplicate("00", 32)
      ...> )
      {:ok, %{collected?: true, capturable_amount: 10000, refundable_amount: 0}}

      iex> X402.AuthCapture.EVM.decode_payment_state("0x")
      {:error, :invalid_payment_state}
  """
  @spec decode_payment_state(term()) :: {:ok, payment_state()} | {:error, :invalid_payment_state}
  def decode_payment_state("0x" <> hex_digits) do
    case Base.decode16(hex_digits, case: :mixed) do
      {:ok,
       <<collected::unsigned-big-integer-size(256), capturable::unsigned-big-integer-size(256),
         refundable::unsigned-big-integer-size(256)>>}
      when collected in [0, 1] and capturable <= @max_uint120 and refundable <= @max_uint120 ->
        {:ok,
         %{
           collected?: collected != 0,
           capturable_amount: capturable,
           refundable_amount: refundable
         }}

      _other ->
        {:error, :invalid_payment_state}
    end
  end

  def decode_payment_state(_value), do: {:error, :invalid_payment_state}

  # -- Reverts ----------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Classifies a node revert onto the spec's typed simulation reverts.

  Reads the custom-error selector from the error `data` when present and
  otherwise looks for the error name in the message. Returns `nil` for an
  unmapped revert.

  ## Examples

      iex> X402.AuthCapture.EVM.classify_revert(%{code: 3, message: "execution reverted", data: "0xad7c145a"})
      :payment_already_collected

      iex> X402.AuthCapture.EVM.classify_revert(%{code: 3, message: "reverted: AfterRefundExpiry(1, 2)", data: nil})
      :refund_deadline_expired

      iex> X402.AuthCapture.EVM.classify_revert(%{code: 3, message: "boom", data: nil})
      nil
  """
  @spec classify_revert(map()) :: atom() | nil
  def classify_revert(error) when is_map(error) do
    classify_revert_data(Map.get(error, :data)) || classify_revert_text(Map.get(error, :message))
  end

  @doc since: "0.9.0"
  @doc group: :calldata
  @doc """
  Returns the custom-error selector table (`selector => {name, reason}`).
  """
  @spec custom_errors() :: %{<<_::32>> => {String.t(), atom()}}
  def custom_errors, do: @custom_errors

  # -- Internals --------------------------------------------------------------

  @spec typed_data(String.t(), map(), map()) :: map()
  defp typed_data(type, domain, message) do
    types = Map.fetch!(@wire_types, type)
    primary_type = type |> String.split("(", parts: 2) |> hd()
    version = Utils.map_value(domain, {"version", :version})

    domain_fields =
      [{"name", "string"}] ++
        if(is_nil(version), do: [], else: [{"version", "string"}]) ++
        [{"chainId", "uint256"}, {"verifyingContract", "address"}]

    domain_json = %{
      "name" => Utils.map_value(domain, {"name", :name}),
      "chainId" => Utils.map_value(domain, {"chainId", :chain_id}),
      "verifyingContract" => Utils.map_value(domain, {"verifyingContract", :verifying_contract})
    }

    %{
      "types" =>
        Map.put(
          types,
          "EIP712Domain",
          Enum.map(domain_fields, fn {name, type} ->
            %{"name" => name, "type" => type}
          end)
        ),
      "primaryType" => primary_type,
      "domain" =>
        if(is_nil(version), do: domain_json, else: Map.put(domain_json, "version", version)),
      "message" =>
        Map.new(Map.fetch!(types, primary_type), fn %{"name" => name} ->
          {name, Utils.map_value(message, {name, String.to_atom(name)})}
        end)
    }
  end

  @spec extra(map()) :: map()
  defp extra(requirements) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      %{} = extra -> extra
      _other -> %{}
    end
  end

  @spec deployment_by_escrow(String.t()) :: {:ok, deployment()} | {:error, :invalid_escrow}
  defp deployment_by_escrow(escrow) do
    Enum.find_value([@v1_1, @v1_0], {:error, :invalid_escrow}, fn deployment ->
      String.downcase(deployment.escrow) == escrow && {:ok, deployment}
    end)
  end

  @spec fetch(map(), String.t()) :: {:ok, term()} | {:error, {:missing_field, String.t()}}
  defp fetch(map, key) do
    case Utils.map_value(map, {key, String.to_atom(key)}) do
      nil -> {:error, {:missing_field, key}}
      value -> {:ok, value}
    end
  end

  @spec inner_payload(map()) :: map()
  defp inner_payload(payload) do
    case Utils.map_value(payload, {"payload", :payload}) do
      %{} = inner -> inner
      _other -> payload
    end
  end

  @spec payer_and_expiry(map()) :: {:ok, String.t(), term()} | {:error, :payload_format}
  defp payer_and_expiry(inner) do
    authorization = Utils.map_value(inner, {"authorization", :authorization})
    permit = Utils.map_value(inner, {"permit2Authorization", :permit2Authorization})

    case {present?(inner, "authorization"), present?(inner, "permit2Authorization"),
          authorization, permit} do
      {true, false, %{} = authorization, _} ->
        {:ok, Utils.map_value(authorization, {"from", :from}),
         Utils.map_value(authorization, {"validBefore", :validBefore})}

      {false, true, _, %{} = permit} ->
        {:ok, Utils.map_value(permit, {"from", :from}),
         Utils.map_value(permit, {"deadline", :deadline})}

      _other ->
        {:error, :payload_format}
    end
    |> case do
      {:ok, from, expiry} when is_binary(from) and not is_nil(expiry) -> {:ok, from, expiry}
      _other -> {:error, :payload_format}
    end
  end

  @spec present?(map(), String.t()) :: boolean()
  defp present?(map, key), do: Map.has_key?(map, key) or Map.has_key?(map, String.to_atom(key))

  @spec field(map(), String.t(), :address | :bytes32 | {:uint, non_neg_integer()}) ::
          {:ok, <<_::256>>} | {:error, {:invalid_payment_info, String.t()}}
  defp field(info, key, kind) do
    value = Utils.map_value(info, {key, String.to_atom(key)})

    result =
      case kind do
        :address -> EIP712.encode_address(value)
        :bytes32 -> EIP712.encode_bytes32(value)
        {:uint, limit} -> encode_bounded(value, limit)
      end

    case result do
      {:ok, word} -> {:ok, word}
      {:error, _reason} -> {:error, {:invalid_payment_info, key}}
    end
  end

  @spec encode_bounded(term(), non_neg_integer()) :: {:ok, <<_::256>>} | {:error, :invalid_amount}
  defp encode_bounded(value, limit) do
    case parse_uint256(value) do
      {:ok, integer} when integer <= limit ->
        {:ok, <<integer::256>>}

      _other ->
        {:error, :invalid_amount}
    end
  end

  @spec consent_words(operation(), map(), :v1_1 | :v1_0) ::
          {:ok, [<<_::256>>]} | {:error, encode_error()}
  defp consent_words(:charge, params, version) do
    with {:ok, hash} <- param(params, "paymentInfoHash", :bytes32),
         {:ok, amount} <- param(params, "amount", :uint256),
         {:ok, collector} <- param(params, "tokenCollector", :address),
         {:ok, data_hash} <- param(params, "collectorDataHash", :bytes32),
         {:ok, fee} <- fee_word(version, Utils.map_value(params, fee_key(version))),
         {:ok, receiver} <- param(params, "feeReceiver", :address) do
      {:ok, [hash, amount, collector, data_hash, fee, receiver]}
    end
  end

  defp consent_words(:capture, params, version) do
    with {:ok, hash} <- param(params, "paymentInfoHash", :bytes32),
         {:ok, amount} <- param(params, "amount", :uint256),
         {:ok, fee} <- fee_word(version, Utils.map_value(params, fee_key(version))),
         {:ok, receiver} <- param(params, "feeReceiver", :address),
         {:ok, capturable} <- param(params, "expectedCapturableAmount", :uint256),
         {:ok, refundable} <- param(params, "expectedRefundableAmount", :uint256) do
      {:ok, [hash, amount, fee, receiver, capturable, refundable]}
    end
  end

  defp consent_words(:void, params, _version) do
    with {:ok, hash} <- param(params, "paymentInfoHash", :bytes32), do: {:ok, [hash]}
  end

  defp consent_words(:refund, params, _version) do
    with {:ok, hash} <- param(params, "paymentInfoHash", :bytes32),
         {:ok, amount} <- param(params, "amount", :uint256),
         {:ok, collector} <- param(params, "tokenCollector", :address),
         {:ok, capturable} <- param(params, "expectedCapturableAmount", :uint256),
         {:ok, refundable} <- param(params, "expectedRefundableAmount", :uint256) do
      {:ok, [hash, amount, collector, capturable, refundable]}
    end
  end

  @spec fee_key(:v1_1 | :v1_0) :: {String.t(), atom()}
  defp fee_key(:v1_1), do: {"feeAmount", :feeAmount}
  defp fee_key(:v1_0), do: {"feeBps", :feeBps}

  @spec param(map(), String.t(), :bytes32 | :uint256 | :address) ::
          {:ok, <<_::256>>} | {:error, {:missing_field, String.t()} | encode_error()}
  defp param(params, key, kind) do
    case Utils.map_value(params, {key, String.to_atom(key)}) do
      nil ->
        {:error, {:missing_field, key}}

      value ->
        case kind do
          :bytes32 -> EIP712.encode_bytes32(value)
          :uint256 -> EIP712.encode_uint256(value)
          :address -> EIP712.encode_address(value)
        end
    end
  end

  @spec fee_word(:v1_1 | :v1_0, term()) :: {:ok, <<_::256>>} | {:error, encode_error()}
  defp fee_word(_version, nil), do: {:error, {:missing_field, "fee"}}
  defp fee_word(:v1_1, fee), do: EIP712.encode_uint256(fee)
  defp fee_word(:v1_0, fee), do: encode_bounded(fee, @max_uint16)

  @spec charge_selector(:v1_1 | :v1_0) :: <<_::32>>
  defp charge_selector(:v1_1), do: selector(:charge_v1_1)
  defp charge_selector(:v1_0), do: selector(:charge_v1_0)

  @spec capture_selector(:v1_1 | :v1_0) :: <<_::32>>
  defp capture_selector(:v1_1), do: selector(:capture_v1_1)
  defp capture_selector(:v1_0), do: selector(:capture_v1_0)

  @spec classify_revert_data(term()) :: atom() | nil
  defp classify_revert_data("0x" <> hex_digits) do
    case Base.decode16(hex_digits, case: :mixed) do
      {:ok, <<selector::binary-size(4), _rest::binary>>} ->
        case Map.get(@custom_errors, selector) do
          {_name, reason} -> reason
          nil -> nil
        end

      _other ->
        nil
    end
  end

  defp classify_revert_data(_data), do: nil

  @spec classify_revert_text(term()) :: atom() | nil
  defp classify_revert_text(message) when is_binary(message) do
    Enum.find_value(@custom_errors, fn {_selector, {name, reason}} ->
      String.contains?(message, name) && reason
    end)
  end

  defp classify_revert_text(_message), do: nil

  @spec same_address?(term(), term()) :: boolean()
  defp same_address?(left, right) when is_binary(left) and is_binary(right),
    do: String.downcase(left) == String.downcase(right)

  defp same_address?(_left, _right), do: false

  @spec word(non_neg_integer()) :: <<_::256>>
  defp word(value), do: <<value::unsigned-big-integer-size(256)>>

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)
end
