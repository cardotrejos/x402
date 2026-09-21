defmodule X402.Verify.AuthCaptureEVM do
  @moduledoc """
  Verification of `auth-capture` payments on EVM networks.

  Runs the spec's client-payload and lifecycle-payload checklists at one of
  three depths, mirroring `X402.Verify.EVM`:

  * `:structural` — shape, scheme, network, `extra`, operator fields,
    method routing, deadlines, collector and token match, amount and fee.
    Needs nothing.
  * `:signature` — additionally recomputes the `signatureNonce` and bound
    salt, verifies the client's ECDSA signature (or gates a counterfactual
    ERC-6492 envelope on the factory allowlist), and recovers every
    authorizer signature. Needs the optional `ex_keccak` / `ex_secp256k1`
    dependencies.
  * `:full` — additionally cross-checks the chain id, classifies the payer
    (EOA, ERC-1271, counterfactual), checks the payer balance, reads
    `paymentState` for lifecycle preconditions and single-use enforcement,
    and simulates the exact escrow call. Needs `:rpc`.

  A level never silently downgrades: a missing dependency or RPC is an
  error, not a pass.

  ## Facilitator policy

  The checklist's operator admission depends on facilitator state, passed
  as options: `:submitters` (the addresses the facilitator submits from,
  for `"delegated"`), `:operators` (the `"custom"` allowlist),
  and `:refund_funding` (whether a delegated
  refund has a funding agreement). A server-side caller that only wants
  the protocol checks leaves `:submitters` unset to skip admission.

  Receiver-authorizer delegation is not supported. Completed charges and
  lifecycle payloads require an explicit signature. Operator control alone
  is not receiver consent. Refund funding remains a separate application
  authorization decision, not something inferred from that signature.

  Full verification requires EIP-1898 block-hash references. All state
  reads use one canonical block after checking the chain, with no fallback
  to `latest`. This trusts the RPC; it is not proof of finality.

  Capture-plus-void requires `eth_simulateV1` with a block-hash parent and
  successful sequential calls. Unsupported RPCs fail closed. Custom
  operators have only structural/signature support; full verification
  rejects them until their collect outcome assertions are implemented.
  Direct callers are subject to a 64 KiB limit per signature and 78 digits
  per decimal value, independent of HTTP header limits.

  ## Results

  `{:ok, verification}` describes the operation the payload settles as,
  the reconstructed `PaymentInfo` and its hash, the resolved deployment,
  the escrow call (`target`, `calldata`), and — for a capture-and-void —
  the second leg's `void_calldata`. `{:error, {:invalid, reason}}` carries
  a reason atom `reason_string/1` maps onto the spec's wire strings.
  """

  alias X402.AuthCapture
  alias X402.AuthCapture.EVM
  alias X402.EIP3009
  alias X402.EIP712
  alias X402.ERC6492
  alias X402.Permit2
  alias X402.RPC
  alias X402.Utils

  @erc1271_selector <<0x16, 0x26, 0xBA, 0x7E>>
  @balance_of_selector <<0x70, 0xA0, 0x82, 0x31>>
  @max_bps 10_000
  @max_signature_bytes 65_536

  @typedoc "Requested verification depth."
  @type level :: :structural | :signature | :full

  @typedoc "How the client's signature was (or would be) verified."
  @type signature_type :: :eoa | :erc1271 | :erc6492_counterfactual

  @typedoc "Where an operation's consent comes from."
  @type authorizer :: :signed | :none

  @typedoc "A successful verification."
  @type verification :: %{
          operation: AuthCapture.operation(),
          level: level(),
          payer: String.t(),
          flow: AuthCapture.payment_flow(),
          operator_type: AuthCapture.operator_type(),
          method: :eip3009 | :permit2 | nil,
          chain_id: non_neg_integer(),
          deployment: EVM.deployment(),
          payment_info: EVM.payment_info(),
          payment_info_hash: String.t() | nil,
          signature_type: signature_type() | nil,
          authorizer: authorizer(),
          amount: non_neg_integer(),
          fee: non_neg_integer() | nil,
          fee_receiver: String.t() | nil,
          target: String.t(),
          submitter: String.t(),
          calldata: binary() | nil,
          void_calldata: binary() | nil,
          payment_state: EVM.payment_state() | nil
        }

  @typedoc "Why a verification failed."
  @type error ::
          {:invalid, AuthCapture.reason()}
          | :missing_dependency
          | :rpc_not_configured
          | {:rpc_error, RPC.error()}
          | {:chain_id_mismatch, non_neg_integer(), non_neg_integer()}

  @opts_schema [
    level: [
      type: {:in, [:structural, :signature, :full]},
      default: :full,
      doc: "Verification depth (see the module documentation)."
    ],
    rpc: [
      type: {:custom, RPC, :validate_config, []},
      doc: "An `X402.RPC` configuration. Required for level `:full`."
    ],
    now: [
      type: :non_neg_integer,
      doc: "Unix seconds used by the deadline checks (default: current time)."
    ],
    skew_seconds: [
      type: :non_neg_integer,
      default: 6,
      doc: "Clock-skew floor for deadline checks."
    ],
    simulate: [
      type: :boolean,
      default: true,
      doc: """
      Whether level `:full` simulates the escrow call. Counterfactual payers
      are always simulated, since the collector deploys the wallet before
      the token validates the signature.
      """
    ],
    verify_chain_id: [
      type: :boolean,
      default: true,
      doc: "Whether level `:full` cross-checks `eth_chainId` against the CAIP-2 network."
    ],
    eip6492_allowed_factories: [
      type: {:list, :string},
      default: [],
      doc: "Factory addresses (case-insensitive) a counterfactual payer may deploy through."
    ],
    submitters: [
      type: {:or, [nil, {:list, :string}]},
      default: nil,
      doc: """
      Addresses the facilitator submits from. A `"delegated"` capture
      authorizer must be one of them (`operator_not_admitted` otherwise).
      `nil` skips the admission check for server-side verification.
      """
    ],
    operators: [
      type: {:list, :map},
      default: [],
      doc: """
      The `"custom"` operator allowlist: maps with `:address` (or `"*"`)
      and `:operator_type`. Empty admits no contract operator.
      """
    ],
    refund_funding: [
      type: :boolean,
      default: false,
      doc: "Whether a `\"delegated\"` refund has an out-of-band funding agreement."
    ],
    settlement: [
      type: :boolean,
      default: false,
      doc: "Require the completed `charge` form (the `/settle` rule)."
    ]
  ]

  @doc since: "0.9.0"
  @doc """
  Verifies an `auth-capture` payment or lifecycle payload against its
  requirements.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}
  """
  @spec verify(map(), map(), keyword()) :: {:ok, verification()} | {:error, error()}
  def verify(payment_payload, requirements, opts \\ [])
      when is_map(payment_payload) and is_map(requirements) and is_list(opts) do
    with {:ok, opts} <- validate_opts(opts),
         :ok <- ensure_rpc(opts),
         {:ok, ctx} <- structural(payment_payload, requirements, opts),
         {:ok, ctx} <- pin_state(ctx, opts),
         {:ok, ctx} <- signature(ctx, opts),
         {:ok, ctx} <- full(ctx, opts) do
      {:ok, result(ctx, opts[:level])}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Verifies a lifecycle consent using pinned EOA/ERC-1271 account rules.

  Requires RPC and a capture, void, or refund envelope. Unlike `verify/3` at
  full level, this does not require the future escrow state or simulate the
  operation. It cannot authorize execution or prove refund liquidity.
  """
  @spec verify_consent(map(), map(), keyword()) :: {:ok, verification()} | {:error, term()}
  def verify_consent(envelope, requirements, opts \\ []) do
    with {:ok, opts} <- validate_opts(Keyword.put(opts, :level, :full)),
         :ok <- ensure_rpc(opts),
         {:ok, ctx} <- structural(envelope, requirements, opts),
         :ok <- ensure(ctx.operation in [:capture, :void, :refund], :payload_format),
         {:ok, ctx} <- pin_state(ctx, opts),
         {:ok, ctx} <- signature(ctx, opts),
         {:ok, ctx} <- build_calldata(ctx) do
      {:ok, result(ctx, :signature)}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Checks only the payload shape (checklist step 1) — the offline
  validation `X402.Scheme.AuthCaptureEVM.validate_payload/3` runs.
  """
  @spec validate_shape(map(), map()) :: :ok | {:error, {:invalid, AuthCapture.reason()}}
  def validate_shape(payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    with {:ok, operation} <- invalid(AuthCapture.operation(payment_payload, requirements)),
         {:ok, deployment} <- invalid(EVM.resolve_deployment(requirements), :extra),
         {:ok, _shape} <-
           shape(inner(payment_payload), operation, deployment.version,
             bound: EVM.bound?(requirements),
             settlement: false
           ) do
      :ok
    end
  end

  @doc since: "0.9.0"
  @doc """
  Validates static requirements without signing or contacting a node.

  Checks amounts, Solidity widths, deployment, operator fields, transfer
  method, payment flow and capture mode. Does not establish operator
  admission, current deadlines, or onchain funding.

  ## Examples

      iex> X402.Verify.AuthCaptureEVM.validate_requirements(%{})
      {:error, {:invalid, :scheme}}
  """
  @spec validate_requirements(map()) :: :ok | {:error, error()}
  def validate_requirements(requirements) when is_map(requirements) do
    with :ok <- ensure(map(requirements, "scheme") == AuthCapture.scheme(), :scheme),
         {:ok, _chain_id} <-
           invalid(EIP712.chain_id_from_caip2(map(requirements, "network")), :invalid_network),
         {:ok, extra} <- check_extra(requirements),
         {:ok, _deployment} <- invalid(EVM.resolve_deployment(requirements), :extra),
         {:ok, _method} <- invalid(AuthCapture.asset_transfer_method(requirements)),
         {:ok, flow} <- invalid(AuthCapture.payment_flow(requirements)),
         {:ok, mode} <- invalid(AuthCapture.capture_mode(requirements)),
         {:ok, operation} <- invalid(AuthCapture.operation(%{}, requirements)),
         {:ok, type} <- check_operator_fields(requirements, extra, operation) do
      check_capture_mode(flow, mode, type, extra)
    end
  end

  @doc since: "0.9.0"
  @doc """
  Converts a reason atom to its canonical wire string
  (`X402.AuthCapture.reason_string/1`).
  """
  @spec reason_string(AuthCapture.reason()) :: String.t()
  defdelegate reason_string(reason), to: AuthCapture

  @doc since: "0.9.0"
  @doc """
  Classifies a node revert onto the spec's typed reasons
  (`X402.AuthCapture.EVM.classify_revert/1`).
  """
  @spec classify_revert(map()) :: atom() | nil
  defdelegate classify_revert(error), to: EVM

  # -- Options ----------------------------------------------------------------

  @spec validate_opts(keyword()) :: {:ok, keyword()} | {:error, term()}
  defp validate_opts(opts) do
    case NimbleOptions.validate(opts, @opts_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, error} -> {:error, {:invalid_options, Exception.message(error)}}
    end
  end

  @spec ensure_rpc(keyword()) :: :ok | {:error, :rpc_not_configured}
  defp ensure_rpc(opts) do
    case {opts[:level], opts[:rpc]} do
      {:full, nil} -> {:error, :rpc_not_configured}
      _other -> :ok
    end
  end

  # -- Structural -------------------------------------------------------------

  @spec structural(map(), map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp structural(payment_payload, requirements, opts) do
    payload = inner(payment_payload)

    with :ok <- check_scheme(payment_payload, requirements),
         {:ok, chain_id} <- check_network(payment_payload, requirements),
         {:ok, extra} <- check_extra(requirements),
         {:ok, deployment} <- invalid(EVM.resolve_deployment(requirements), :extra),
         {:ok, flow} <- invalid(AuthCapture.payment_flow(requirements)),
         {:ok, mode} <- invalid(AuthCapture.capture_mode(requirements)),
         {:ok, operation} <- invalid(AuthCapture.operation(payment_payload, requirements)),
         {:ok, operator_type} <- check_operator(requirements, extra, operation, opts),
         :ok <- check_capture_mode(flow, mode, operator_type, extra) do
      ctx = %{
        payload: payload,
        requirements: requirements,
        extra: extra,
        chain_id: chain_id,
        deployment: deployment,
        version: deployment.version,
        flow: flow,
        operation: operation,
        operator_type: operator_type,
        receiver_authorizer: nonzero_or_nil(map(extra, "receiverAuthorizer")),
        policy: nonzero_or_nil(map(extra, "policy")),
        bound?: EVM.bound?(requirements),
        submitter: map(extra, "captureAuthorizer"),
        target: target(operator_type, deployment, extra),
        signature_type: nil,
        payment_state: nil,
        void_calldata: nil,
        calldata: nil
      }

      case lifecycle_operation?(operation) do
        true -> structural_lifecycle(ctx, opts)
        false -> structural_collect(ctx, opts)
      end
    end
  end

  @spec structural_collect(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp structural_collect(ctx, opts) do
    with {:ok, shape} <-
           shape(ctx.payload, ctx.operation, ctx.version,
             bound: ctx.bound?,
             settlement: opts[:settlement]
           ),
         {:ok, method} <- invalid(AuthCapture.asset_transfer_method(ctx.requirements)),
         :ok <- check_method(method, shape.method),
         :ok <- invalid(AuthCapture.check_deadlines(ctx.requirements, time_opts(opts))),
         :ok <-
           invalid(
             AuthCapture.check_authorization_window(
               shape.valid_after,
               shape.expiry,
               map(ctx.extra, "captureDeadline"),
               time_opts(opts)
             )
           ),
         :ok <- check_collector(shape, method, ctx.deployment),
         :ok <- check_token(shape, method, ctx.requirements),
         {:ok, required_amount} <- uint(map(ctx.requirements, "amount"), :amount_mismatch),
         {:ok, signed_amount} <- uint(shape.value, :amount_mismatch),
         :ok <- ensure(signed_amount == required_amount, :amount_mismatch),
         {:ok, amount, fee, fee_receiver} <- charge_terms(ctx, shape, required_amount),
         {:ok, payment_info} <-
           invalid(
             EVM.payment_info(ctx.requirements, shape.payer, shape.expiry, shape.salt),
             :extra
           ) do
      {:ok,
       Map.merge(ctx, %{
         method: method,
         shape: shape,
         payer: shape.payer,
         payment_info: payment_info,
         amount: amount,
         fee: fee,
         fee_receiver: fee_receiver,
         collector: AuthCapture.collector(ctx.deployment, method),
         authorizer:
           if(shape.completed?, do: consent_source(shape.authorizer_signature), else: :none)
       })}
    end
  end

  @spec structural_lifecycle(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp structural_lifecycle(ctx, opts) do
    with :ok <- check_lifecycle_admitted(ctx, opts),
         {:ok, shape} <-
           lifecycle_shape(ctx.payload, ctx.operation, ctx.version),
         :ok <-
           ensure(
             same_address?(map(shape.payment_info, "operator"), ctx.submitter),
             :operator_mismatch
           ),
         :ok <- check_payment_info_matches(shape.payment_info, ctx),
         {:ok, amount, fee, fee_receiver} <- lifecycle_terms(ctx, shape) do
      {:ok,
       Map.merge(ctx, %{
         method: nil,
         shape: shape,
         payer: map(shape.payment_info, "payer"),
         payment_info: shape.payment_info,
         amount: amount,
         fee: fee,
         fee_receiver: fee_receiver,
         collector: ctx.deployment.refund_collector,
         authorizer: consent_source(shape.authorizer_signature)
       })}
    end
  end

  # -- Signature --------------------------------------------------------------

  @spec signature(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp signature(ctx, opts) do
    case opts[:level] do
      :structural -> {:ok, Map.merge(ctx, %{payment_info_hash: nil, signature_type: nil})}
      _level -> signature_checks(ctx, opts)
    end
  end

  @spec signature_checks(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp signature_checks(ctx, opts) do
    with {:ok, hash} <-
           dependency(
             EVM.payment_info_hash(ctx.chain_id, ctx.deployment.escrow, ctx.payment_info)
           ),
         ctx = Map.put(ctx, :payment_info_hash, hash),
         :ok <- check_salt_binding(ctx),
         {:ok, ctx} <- check_identity_and_client_signature(ctx, opts),
         {:ok, ctx} <- classify_authorizer(ctx, opts),
         :ok <- check_consent(ctx, opts),
         :ok <- check_void_consent(ctx, opts) do
      {:ok, ctx}
    end
  end

  @spec check_salt_binding(map()) :: :ok | {:error, error()}
  defp check_salt_binding(%{bound?: false}), do: :ok

  defp check_salt_binding(ctx) do
    with {:ok, expected} <-
           dependency(EVM.bound_salt(ctx.receiver_authorizer, ctx.policy, ctx.shape.salt_nonce)) do
      ensure(same_hex?(expected, map(ctx.payment_info, "salt")), :salt_binding_mismatch)
    end
  end

  @spec check_identity_and_client_signature(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp check_identity_and_client_signature(%{operation: operation} = ctx, _opts)
       when operation in [:capture, :void, :refund],
       do: {:ok, ctx}

  defp check_identity_and_client_signature(ctx, opts) do
    with {:ok, nonce} <-
           dependency(EVM.signature_nonce(ctx.chain_id, ctx.deployment.escrow, ctx.payment_info)),
         :ok <- check_nonce(ctx.method, nonce, ctx.shape.nonce),
         {:ok, digest} <- dependency(client_digest(ctx)),
         {:ok, parsed} <- invalid(ERC6492.parse_bytes(ctx.shape.signature_bytes), :signature),
         {:ok, signature_type} <- classify_client_signature(ctx, digest, parsed, opts) do
      {:ok,
       Map.merge(ctx, %{
         digest: digest,
         parsed: parsed,
         signature_type: signature_type,
         collector_data: EVM.collector_data(ctx.method, ctx.shape.signature_bytes)
       })}
    end
  end

  @spec check_nonce(:eip3009 | :permit2, String.t(), term()) :: :ok | {:error, error()}
  defp check_nonce(:eip3009, expected, wire),
    do: ensure(is_binary(wire) and same_hex?(expected, wire), :nonce_mismatch)

  defp check_nonce(:permit2, expected, wire) do
    with {:ok, decimal} <- dependency(EVM.permit2_nonce(expected)) do
      ensure(is_binary(wire) and wire == decimal, :nonce_mismatch)
    end
  end

  @spec client_digest(map()) :: {:ok, binary()} | {:error, term()}
  defp client_digest(%{method: :eip3009} = ctx) do
    with {:ok, domain} <- EIP712.domain(ctx.requirements) do
      EVM.receive_authorization_digest(domain, ctx.shape.authorization)
    end
  end

  defp client_digest(%{method: :permit2} = ctx) do
    with {:ok, domain} <- Permit2.domain(ctx.requirements) do
      EVM.permit_transfer_digest(domain, ctx.shape.authorization)
    end
  end

  # At :signature the payer's code is unknown: a 6492 envelope is gated on
  # the factory allowlist and proven later by simulation, everything else
  # must recover as ECDSA. :full re-classifies against eth_getCode.
  @spec classify_client_signature(map(), binary(), ERC6492.parsed(), keyword()) ::
          {:ok, signature_type()} | {:error, error()}
  defp classify_client_signature(_ctx, _digest, %{wrapped?: true} = parsed, opts) do
    allowed = Enum.map(opts[:eip6492_allowed_factories], &String.downcase/1)

    case is_binary(parsed.factory) and String.downcase(parsed.factory) in allowed do
      true -> {:ok, :erc6492_counterfactual}
      false -> {:error, {:invalid, :erc6492_factory_not_allowed}}
    end
  end

  defp classify_client_signature(ctx, digest, parsed, opts) do
    case opts[:level] do
      :full -> {:ok, :erc1271}
      :signature -> eoa_signature(digest, parsed.inner_signature, ctx.payer, :signature)
    end
  end

  @spec eoa_signature(binary(), binary(), String.t(), atom()) :: {:ok, :eoa} | {:error, error()}
  defp eoa_signature(digest, signature, address, reason) do
    case recover(digest, signature, address) do
      :ok -> {:ok, :eoa}
      :mismatch -> {:error, {:invalid, reason}}
      {:error, error} -> {:error, error}
    end
  end

  @spec recover(binary(), binary(), String.t()) :: :ok | :mismatch | {:error, error()}
  defp recover(digest, signature, expected) do
    case EIP3009.recover_signer(digest, signature) do
      {:ok, address} -> if same_address?(address, expected), do: :ok, else: :mismatch
      {:error, :missing_dependency} -> {:error, :missing_dependency}
      {:error, _reason} -> :mismatch
    end
  end

  @spec check_consent(map(), keyword()) :: :ok | {:error, error()}
  defp check_consent(%{authorizer: :none}, _opts), do: :ok

  defp check_consent(ctx, opts) do
    with {:ok, params} <- consent_params(ctx),
         {:ok, digest} <-
           dependency(EVM.consent_digest(ctx.operation, params, domain(ctx), ctx.version)) do
      check_authorizer_signature(
        ctx,
        digest,
        ctx.shape.authorizer_signature,
        :authorizer_signature,
        opts
      )
    end
  end

  @spec check_void_consent(map(), keyword()) :: :ok | {:error, error()}
  defp check_void_consent(%{shape: %{void_signature: signature}} = ctx, opts)
       when is_binary(signature) do
    with {:ok, digest} <-
           dependency(
             EVM.consent_digest(
               :void,
               %{"paymentInfoHash" => ctx.payment_info_hash},
               domain(ctx),
               :v1_1
             )
           ) do
      check_authorizer_signature(ctx, digest, signature, :void_authorizer_signature, opts)
    end
  end

  defp check_void_consent(_ctx, _opts), do: :ok

  # Deployed accounts must accept the signature through ERC-1271, even
  # when an ECDSA key also recovers to their address (for example EIP-7702).
  @spec check_authorizer_signature(map(), binary(), String.t(), atom(), keyword()) ::
          :ok | {:error, error()}
  defp check_authorizer_signature(ctx, digest, signature, reason, opts) do
    with {:ok, bytes} <- invalid(decode_hex(signature), reason) do
      case opts[:level] do
        :full ->
          check_account_signature(
            ctx.authorizer_deployed?,
            opts[:rpc],
            ctx.block,
            ctx.receiver_authorizer,
            digest,
            bytes,
            reason
          )

        :signature ->
          check_eoa_signature(ctx.receiver_authorizer, digest, bytes, reason)
      end
    end
  end

  @spec classify_authorizer(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp classify_authorizer(ctx, opts) do
    if opts[:level] == :full and ctx.authorizer == :signed do
      with {:ok, deployed?} <- account_deployed?(opts[:rpc], ctx.receiver_authorizer, ctx.block) do
        {:ok, Map.put(ctx, :authorizer_deployed?, deployed?)}
      end
    else
      {:ok, ctx}
    end
  end

  @spec check_account_signature(boolean(), RPC.t(), map(), String.t(), binary(), binary(), atom()) ::
          :ok | {:error, error()}
  defp check_account_signature(true, rpc, block, account, digest, bytes, reason),
    do: erc1271(rpc, block, account, digest, bytes, reason)

  defp check_account_signature(false, _rpc, _block, account, digest, bytes, reason),
    do: check_eoa_signature(account, digest, bytes, reason)

  @spec check_eoa_signature(String.t(), binary(), binary(), atom()) :: :ok | {:error, error()}
  defp check_eoa_signature(account, digest, bytes, reason) do
    with {:ok, :eoa} <- eoa_signature(digest, bytes, account, reason), do: :ok
  end

  @spec consent_params(map()) :: {:ok, map()} | {:error, error()}
  defp consent_params(%{operation: :charge} = ctx) do
    with {:ok, keccak} <- EIP712.keccak_module() do
      {:ok,
       %{
         "paymentInfoHash" => ctx.payment_info_hash,
         "amount" => ctx.amount,
         "tokenCollector" => ctx.collector,
         "collectorDataHash" => hex(keccak.hash_256(ctx.collector_data)),
         EVM.fee_field(ctx.version) => ctx.fee,
         "feeReceiver" => ctx.fee_receiver
       }}
    end
  end

  defp consent_params(%{operation: :capture} = ctx) do
    {:ok,
     %{
       "paymentInfoHash" => ctx.payment_info_hash,
       "amount" => ctx.amount,
       EVM.fee_field(ctx.version) => ctx.fee,
       "feeReceiver" => ctx.fee_receiver,
       "expectedCapturableAmount" => ctx.shape.expected_capturable,
       "expectedRefundableAmount" => ctx.shape.expected_refundable
     }}
  end

  defp consent_params(%{operation: :void} = ctx),
    do: {:ok, %{"paymentInfoHash" => ctx.payment_info_hash}}

  defp consent_params(%{operation: :refund} = ctx) do
    {:ok,
     %{
       "paymentInfoHash" => ctx.payment_info_hash,
       "amount" => ctx.amount,
       "tokenCollector" => ctx.deployment.refund_collector,
       "expectedCapturableAmount" => ctx.shape.expected_capturable,
       "expectedRefundableAmount" => ctx.shape.expected_refundable
     }}
  end

  # -- Full -------------------------------------------------------------------

  @spec pin_state(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp pin_state(ctx, opts) do
    case opts[:level] do
      :full ->
        with :ok <- check_chain_id(opts[:rpc], ctx.chain_id, opts[:verify_chain_id]),
             {:ok, block} <-
               rpc(RPC.request(opts[:rpc], "eth_getBlockByNumber", ["latest", false])),
             {:ok, reference} <- block_reference(block) do
          {:ok, Map.put(ctx, :block, reference)}
        end

      _level ->
        {:ok, ctx}
    end
  end

  @spec block_reference(term()) :: {:ok, map()} | {:error, error()}
  defp block_reference(%{"hash" => hash, "number" => number} = block) do
    with {:ok, _hash} <- EIP712.encode_bytes32(hash),
         {:ok, _number} <- RPC.decode_quantity(number) do
      {:ok, %{"blockHash" => String.downcase(hash), "requireCanonical" => true}}
    else
      _error -> {:error, {:rpc_error, {:invalid_response, block}}}
    end
  end

  defp block_reference(other), do: {:error, {:rpc_error, {:invalid_response, other}}}

  @spec full(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp full(ctx, opts) do
    case opts[:level] do
      :full -> full_checks(ctx, opts)
      _level -> build_calldata(ctx)
    end
  end

  @spec full_checks(map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp full_checks(%{operator_type: :custom}, _opts),
    do: {:error, {:invalid, :unsupported_operator_type}}

  defp full_checks(ctx, opts) do
    rpc = opts[:rpc]

    with :ok <- check_contracts(rpc, ctx),
         {:ok, ctx} <- classify_payer(rpc, ctx),
         {:ok, ctx} <- read_preconditions(rpc, ctx, opts),
         {:ok, ctx} <- build_calldata(ctx),
         :ok <- simulate(rpc, ctx, opts) do
      {:ok, ctx}
    end
  end

  @spec check_contracts(RPC.t(), map()) :: :ok | {:error, error()}
  defp check_contracts(rpc, ctx) do
    collectors = if ctx.operation in [:authorize, :charge, :refund], do: [ctx.collector], else: []
    permit2 = if ctx.method == :permit2, do: [Permit2.permit2_address()], else: []

    ([ctx.deployment.escrow, map(ctx.requirements, "asset")] ++ collectors ++ permit2)
    |> Enum.uniq_by(&String.downcase/1)
    |> Enum.reduce_while(:ok, fn address, :ok ->
      case account_deployed?(rpc, address, ctx.block) do
        {:ok, true} -> {:cont, :ok}
        {:ok, false} -> {:halt, {:error, {:invalid, :simulation_failed}}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  @spec check_chain_id(RPC.t(), non_neg_integer(), boolean()) :: :ok | {:error, error()}
  defp check_chain_id(_rpc, _chain_id, false), do: :ok

  defp check_chain_id(rpc, chain_id, true) do
    with {:ok, hex} <- rpc(RPC.chain_id(rpc)) do
      case RPC.decode_quantity(hex) do
        {:ok, ^chain_id} -> :ok
        {:ok, other} -> {:error, {:chain_id_mismatch, chain_id, other}}
        {:error, :invalid_quantity} -> {:error, {:rpc_error, {:invalid_response, hex}}}
      end
    end
  end

  # Collect payloads: the payer's code decides between EOA and ERC-1271,
  # and a counterfactual envelope must find no code yet. Lifecycle payloads
  # carry no client signature.
  @spec classify_payer(RPC.t(), map()) :: {:ok, map()} | {:error, error()}
  defp classify_payer(_rpc, %{signature_type: nil} = ctx), do: {:ok, ctx}

  defp classify_payer(rpc, ctx) do
    with {:ok, deployed?} <- account_deployed?(rpc, ctx.payer, ctx.block) do
      classify_payer_code(deployed?, rpc, ctx)
    end
  end

  @spec classify_payer_code(boolean(), RPC.t(), map()) :: {:ok, map()} | {:error, error()}
  defp classify_payer_code(true, rpc, ctx) do
    with :ok <-
           erc1271(rpc, ctx.block, ctx.payer, ctx.digest, ctx.parsed.inner_signature, :signature) do
      {:ok, %{ctx | signature_type: :erc1271}}
    end
  end

  defp classify_payer_code(false, _rpc, %{parsed: %{wrapped?: true}} = ctx),
    do: {:ok, %{ctx | signature_type: :erc6492_counterfactual}}

  defp classify_payer_code(false, _rpc, ctx) do
    with {:ok, :eoa} <-
           eoa_signature(ctx.digest, ctx.parsed.inner_signature, ctx.payer, :signature) do
      {:ok, %{ctx | signature_type: :eoa}}
    end
  end

  @spec account_deployed?(RPC.t(), String.t(), map()) :: {:ok, boolean()} | {:error, error()}
  defp account_deployed?(rpc, account, block) do
    with {:ok, code} <- rpc(RPC.get_code(rpc, account, block)) do
      decode_code(code)
    end
  end

  @spec decode_code(term()) :: {:ok, boolean()} | {:error, error()}
  defp decode_code("0x" <> hex = code) do
    case Base.decode16(hex, case: :mixed) do
      {:ok, bytes} -> {:ok, bytes != <<>>}
      :error -> {:error, {:rpc_error, {:invalid_response, code}}}
    end
  end

  defp decode_code(code), do: {:error, {:rpc_error, {:invalid_response, code}}}

  @spec read_preconditions(RPC.t(), map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp read_preconditions(rpc, %{operation: operation} = ctx, _opts)
       when operation in [:authorize, :charge] do
    calldata = @balance_of_selector <> address_word(ctx.payer)

    with {:ok, hex} <-
           rpc(
             RPC.call(
               rpc,
               %{"to" => map(ctx.requirements, "asset"), "data" => hex(calldata)},
               ctx.block
             )
           ),
         {:ok, balance} <- parse_word(hex) do
      case balance >= ctx.amount do
        true -> {:ok, ctx}
        false -> {:error, {:invalid, :insufficient_balance}}
      end
    end
  end

  defp read_preconditions(rpc, ctx, opts) do
    with {:ok, calldata} <- dependency(EVM.payment_state_calldata(ctx.payment_info_hash)),
         {:ok, hex} <-
           rpc(
             RPC.call(rpc, %{"to" => ctx.deployment.escrow, "data" => hex(calldata)}, ctx.block)
           ),
         {:ok, state} <- rpc_shape(EVM.decode_payment_state(hex), hex),
         :ok <- check_preconditions(ctx, state, opts) do
      {:ok, Map.put(ctx, :payment_state, state)}
    end
  end

  @spec check_preconditions(map(), EVM.payment_state(), keyword()) :: :ok | {:error, error()}
  defp check_preconditions(%{operation: :capture} = ctx, state, opts) do
    now = now(opts)

    with {:ok, expiry} <- uint(map(ctx.payment_info, "authorizationExpiry"), :extra),
         :ok <- ensure(now < expiry, :capture_deadline_expired),
         :ok <- ensure(ctx.amount <= state.capturable_amount, :insufficient_authorization),
         :ok <- check_single_use(ctx, state) do
      case ctx.shape.void_signature do
        nil -> :ok
        _signature -> ensure(ctx.amount < state.capturable_amount, :void_remainder_full_capture)
      end
    end
  end

  defp check_preconditions(%{operation: :void}, state, _opts),
    do: ensure(state.capturable_amount > 0, :zero_authorization)

  defp check_preconditions(%{operation: :refund} = ctx, state, opts) do
    now = now(opts)

    with {:ok, expiry} <- uint(map(ctx.payment_info, "refundExpiry"), :extra),
         :ok <- ensure(now < expiry, :refund_deadline_expired),
         :ok <- ensure(ctx.amount <= state.refundable_amount, :refund_exceeds_capture) do
      check_single_use(ctx, state)
    end
  end

  @spec check_single_use(map(), EVM.payment_state()) :: :ok | {:error, error()}
  defp check_single_use(ctx, state) do
    with {:ok, capturable} <- uint(ctx.shape.expected_capturable, :payload_format),
         {:ok, refundable} <- uint(ctx.shape.expected_refundable, :payload_format) do
      ensure(
        capturable == state.capturable_amount and refundable == state.refundable_amount,
        :unexpected_payment_state
      )
    end
  end

  @spec build_calldata(map()) :: {:ok, map()} | {:error, error()}
  defp build_calldata(%{payment_info_hash: nil} = ctx), do: {:ok, ctx}

  defp build_calldata(ctx) do
    info = ctx.payment_info

    result =
      case ctx.operation do
        :authorize ->
          EVM.authorize_calldata(info, ctx.amount, ctx.collector, ctx.collector_data)

        :charge ->
          EVM.charge_calldata(
            ctx.version,
            info,
            ctx.amount,
            ctx.collector,
            ctx.collector_data,
            ctx.fee,
            ctx.fee_receiver
          )

        :capture ->
          EVM.capture_calldata(ctx.version, info, ctx.amount, ctx.fee, ctx.fee_receiver)

        :void ->
          EVM.void_calldata(info)

        :refund ->
          EVM.refund_calldata(info, ctx.amount, ctx.deployment.refund_collector)
      end

    with {:ok, calldata} <- dependency(result),
         {:ok, void_calldata} <- void_leg(ctx) do
      {:ok, %{ctx | calldata: calldata, void_calldata: void_calldata}}
    end
  end

  @spec void_leg(map()) :: {:ok, binary() | nil} | {:error, error()}
  defp void_leg(%{operation: :capture, shape: %{void_signature: signature}} = ctx)
       when is_binary(signature),
       do: dependency(EVM.void_calldata(ctx.payment_info))

  defp void_leg(_ctx), do: {:ok, nil}

  # The exact call settlement will submit, from the operator the escrow
  # admits. A counterfactual payer is only ever proven here — the collector
  # deploys the wallet before the token validates the signature — so it
  # simulates even when simulation is off.
  @spec simulate(RPC.t(), map(), keyword()) :: :ok | {:error, error()}
  defp simulate(rpc, ctx, opts) do
    if opts[:simulate] or ctx.signature_type == :erc6492_counterfactual do
      simulate_operations(rpc, ctx)
    else
      :ok
    end
  end

  @spec simulate_operations(RPC.t(), map()) :: :ok | {:error, error()}
  defp simulate_operations(rpc, %{void_calldata: nil} = ctx) do
    simulate_result(RPC.call(rpc, simulation_call(ctx, ctx.calldata), ctx.block))
  end

  defp simulate_operations(rpc, ctx) do
    params = %{
      "blockStateCalls" => [
        %{
          "calls" => [
            simulation_call(ctx, ctx.calldata),
            simulation_call(ctx, ctx.void_calldata)
          ]
        }
      ],
      "validation" => false,
      "traceTransfers" => false
    }

    parent = ctx.block["blockHash"]

    with :ok <- sequential_result(RPC.request(rpc, "eth_simulateV1", [params, parent]), parent),
         {:ok, deployed?} <- account_deployed?(rpc, ctx.deployment.escrow, ctx.block) do
      ensure(deployed?, :simulation_failed)
    end
  end

  @spec sequential_result(term(), String.t()) :: :ok | {:error, error()}
  defp sequential_result(
         {:ok,
          [
            %{
              "parentHash" => parent,
              "calls" => [
                %{"status" => "0x1", "returnData" => "0x"},
                %{"status" => "0x1", "returnData" => "0x"}
              ]
            }
          ]},
         parent
       ),
       do: :ok

  defp sequential_result({:ok, _other}, _parent), do: {:error, {:invalid, :simulation_failed}}
  defp sequential_result({:error, error}, _parent), do: simulate_result({:error, error})

  @spec simulation_call(map(), binary()) :: map()
  defp simulation_call(ctx, calldata),
    do: %{"from" => ctx.submitter, "to" => ctx.target, "data" => hex(calldata)}

  @spec simulate_result(term()) :: :ok | {:error, error()}
  defp simulate_result({:ok, "0x"}), do: :ok
  defp simulate_result({:ok, _other}), do: {:error, {:invalid, :simulation_failed}}

  defp simulate_result({:error, {:jsonrpc_error, error}}),
    do: {:error, {:invalid, classify_revert(error) || :simulation_failed}}

  defp simulate_result({:error, reason}), do: {:error, {:rpc_error, reason}}

  @spec erc1271(RPC.t(), map(), String.t(), binary(), binary(), atom()) :: :ok | {:error, error()}
  defp erc1271(rpc, block, account, digest, signature, reason) do
    calldata =
      @erc1271_selector <>
        digest <> <<64::unsigned-big-integer-size(256)>> <> EIP712.encode_dynamic_bytes(signature)

    case RPC.call(rpc, %{"to" => account, "data" => hex(calldata)}, block) do
      {:ok, "0x" <> hex_digits} ->
        case Base.decode16(hex_digits, case: :mixed) do
          {:ok, <<@erc1271_selector, 0::224>>} -> :ok
          _other -> {:error, {:invalid, reason}}
        end

      {:ok, _other} ->
        {:error, {:invalid, reason}}

      {:error, {:jsonrpc_error, _error}} ->
        {:error, {:invalid, reason}}

      {:error, error} ->
        {:error, {:rpc_error, error}}
    end
  end

  # -- Structural helpers -----------------------------------------------------

  @spec check_capture_mode(
          AuthCapture.payment_flow(),
          AuthCapture.capture_mode(),
          AuthCapture.operator_type(),
          map()
        ) ::
          :ok | {:error, error()}
  defp check_capture_mode(:escrow, :sync, type, extra) do
    ensure(type == :delegated and EVM.nonzero_address?(map(extra, "receiverAuthorizer")), :extra)
  end

  defp check_capture_mode(_flow, _mode, _type, _extra), do: :ok

  @spec check_scheme(map(), map()) :: :ok | {:error, error()}
  defp check_scheme(payment_payload, requirements) do
    accepted = map(payment_payload, "accepted") || %{}
    scheme = AuthCapture.scheme()

    with :ok <- ensure(map(payment_payload, "x402Version") == 2, :invalid_x402_version),
         :ok <- ensure(map(requirements, "scheme") == scheme, :scheme) do
      ensure(map(accepted, "scheme") == scheme, :scheme)
    end
  end

  @spec check_network(map(), map()) :: {:ok, non_neg_integer()} | {:error, error()}
  defp check_network(payment_payload, requirements) do
    accepted = map(payment_payload, "accepted") || %{}
    network = map(requirements, "network")

    with {:ok, chain_id} <- invalid(EIP712.chain_id_from_caip2(network), :invalid_network),
         :ok <- ensure(map(accepted, "network") == network, :network_mismatch) do
      {:ok, chain_id}
    end
  end

  @spec check_extra(map()) :: {:ok, map()} | {:error, error()}
  defp check_extra(requirements) do
    extra = map(requirements, "extra")

    with true <- is_map(extra),
         true <- EVM.nonzero_address?(map(requirements, "asset")),
         true <- EVM.nonzero_address?(map(requirements, "payTo")),
         {:ok, amount} <- uint(map(requirements, "amount")),
         true <- amount > 0 and amount < Integer.pow(2, 120),
         true <- is_integer(map(requirements, "maxTimeoutSeconds")),
         true <- map(requirements, "maxTimeoutSeconds") >= 0,
         true <- EVM.nonzero_address?(map(extra, "captureAuthorizer")),
         true <- address?(map(extra, "feeRecipient")),
         {:ok, capture} <- uint(map(extra, "captureDeadline")),
         {:ok, refund} <- uint(map(extra, "refundDeadline")),
         true <- capture <= refund and refund < Integer.pow(2, 48),
         {:ok, min_bps} <- uint(map(extra, "minFeeBps")),
         {:ok, max_bps} <- uint(map(extra, "maxFeeBps")),
         true <- min_bps <= max_bps and max_bps <= @max_bps,
         true <- is_binary(map(extra, "name")) and map(extra, "name") != "",
         true <- is_binary(map(extra, "version")) and map(extra, "version") != "",
         true <- address_or_nil?(map(extra, "receiverAuthorizer")),
         true <- address_or_nil?(map(extra, "policy")),
         # A zero fee receiver lets the submitter name any recipient, so the
         # signed bounds must leave nothing to take.
         true <- EVM.nonzero_address?(map(extra, "feeRecipient")) or max_bps == 0 do
      {:ok, extra}
    else
      _failure -> {:error, {:invalid, :extra}}
    end
  end

  @spec check_operator(map(), map(), AuthCapture.operation(), keyword()) ::
          {:ok, AuthCapture.operator_type()} | {:error, error()}
  defp check_operator(requirements, extra, operation, opts) do
    with {:ok, type} <- check_operator_fields(requirements, extra, operation),
         :ok <- check_admission(type, map(extra, "captureAuthorizer"), opts) do
      {:ok, type}
    end
  end

  @spec check_operator_fields(map(), map(), AuthCapture.operation()) ::
          {:ok, AuthCapture.operator_type()} | {:error, error()}
  defp check_operator_fields(requirements, extra, operation) do
    with {:ok, type} <- invalid(AuthCapture.operator_type(requirements)),
         :ok <- ensure(type != :policy, :unsupported_operator_type),
         :ok <- ensure(not EVM.nonzero_address?(map(extra, "policy")), :policy),
         :ok <- check_receiver_authorizer(operation, map(extra, "receiverAuthorizer")) do
      {:ok, type}
    end
  end

  @spec check_admission(AuthCapture.operator_type(), String.t(), keyword()) ::
          :ok | {:error, error()}
  defp check_admission(:delegated, authorizer, opts) do
    case opts[:submitters] do
      nil ->
        :ok

      submitters ->
        ensure(Enum.any?(submitters, &same_address?(&1, authorizer)), :operator_not_admitted)
    end
  end

  defp check_admission(:custom, authorizer, opts) do
    admitted? =
      Enum.any?(opts[:operators], fn operator ->
        address = Utils.map_value(operator, {"address", :address})
        type = Utils.map_value(operator, {"operatorType", :operator_type})

        to_string(type) == "custom" and (address == "*" or same_address?(address, authorizer))
      end)

    ensure(admitted?, :operator_not_admitted)
  end

  @spec check_receiver_authorizer(AuthCapture.operation(), term()) :: :ok | {:error, error()}
  defp check_receiver_authorizer(:authorize, _authorizer), do: :ok

  defp check_receiver_authorizer(_operation, authorizer),
    do: ensure(EVM.nonzero_address?(authorizer), :missing_receiver_authorizer)

  @spec check_lifecycle_admitted(map(), keyword()) :: :ok | {:error, error()}
  defp check_lifecycle_admitted(ctx, opts) do
    with :ok <-
           ensure(
             ctx.operator_type == :delegated and not is_nil(ctx.receiver_authorizer),
             :lifecycle_not_relayed
           ) do
      case ctx.operation do
        :refund -> ensure(opts[:refund_funding], :refund_funding_unavailable)
        _operation -> :ok
      end
    end
  end

  @spec check_method(:eip3009 | :permit2, :eip3009 | :permit2) :: :ok | {:error, error()}
  defp check_method(method, method), do: :ok
  defp check_method(_method, _shape), do: {:error, {:invalid, :payload_method_mismatch}}

  @spec check_collector(map(), :eip3009 | :permit2, EVM.deployment()) :: :ok | {:error, error()}
  defp check_collector(shape, method, deployment) do
    expected = AuthCapture.collector(deployment, method)

    actual =
      if method == :eip3009,
        do: map(shape.authorization, "to"),
        else: map(shape.authorization, "spender")

    ensure(same_address?(actual, expected), :token_collector_mismatch)
  end

  @spec check_token(map(), :eip3009 | :permit2, map()) :: :ok | {:error, error()}
  defp check_token(_shape, :eip3009, _requirements), do: :ok

  defp check_token(shape, :permit2, requirements) do
    token =
      Utils.nested_map_value(shape.authorization, [{"permitted", :permitted}, {"token", :token}])

    ensure(same_address?(token, map(requirements, "asset")), :token_mismatch)
  end

  # A raw /verify charge simulates the provisional full amount at the
  # default fee; a completed charge carries its own terms.
  @spec charge_terms(map(), map(), non_neg_integer()) ::
          {:ok, non_neg_integer(), non_neg_integer() | nil, String.t() | nil} | {:error, error()}
  defp charge_terms(%{operation: :authorize}, _shape, amount), do: {:ok, amount, nil, nil}

  defp charge_terms(%{operation: :charge} = ctx, %{completed?: false}, amount),
    do: {:ok, amount, default_fee(ctx, amount), map(ctx.extra, "feeRecipient")}

  defp charge_terms(%{operation: :charge} = ctx, shape, required_amount) do
    with {:ok, amount} <- uint(shape.amount, :amount_mismatch),
         :ok <- ensure(amount > 0 and amount <= required_amount, :amount_mismatch),
         {:ok, fee} <- uint(shape.fee, :fee_bps_out_of_range),
         :ok <- check_fee(ctx, amount, fee, shape.fee_receiver) do
      {:ok, amount, fee, shape.fee_receiver}
    end
  end

  @spec lifecycle_terms(map(), map()) ::
          {:ok, non_neg_integer(), non_neg_integer() | nil, String.t() | nil} | {:error, error()}
  defp lifecycle_terms(%{operation: :void}, _shape), do: {:ok, 0, nil, nil}

  defp lifecycle_terms(%{operation: :refund}, shape) do
    with {:ok, amount} <- uint(shape.amount, :amount_mismatch),
         :ok <- ensure(amount > 0, :amount_mismatch) do
      {:ok, amount, nil, nil}
    end
  end

  defp lifecycle_terms(%{operation: :capture} = ctx, shape) do
    with {:ok, amount} <- uint(shape.amount, :amount_mismatch),
         :ok <- ensure(amount > 0, :amount_mismatch),
         {:ok, fee} <- uint(shape.fee, :fee_bps_out_of_range),
         :ok <- check_fee(ctx, amount, fee, shape.fee_receiver) do
      {:ok, amount, fee, shape.fee_receiver}
    end
  end

  @spec check_fee(map(), non_neg_integer(), non_neg_integer(), String.t()) ::
          :ok | {:error, error()}
  defp check_fee(ctx, amount, fee, fee_receiver) do
    with {:ok, min_bps} <- uint(map(ctx.extra, "minFeeBps"), :extra),
         {:ok, max_bps} <- uint(map(ctx.extra, "maxFeeBps"), :extra) do
      invalid(
        EVM.check_fee(
          ctx.version,
          amount,
          fee,
          fee_receiver,
          min_bps,
          max_bps,
          map(ctx.extra, "feeRecipient")
        )
      )
    end
  end

  @spec default_fee(map(), non_neg_integer()) :: non_neg_integer()
  defp default_fee(ctx, amount) do
    {:ok, min_bps} = uint(map(ctx.extra, "minFeeBps"))

    case ctx.version do
      :v1_1 -> EVM.fee_amount(amount, min_bps)
      :v1_0 -> min_bps
    end
  end

  @spec check_payment_info_matches(map(), map()) :: :ok | {:error, error()}
  defp check_payment_info_matches(info, ctx) do
    invalid(EVM.match_payment_info(ctx.requirements, info), :payload_format)
  end

  # -- Shape guards -----------------------------------------------------------

  # Step 1 of the client checklist: exactly one authorization shape,
  # signature and salt present, saltNonce iff bound, and the four charge
  # completion fields all present or all absent.
  @spec shape(map(), AuthCapture.operation(), :v1_1 | :v1_0, keyword()) ::
          {:ok, map()} | {:error, error()}
  defp shape(payload, operation, version, _opts) when operation in [:capture, :void, :refund],
    do: lifecycle_shape(payload, operation, version)

  defp shape(payload, operation, version, opts) do
    with {:ok, method, authorization} <- authorization_shape(payload),
         :ok <- authorization_fields(method, authorization),
         payer = map(authorization, "from"),
         :ok <- ensure(address?(payer), :payload_format),
         {:ok, signature} <- invalid(decode_hex(map(payload, "signature")), :payload_format),
         {:ok, salt} <- bytes32(map(payload, "salt")),
         {:ok, salt_nonce} <- salt_nonce(map(payload, "saltNonce"), opts[:bound]),
         {:ok, completion} <- completion_shape(payload, operation, version, opts) do
      {:ok,
       Map.merge(completion, %{
         method: method,
         authorization: authorization,
         payer: String.downcase(payer),
         signature_bytes: signature,
         salt: salt,
         salt_nonce: salt_nonce,
         value:
           if(method == :eip3009,
             do: map(authorization, "value"),
             else:
               Utils.nested_map_value(authorization, [
                 {"permitted", :permitted},
                 {"amount", :amount}
               ])
           ),
         expiry:
           if(method == :eip3009,
             do: map(authorization, "validBefore"),
             else: map(authorization, "deadline")
           ),
         valid_after: if(method == :eip3009, do: map(authorization, "validAfter"), else: nil),
         nonce: map(authorization, "nonce"),
         void_signature: nil
       })}
    end
  end

  @spec authorization_fields(:eip3009 | :permit2, map()) :: :ok | {:error, error()}
  defp authorization_fields(:eip3009, authorization) do
    with :ok <- ensure(address?(map(authorization, "to")), :payload_format),
         :ok <- ensure(uint?(map(authorization, "value")), :payload_format),
         :ok <- ensure(uint?(map(authorization, "validBefore")), :payload_format),
         :ok <- ensure(uint(map(authorization, "validAfter")) == {:ok, 0}, :payload_format),
         {:ok, _nonce} <- bytes32(map(authorization, "nonce")) do
      :ok
    end
  end

  defp authorization_fields(:permit2, authorization) do
    permitted = map(authorization, "permitted")

    ensure(
      address?(map(authorization, "spender")) and address?(map(permitted, "token")) and
        uint?(map(permitted, "amount")) and uint?(map(authorization, "nonce")) and
        uint?(map(authorization, "deadline")),
      :payload_format
    )
  end

  @spec authorization_shape(map()) ::
          {:ok, :eip3009 | :permit2, map()} | {:error, error()}
  defp authorization_shape(payload) do
    case {present?(payload, "authorization"), present?(payload, "permit2Authorization"),
          map(payload, "authorization"), map(payload, "permit2Authorization")} do
      {true, false, %{} = authorization, _} -> {:ok, :eip3009, authorization}
      {false, true, _, %{} = permit} -> {:ok, :permit2, permit}
      _other -> {:error, {:invalid, :payload_format}}
    end
  end

  @spec salt_nonce(term(), boolean()) :: {:ok, String.t() | nil} | {:error, error()}
  defp salt_nonce(nil, false), do: {:ok, nil}
  defp salt_nonce(nil, true), do: {:error, {:invalid, :payload_format}}
  defp salt_nonce(_nonce, false), do: {:error, {:invalid, :payload_format}}
  defp salt_nonce(nonce, true), do: bytes32(nonce)

  @spec completion_shape(map(), AuthCapture.operation(), :v1_1 | :v1_0, keyword()) ::
          {:ok, map()} | {:error, error()}
  defp completion_shape(payload, operation, version, opts) do
    fee_field = EVM.fee_field(version)
    other_fee = if version == :v1_1, do: "feeBps", else: "feeAmount"
    fields = ["amount", fee_field, "feeReceiver", "authorizerSignature"]

    with :ok <- ensure(not present?(payload, other_fee), :payload_format) do
      case Enum.any?(fields, &present?(payload, &1)) do
        false -> raw_completion(operation, opts[:settlement])
        true -> completed_charge(payload, operation, fee_field)
      end
    end
  end

  @spec raw_completion(AuthCapture.operation(), boolean()) :: {:ok, map()} | {:error, error()}
  defp raw_completion(:charge, true), do: {:error, {:invalid, :payload_format}}

  defp raw_completion(_operation, _settlement),
    do:
      {:ok,
       %{completed?: false, amount: nil, fee: nil, fee_receiver: nil, authorizer_signature: nil}}

  @spec completed_charge(map(), AuthCapture.operation(), String.t()) ::
          {:ok, map()} | {:error, error()}
  defp completed_charge(payload, :charge, fee_field) do
    with :ok <- ensure(uint?(map(payload, "amount")), :payload_format),
         :ok <- ensure(uint?(map(payload, fee_field)), :payload_format),
         :ok <- ensure(address?(map(payload, "feeReceiver")), :payload_format),
         :ok <- ensure(hex_bytes?(map(payload, "authorizerSignature")), :authorizer_signature) do
      {:ok,
       %{
         completed?: true,
         amount: map(payload, "amount"),
         fee: map(payload, fee_field),
         fee_receiver: map(payload, "feeReceiver"),
         authorizer_signature: map(payload, "authorizerSignature")
       }}
    end
  end

  defp completed_charge(_payload, _operation, _fee_field),
    do: {:error, {:invalid, :payload_format}}

  @spec lifecycle_shape(map(), AuthCapture.operation(), :v1_1 | :v1_0) ::
          {:ok, map()} | {:error, error()}
  defp lifecycle_shape(payload, operation, version) do
    info = map(payload, "paymentInfo")
    signature = map(payload, "authorizerSignature")
    void_signature = map(payload, "voidAuthorizerSignature")
    fee = map(payload, EVM.fee_field(version))

    other_fee = if version == :v1_1, do: "feeBps", else: "feeAmount"

    with :ok <- ensure(is_map(info), :payload_format),
         :ok <- ensure(not present?(payload, other_fee), :payload_format),
         {:ok, salt_nonce} <- bytes32(map(payload, "saltNonce")),
         :ok <- ensure(hex_bytes?(signature), :authorizer_signature),
         :ok <-
           ensure(
             is_nil(void_signature) or (operation == :capture and hex_bytes?(void_signature)),
             :void_authorizer_signature
           ),
         :ok <- lifecycle_fields(payload, operation, fee) do
      {:ok,
       %{
         payment_info: info,
         salt_nonce: salt_nonce,
         amount: map(payload, "amount"),
         fee: fee,
         fee_receiver: map(payload, "feeReceiver"),
         expected_capturable: map(payload, "expectedCapturableAmount"),
         expected_refundable: map(payload, "expectedRefundableAmount"),
         authorizer_signature: signature,
         void_signature: void_signature
       }}
    end
  end

  @spec lifecycle_fields(map(), AuthCapture.operation(), term()) :: :ok | {:error, error()}
  defp lifecycle_fields(_payload, :void, _fee), do: :ok

  defp lifecycle_fields(payload, :refund, _fee) do
    ensure(
      Enum.all?(
        ["amount", "expectedCapturableAmount", "expectedRefundableAmount"],
        &uint?(map(payload, &1))
      ),
      :payload_format
    )
  end

  defp lifecycle_fields(payload, :capture, fee) do
    ensure(
      Enum.all?(
        ["amount", "expectedCapturableAmount", "expectedRefundableAmount"],
        &uint?(map(payload, &1))
      ) and
        uint?(fee) and address?(map(payload, "feeReceiver")),
      :payload_format
    )
  end

  # -- Result -----------------------------------------------------------------

  @spec result(map(), level()) :: verification()
  defp result(ctx, level) do
    %{
      operation: ctx.operation,
      level: level,
      payer: ctx.payer,
      flow: ctx.flow,
      operator_type: ctx.operator_type,
      method: ctx.method,
      chain_id: ctx.chain_id,
      deployment: ctx.deployment,
      payment_info: ctx.payment_info,
      payment_info_hash: ctx.payment_info_hash,
      signature_type: ctx.signature_type,
      authorizer: ctx.authorizer,
      amount: ctx.amount,
      fee: ctx.fee,
      fee_receiver: ctx.fee_receiver,
      target: ctx.target,
      submitter: ctx.submitter,
      calldata: ctx.calldata,
      void_calldata: ctx.void_calldata,
      payment_state: ctx.payment_state
    }
  end

  # -- Small helpers ----------------------------------------------------------

  @spec inner(map()) :: map()
  defp inner(payment_payload) do
    case map(payment_payload, "payload") do
      %{} = payload -> payload
      _other -> %{}
    end
  end

  @spec map(term(), String.t()) :: term()
  defp map(map, key) when is_map(map), do: Utils.map_value(map, {key, String.to_atom(key)})
  defp map(_map, _key), do: nil

  @spec present?(map(), String.t()) :: boolean()
  defp present?(map, key), do: Map.has_key?(map, key) or Map.has_key?(map, String.to_atom(key))

  @spec target(AuthCapture.operator_type(), EVM.deployment(), map()) :: String.t()
  defp target(:custom, _deployment, extra), do: map(extra, "captureAuthorizer")
  defp target(_type, deployment, _extra), do: deployment.escrow

  @spec consent_source(term()) :: authorizer()
  defp consent_source(_signature), do: :signed

  @spec domain(map()) :: map()
  defp domain(ctx), do: EVM.operator_domain(ctx.chain_id, ctx.submitter)

  @spec lifecycle_operation?(AuthCapture.operation()) :: boolean()
  defp lifecycle_operation?(operation), do: operation in [:capture, :void, :refund]

  @spec time_opts(keyword()) :: keyword()
  defp time_opts(opts), do: [now: now(opts), skew_seconds: opts[:skew_seconds]]

  @spec now(keyword()) :: non_neg_integer()
  defp now(opts), do: opts[:now] || System.os_time(:second)

  @spec ensure(boolean(), atom()) :: :ok | {:error, {:invalid, atom()}}
  defp ensure(true, _reason), do: :ok
  defp ensure(false, reason), do: {:error, {:invalid, reason}}

  # Lifts a domain result into the verifier's error shape: the given (or
  # carried) reason becomes {:invalid, reason}.
  @spec invalid(term()) :: term()
  defp invalid({:error, reason}) when is_atom(reason), do: {:error, {:invalid, reason}}
  defp invalid(other), do: other

  @spec invalid(term(), atom()) :: term()
  defp invalid({:error, _reason}, reason), do: {:error, {:invalid, reason}}
  defp invalid(other, _reason), do: other

  @spec dependency(term()) :: term()
  defp dependency({:error, :missing_dependency}), do: {:error, :missing_dependency}
  defp dependency({:error, _reason}), do: {:error, {:invalid, :payload_format}}
  defp dependency(other), do: other

  @spec rpc(term()) :: term()
  defp rpc({:error, reason}), do: {:error, {:rpc_error, reason}}
  defp rpc(other), do: other

  @spec rpc_shape(term(), term()) :: term()
  defp rpc_shape({:error, _reason}, hex), do: {:error, {:rpc_error, {:invalid_response, hex}}}
  defp rpc_shape(other, _hex), do: other

  @spec uint(term()) :: {:ok, non_neg_integer()} | :error
  defp uint(value) do
    case EVM.parse_uint256(value) do
      {:ok, integer} -> {:ok, integer}
      {:error, _reason} -> :error
    end
  end

  @spec uint(term(), atom()) :: {:ok, non_neg_integer()} | {:error, {:invalid, atom()}}
  defp uint(value, reason) do
    case uint(value) do
      {:ok, integer} -> {:ok, integer}
      :error -> {:error, {:invalid, reason}}
    end
  end

  @spec uint?(term()) :: boolean()
  defp uint?(value), do: match?({:ok, _integer}, uint(value))

  @spec address?(term()) :: boolean()
  defp address?(value), do: match?({:ok, _word}, EIP712.encode_address(value))

  @spec address_or_nil?(term()) :: boolean()
  defp address_or_nil?(nil), do: true
  defp address_or_nil?(value), do: address?(value)

  @spec nonzero_or_nil(term()) :: String.t() | nil
  defp nonzero_or_nil(value), do: if(EVM.nonzero_address?(value), do: value, else: nil)

  @spec same_address?(term(), term()) :: boolean()
  defp same_address?(left, right) when is_binary(left) and is_binary(right),
    do: String.downcase(left) == String.downcase(right)

  defp same_address?(_left, _right), do: false

  @spec same_hex?(term(), term()) :: boolean()
  defp same_hex?(left, right) when is_binary(left) and is_binary(right),
    do: String.downcase(left) == String.downcase(right)

  defp same_hex?(_left, _right), do: false

  @spec bytes32(term()) :: {:ok, String.t()} | {:error, {:invalid, :payload_format}}
  defp bytes32(value) do
    case EIP712.encode_bytes32(value) do
      {:ok, _bytes} -> {:ok, value}
      {:error, _reason} -> {:error, {:invalid, :payload_format}}
    end
  end

  @spec hex_bytes?(term()) :: boolean()
  defp hex_bytes?(value), do: match?({:ok, _bytes}, decode_hex(value))

  @spec decode_hex(term()) :: {:ok, binary()} | {:error, :invalid_hex}
  defp decode_hex("0x" <> hex_digits)
       when byte_size(hex_digits) >= 2 and byte_size(hex_digits) <= @max_signature_bytes * 2 do
    case Base.decode16(hex_digits, case: :mixed) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_hex}
    end
  end

  defp decode_hex(_value), do: {:error, :invalid_hex}

  @spec address_word(String.t()) :: binary()
  defp address_word(address) do
    {:ok, word} = EIP712.encode_address(address)
    word
  end

  @spec parse_word(term()) :: {:ok, non_neg_integer()} | {:error, error()}
  defp parse_word("0x" <> hex_digits = hex) do
    case Base.decode16(hex_digits, case: :mixed) do
      {:ok, <<value::unsigned-big-integer-size(256)>>} -> {:ok, value}
      _other -> {:error, {:rpc_error, {:invalid_response, hex}}}
    end
  end

  defp parse_word(other), do: {:error, {:rpc_error, {:invalid_response, other}}}

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)
end
