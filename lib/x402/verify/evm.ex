defmodule X402.Verify.EVM do
  @moduledoc """
  Local verification of EVM `exact` (EIP-3009 and Permit2) and `upto`
  (Permit2) payment payloads.

  Runs the full facilitator verify checklist from the exact-EVM and
  upto-EVM scheme specifications locally, so an Elixir resource server can
  cryptographically verify payments instead of trusting a remote
  facilitator's `verify` endpoint. The checks mirror the reference
  TypeScript/Go/Python facilitator engines check for check.

  ## Payment kinds

  The requirements select the flow; the result's `kind` echoes it:

  * `:eip3009` — `exact` with `extra.assetTransferMethod` absent or
    `"eip3009"`; the scheme payload carries `authorization`.
  * `:permit2_exact` — `exact` with `extra.assetTransferMethod` `"permit2"`;
    the payload carries `permit2Authorization`, the `spender` must be the
    `x402ExactPermit2Proxy`, the witness `to` must equal `payTo`, the
    `permitted.amount` must equal `amount` and `permitted.token` the
    `asset`, and the `deadline`/`witness.validAfter` window must cover now.
  * `:permit2_upto` — `upto`; as `:permit2_exact` but the spender is the
    `x402UptoPermit2Proxy`, the witness additionally binds
    `extra.facilitatorAddress`, and the requirements' `amount` (what gets
    settled) may be at most `permitted.amount`.

  At `:full`, Permit2 flows simulate the proxy's `settle` via `eth_call`
  (for `upto` as the witness facilitator, the only sender the proxy
  accepts) and diagnose a failure the way the reference facilitator does:
  proxy not deployed, insufficient balance, missing ERC-20 allowance to
  the canonical Permit2 contract, or a generic simulation failure —
  after mapping any named Permit2/proxy custom error first.

  ## Verification levels

  The `:level` option is required and explicit — a level whose capabilities
  are unavailable returns an error instead of silently downgrading:

  * `:structural` — pure checks, no cryptography and no RPC: scheme,
    network, and EIP-712 domain requirements; payload shape; `payTo`
    recipient equality; exact amount equality; and the
    `validAfter`/`validBefore` window with the reference implementations'
    6-second settlement buffer.

  * `:signature` — everything in `:structural`, plus EIP-712 digest
    recomputation and EOA signature recovery (requires the optional
    `ex_keccak` and `ex_secp256k1` dependencies, otherwise
    `{:error, :missing_dependency}`). Smart-wallet signatures (ERC-1271 /
    ERC-6492) cannot be proven without RPC and are rejected with
    `{:error, {:invalid, :smart_wallet_requires_rpc}}` — fail closed, never
    assume.

  * `:full` — everything in `:signature`, plus on-chain checks over a
    configured `X402.RPC` endpoint (otherwise
    `{:error, :rpc_not_configured}`): chain-id cross-check, signature
    routing by payer bytecode (EOA `ecrecover` when the payer has no code,
    strict ERC-1271 `isValidSignature` when it does — no ECDSA fallback,
    matching on-chain `SignatureChecker` semantics), ERC-6492 counterfactual
    handling, asset bytecode presence, `balanceOf` funding, and an
    `eth_call` simulation of `transferWithAuthorization` with failure
    diagnosis (nonce already used, insufficient balance, token domain
    mismatch, ...).

  ## ERC-6492 counterfactual signatures (fail-closed)

  A wrapped signature from an undeployed wallet is **never** accepted on the
  strength of the wrapper alone (the reference Go design):

  * the deployment factory must appear in `:eip6492_allowed_factories`
    (default `[]` — all counterfactual payments are rejected with
    `{:invalid, :eip6492_factory_not_allowed}` until factories are
    explicitly trusted), and
  * validity is proven only by an atomic Multicall3 simulation that deploys
    the wallet and executes the transfer in a single `eth_call`. With
    `simulate: false` counterfactual payments are rejected with
    `{:invalid, :undeployed_smart_wallet}`.

  ## Example

      {:ok, payload} = X402.PaymentSignature.decode_and_validate(header, requirements)

      {:ok, rpc} = X402.RPC.new(rpc_url: "https://sepolia.base.org", finch: MyApp.Finch)

      case X402.Verify.EVM.verify(payload, requirements, level: :full, rpc: rpc) do
        {:ok, %{payer: payer}} -> grant_access(payer)
        {:error, _reason} -> deny_access()
      end

  The result never silently downgrades: `{:ok, result}` means the payment
  passed every check the stated `:level` includes, and `result.level` echoes
  that level.

  Structural-only verification is pure and needs no optional dependency:

      iex> requirements = %{
      ...>   "scheme" => "exact",
      ...>   "network" => "eip155:84532",
      ...>   "amount" => "10000",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "maxTimeoutSeconds" => 60,
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> }
      iex> payload = %{
      ...>   "x402Version" => 2,
      ...>   "accepted" => requirements,
      ...>   "payload" => %{
      ...>     "signature" => "0x" <> String.duplicate("11", 65),
      ...>     "authorization" => %{
      ...>       "from" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>       "to" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>       "value" => "10000",
      ...>       "validAfter" => "0",
      ...>       "validBefore" => "32503680000",
      ...>       "nonce" => "0x" <> String.duplicate("ab", 32)
      ...>     }
      ...>   }
      ...> }
      iex> {:ok, result} = X402.Verify.EVM.verify(payload, requirements, level: :structural)
      iex> {result.level, result.payer}
      {:structural, "0x857b06519e91e3a54538791bdbb0e22373e36b66"}
  """

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.ERC6492
  alias X402.Permit2
  alias X402.RPC
  alias X402.Scheme.ExactEVM
  alias X402.Telemetry
  alias X402.Utils
  alias X402.Wallet

  # Settlement buffer applied to validBefore, matching the reference
  # facilitators (block inclusion time).
  @time_buffer_seconds 6

  # Canonical Multicall3 deployment (same address on all supported chains).
  @multicall3_address "0xcA11bde05977b3631167028862bE2a173976CA11"

  # Function selectors (first 4 bytes of keccak256 of the signature). They are
  # hardcoded so the module works without the optional keccak dependency; the
  # test suite recomputes them with ExKeccak to guard against typos.
  @selector_is_valid_signature <<0x16, 0x26, 0xBA, 0x7E>>
  @selector_balance_of <<0x70, 0xA0, 0x82, 0x31>>
  @selector_authorization_state <<0xE9, 0x4A, 0x01, 0x02>>
  @selector_name <<0x06, 0xFD, 0xDE, 0x03>>
  @selector_version <<0x54, 0xFD, 0x4D, 0x50>>
  @selector_aggregate3 <<0x82, 0xAD, 0x56, 0xCB>>
  # allowance(address,address)
  @selector_allowance <<0xDD, 0x62, 0xED, 0x3E>>
  # PERMIT2() — the proxies' immutable getter, used to probe deployment
  @selector_permit2_getter <<0x6A, 0xFD, 0xD8, 0x50>>

  @erc1271_magic_value <<0x16, 0x26, 0xBA, 0x7E>>

  # Custom-error selectors raised by Permit2 and the x402 proxies, mapped
  # onto the reference facilitator's reasons. Signature-related errors all
  # collapse onto the single canonical signature reason.
  @permit2_error_selectors %{
    # Permit2612AmountMismatch()
    <<0x05, 0x0C, 0xDA, 0x49>> => :permit2_2612_amount_mismatch,
    # InvalidAmount(uint256)
    <<0x37, 0x28, 0xB8, 0x3D>> => :permit2_invalid_amount,
    # InvalidDestination()
    <<0xAC, 0x6B, 0x05, 0xF5>> => :permit2_invalid_destination,
    # InvalidOwner()
    <<0x49, 0xE2, 0x7C, 0xFF>> => :permit2_invalid_owner,
    # PaymentTooEarly()
    <<0xA6, 0x55, 0x39, 0xFA>> => :permit2_payment_too_early,
    # InvalidSignature()
    <<0x8B, 0xAA, 0x57, 0x9F>> => :invalid_signature,
    # InvalidSigner()
    <<0x81, 0x5E, 0x1D, 0x64>> => :invalid_signature,
    # InvalidContractSignature()
    <<0xB0, 0x66, 0x9C, 0xBC>> => :invalid_signature,
    # InvalidSignatureLength()
    <<0x4B, 0xE6, 0x32, 0x1B>> => :invalid_signature,
    # SignatureExpired(uint256)
    <<0xCD, 0x21, 0xDB, 0x4F>> => :invalid_signature,
    # InvalidNonce()
    <<0x75, 0x66, 0x88, 0xFE>> => :permit2_invalid_nonce,
    # AmountExceedsPermitted()
    <<0xFE, 0x64, 0xB4, 0xC7>> => :upto_amount_exceeds_permitted,
    # UnauthorizedFacilitator()
    <<0x0F, 0x6F, 0xAE, 0x87>> => :upto_unauthorized_facilitator
  }

  @permit2_error_names [
    {"Permit2612AmountMismatch", :permit2_2612_amount_mismatch},
    {"InvalidAmount", :permit2_invalid_amount},
    {"InvalidDestination", :permit2_invalid_destination},
    {"InvalidOwner", :permit2_invalid_owner},
    {"PaymentTooEarly", :permit2_payment_too_early},
    {"Too early", :permit2_payment_too_early},
    {"InvalidSignature", :invalid_signature},
    {"InvalidSigner", :invalid_signature},
    {"InvalidContractSignature", :invalid_signature},
    {"SignatureExpired", :invalid_signature},
    {"InvalidNonce", :permit2_invalid_nonce},
    {"AmountExceedsPermitted", :upto_amount_exceeds_permitted},
    {"UnauthorizedFacilitator", :upto_unauthorized_facilitator}
  ]

  @typedoc "Requested verification depth."
  @type level :: :structural | :signature | :full

  @typedoc "The payment flow a payload belongs to."
  @type kind :: :eip3009 | :permit2_exact | :permit2_upto

  @typedoc """
  Simulation mode for level `:full`.

  `:counterfactual_only` skips the EOA/ERC-1271 transfer simulation like
  `false`, but keeps the atomic ERC-6492 deploy-and-transfer simulation —
  the only possible signature proof for an undeployed wallet.
  """
  @type simulate :: boolean() | :counterfactual_only

  @typedoc "How the payment signature was (or would be) verified."
  @type signature_type :: :eoa | :erc1271 | :erc6492_counterfactual

  @typedoc """
  A successful verification.

  `payer` is the lowercase authorization `from` address. `kind` is the
  payment flow (see the module documentation). `level` echoes the level
  that was run. `signature_type` is `nil` at `:structural` (no signature
  classification happens without cryptography).
  """
  @type verification :: %{
          payer: String.t(),
          kind: kind(),
          level: level(),
          signature_type: signature_type() | nil
        }

  @typedoc """
  Why a payment was rejected.

  Reasons map onto the canonical cross-SDK `invalidReason` strings via
  `reason_string/1` where an equivalent exists. The `permit2_*` and
  `upto_*` reasons are produced by the Permit2 flows only.
  """
  @type invalid_reason ::
          :invalid_payload
          | :invalid_authorization
          | :invalid_requirements
          | :scheme_mismatch
          | :unsupported_transfer_method
          | :unsupported_network
          | :network_mismatch
          | :missing_eip712_domain
          | :recipient_mismatch
          | :value_mismatch
          | :valid_before_expired
          | :valid_after_in_future
          | :invalid_signature
          | :smart_wallet_requires_rpc
          | :undeployed_smart_wallet
          | :eip6492_factory_not_allowed
          | :asset_not_deployed_contract
          | :balance_check_failed
          | :insufficient_balance
          | :eip3009_not_supported
          | :nonce_already_used
          | :token_name_mismatch
          | :token_version_mismatch
          | :simulation_failed
          | :upto_scheme_mismatch
          | :upto_network_mismatch
          | :upto_facilitator_mismatch
          | :settlement_exceeds_amount
          | :invalid_permit2_spender
          | :permit2_recipient_mismatch
          | :permit2_deadline_expired
          | :permit2_not_yet_valid
          | :permit2_amount_mismatch
          | :permit2_token_mismatch
          | :invalid_permit2_signature
          | :permit2_proxy_not_deployed
          | :permit2_insufficient_balance
          | :permit2_allowance_required
          | :permit2_simulation_failed
          | :permit2_2612_amount_mismatch
          | :permit2_invalid_amount
          | :permit2_invalid_destination
          | :permit2_invalid_owner
          | :permit2_payment_too_early
          | :permit2_invalid_nonce
          | :upto_amount_exceeds_permitted
          | :upto_unauthorized_facilitator

  @typedoc "Verification errors."
  @type error ::
          {:invalid, invalid_reason()}
          | :missing_dependency
          | :rpc_not_configured
          | {:rpc_error, RPC.error()}
          | {:chain_id_mismatch, non_neg_integer(), non_neg_integer()}

  @verify_opts_schema [
    level: [
      type: {:in, [:structural, :signature, :full]},
      required: true,
      doc: """
      Verification depth. `:structural` needs nothing, `:signature` needs the
      optional crypto dependencies, `:full` additionally needs `:rpc`. A
      level never silently downgrades.
      """
    ],
    rpc: [
      type: {:custom, RPC, :validate_config, []},
      doc: "An `X402.RPC` configuration. Required for level `:full`."
    ],
    simulate: [
      type: {:in, [true, false, :counterfactual_only]},
      default: true,
      doc: """
      Whether level `:full` simulates `transferWithAuthorization` via
      `eth_call`. Counterfactual ERC-6492 payments always require simulation
      and are rejected when it is `false`; `:counterfactual_only` skips the
      EOA/ERC-1271 transfer simulation but keeps the atomic counterfactual
      deploy-and-transfer simulation, which is the only possible proof of a
      counterfactual signature.
      """
    ],
    verify_chain_id: [
      type: :boolean,
      default: true,
      doc: """
      Whether level `:full` cross-checks `eth_chainId` against the CAIP-2
      network in the requirements, guarding against a misconfigured RPC
      endpoint. Adds no extra round-trip (batched with the other reads).
      """
    ],
    eip6492_allowed_factories: [
      type: {:list, :string},
      default: [],
      doc: """
      Factory contract addresses trusted to deploy counterfactual ERC-6492
      smart wallets (case-insensitive). The default empty list rejects every
      counterfactual payment.
      """
    ],
    multicall_address: [
      type: :string,
      default: @multicall3_address,
      doc: "The Multicall3 contract used for atomic ERC-6492 deploy-and-transfer simulation."
    ]
  ]

  @doc since: "0.6.0", group: :verification
  @doc """
  Verifies a decoded v2 `PaymentPayload` against payment requirements.

  `payment_payload` is the decoded v2 envelope (as returned by
  `X402.PaymentSignature.decode_and_validate/2`) and `requirements` the
  matched `PaymentRequirements` object. Both accept string or atom keys.

  Returns `{:ok, verification}` when the payment passes every check the
  stated `:level` includes, `{:error, {:invalid, reason}}` when a check
  fails, and a capability error (`:missing_dependency`,
  `:rpc_not_configured`) when the level cannot run — never a silent
  downgrade. RPC transport failures return `{:error, {:rpc_error, reason}}`
  (fail closed: the payment is not proven valid).

  ## Options

  #{NimbleOptions.docs(@verify_opts_schema)}

  ## Examples

      iex> X402.Verify.EVM.verify(%{"x402Version" => 2}, %{}, level: :structural)
      {:error, {:invalid, :invalid_payload}}
  """
  @spec verify(map(), map(), keyword()) :: {:ok, verification()} | {:error, error()}
  def verify(payment_payload, requirements, opts)
      when is_map(payment_payload) and is_map(requirements) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @verify_opts_schema)
    level = Keyword.fetch!(opts, :level)

    case do_verify(payment_payload, requirements, level, opts) do
      {:ok, result} ->
        Telemetry.emit(:verify, :evm, :ok, %{level: level})
        {:ok, result}

      {:error, reason} ->
        Telemetry.emit(:verify, :evm, :error, %{level: level, reason: reason})
        {:error, reason}
    end
  end

  @doc since: "0.6.0", group: :verification
  @doc """
  Maps an `invalid` reason atom to the canonical cross-SDK `invalidReason`
  string used by the reference facilitators.

  Local-only reasons without a canonical wire equivalent fall back to their
  atom name.

  ## Examples

      iex> X402.Verify.EVM.reason_string(:recipient_mismatch)
      "invalid_exact_evm_recipient_mismatch"

      iex> X402.Verify.EVM.reason_string(:nonce_already_used)
      "invalid_exact_evm_nonce_already_used"

      iex> X402.Verify.EVM.reason_string(:invalid_payload)
      "invalid_payload"
  """
  @spec reason_string(invalid_reason()) :: String.t()
  def reason_string(reason) when is_atom(reason) do
    Map.get(reason_strings(), reason, Atom.to_string(reason))
  end

  @spec reason_strings() :: %{invalid_reason() => String.t()}
  defp reason_strings do
    %{
      scheme_mismatch: "invalid_exact_evm_scheme",
      unsupported_transfer_method: "invalid_exact_evm_scheme",
      network_mismatch: "invalid_exact_evm_network_mismatch",
      unsupported_network: "invalid_exact_evm_network_mismatch",
      missing_eip712_domain: "invalid_exact_evm_missing_eip712_domain",
      recipient_mismatch: "invalid_exact_evm_recipient_mismatch",
      invalid_signature: "invalid_exact_evm_signature",
      smart_wallet_requires_rpc: "invalid_exact_evm_signature",
      valid_before_expired: "invalid_exact_evm_payload_authorization_valid_before",
      valid_after_in_future: "invalid_exact_evm_payload_authorization_valid_after",
      value_mismatch: "invalid_exact_evm_payload_authorization_value_mismatch",
      undeployed_smart_wallet: "invalid_exact_evm_payload_undeployed_smart_wallet",
      eip6492_factory_not_allowed: "eip6492_factory_not_allowed",
      asset_not_deployed_contract: "asset_not_deployed_contract",
      insufficient_balance: "invalid_exact_evm_insufficient_balance",
      balance_check_failed: "invalid_exact_evm_transaction_simulation_failed",
      eip3009_not_supported: "invalid_exact_evm_eip3009_not_supported",
      nonce_already_used: "invalid_exact_evm_nonce_already_used",
      token_name_mismatch: "invalid_exact_evm_token_name_mismatch",
      token_version_mismatch: "invalid_exact_evm_token_version_mismatch",
      simulation_failed: "invalid_exact_evm_transaction_simulation_failed",
      upto_scheme_mismatch: "invalid_upto_evm_scheme",
      upto_network_mismatch: "invalid_upto_evm_network_mismatch",
      settlement_exceeds_amount: "invalid_upto_evm_payload_settlement_exceeds_amount",
      permit2_recipient_mismatch: "invalid_permit2_recipient_mismatch"
    }
  end

  # Reasons shared with the EIP-3009 pipeline are renamed onto the Permit2
  # family so the wire string matches the reference facilitator.
  @permit2_reason_translation %{
    invalid_signature: :invalid_permit2_signature,
    smart_wallet_requires_rpc: :invalid_permit2_signature,
    insufficient_balance: :permit2_insufficient_balance,
    balance_check_failed: :permit2_simulation_failed,
    simulation_failed: :permit2_simulation_failed
  }

  @doc false
  # Classifies a Permit2 / x402-proxy `settle` revert onto a verify reason
  # from its ABI-encoded custom-error data (selector) or, failing that, the
  # error name inside the node's message. Public so
  # `X402.Facilitator.Engine` can classify `eth_estimateGas` reverts during
  # settlement. Returns `nil` when unrecognized.
  @spec classify_permit2_revert(RPC.jsonrpc_error()) :: invalid_reason() | nil
  def classify_permit2_revert(error) do
    selector_reason =
      case error.data do
        "0x" <> _rest = data ->
          case unhex(data) do
            {:ok, <<selector::binary-size(4), _rest::binary>>} ->
              Map.get(@permit2_error_selectors, selector)

            _other ->
              nil
          end

        _other ->
          nil
      end

    reason = selector_reason || permit2_message_reason(error.message || "")
    reason && translate_permit2_reason(reason)
  end

  @spec permit2_message_reason(String.t()) :: invalid_reason() | nil
  defp permit2_message_reason(message) do
    Enum.find_value(@permit2_error_names, fn {name, reason} ->
      if String.contains?(message, name), do: reason
    end)
  end

  @spec translate_permit2_reason(invalid_reason()) :: invalid_reason()
  defp translate_permit2_reason(reason), do: Map.get(@permit2_reason_translation, reason, reason)

  # -- Pipeline ---------------------------------------------------------------

  @spec do_verify(map(), map(), level(), keyword()) ::
          {:ok, verification()} | {:error, error()}
  defp do_verify(payment_payload, requirements, level, opts) do
    with {:ok, ctx} <- build_context(payment_payload, requirements) do
      ctx
      |> then(&run_level(level, &1, opts))
      |> translate_error(ctx.kind)
    end
  end

  @spec translate_error({:ok, verification()} | {:error, error()}, kind()) ::
          {:ok, verification()} | {:error, error()}
  defp translate_error({:error, {:invalid, reason}}, kind)
       when kind in [:permit2_exact, :permit2_upto],
       do: {:error, {:invalid, translate_permit2_reason(reason)}}

  defp translate_error(outcome, _kind), do: outcome

  @spec run_level(level(), map(), keyword()) :: {:ok, verification()} | {:error, error()}
  defp run_level(:structural, ctx, _opts), do: {:ok, result(ctx, :structural, nil)}
  defp run_level(:signature, ctx, _opts), do: signature_verify(ctx)
  defp run_level(:full, ctx, opts), do: full_verify(ctx, opts)

  @spec result(map(), level(), signature_type() | nil) :: verification()
  defp result(ctx, level, signature_type),
    do: %{payer: ctx.payer, kind: ctx.kind, level: level, signature_type: signature_type}

  # -- Structural checks (no crypto, no RPC) ----------------------------------

  # The context is the kind-independent state the signature and full levels
  # consume: `authorization` (whatever object the digest is computed from),
  # `asset`, `chain_id`, `value` (the amount that settles), `nonce`, and
  # `payer`. Permit2 kinds add `spender` (the proxy) and `witness`.
  @spec build_context(map(), map()) :: {:ok, map()} | {:error, {:invalid, invalid_reason()}}
  defp build_context(payment_payload, requirements) do
    accepted = Utils.map_value(payment_payload, {"accepted", :accepted})
    scheme_payload = Utils.map_value(payment_payload, {"payload", :payload})

    with :ok <- ensure_maps(accepted, scheme_payload),
         {:ok, kind} <- detect_kind(requirements) do
      case kind do
        :eip3009 -> build_eip3009_context(accepted, scheme_payload, requirements)
        _permit2 -> build_permit2_context(kind, accepted, scheme_payload, requirements)
      end
    end
  end

  @spec detect_kind(map()) :: {:ok, kind()} | {:error, {:invalid, invalid_reason()}}
  defp detect_kind(requirements) do
    case Utils.map_value(requirements, {"scheme", :scheme}) do
      "upto" ->
        {:ok, :permit2_upto}

      "exact" ->
        case ExactEVM.transfer_method(requirements) do
          {:ok, :eip3009} -> {:ok, :eip3009}
          {:ok, :permit2} -> {:ok, :permit2_exact}
          {:error, _reason} -> {:error, {:invalid, :unsupported_transfer_method}}
        end

      _other ->
        {:error, {:invalid, :scheme_mismatch}}
    end
  end

  @spec build_eip3009_context(map(), map(), map()) ::
          {:ok, map()} | {:error, {:invalid, invalid_reason()}}
  defp build_eip3009_context(accepted, scheme_payload, requirements) do
    with :ok <- check_scheme(accepted, requirements),
         :ok <- check_network_match(accepted, requirements),
         {:ok, domain} <- derive_domain(requirements),
         {:ok, signature_bytes} <- extract_signature(scheme_payload),
         {:ok, authorization} <- extract_authorization(scheme_payload),
         {:ok, timing} <- extract_timing(authorization),
         {:ok, value} <- extract_amount(Utils.map_value(authorization, {"value", :value})),
         {:ok, amount} <- extract_amount(Utils.map_value(requirements, {"amount", :amount})),
         :ok <- check_recipient(authorization, requirements),
         :ok <- check_value(value, amount),
         :ok <- check_timing(timing) do
      {:ok,
       %{
         kind: :eip3009,
         domain: domain,
         authorization: authorization,
         signature_bytes: signature_bytes,
         payer: String.downcase(Utils.map_value(authorization, {"from", :from})),
         asset: domain.verifying_contract,
         chain_id: domain.chain_id,
         extra_name: domain.name,
         extra_version: domain.version,
         value: value,
         nonce: Utils.map_value(authorization, {"nonce", :nonce})
       }}
    end
  end

  # Mirrors the reference Permit2 verify order: scheme, network, spender,
  # recipient, (facilitator for upto), deadline, validAfter, amount, token.
  @spec build_permit2_context(kind(), map(), map(), map()) ::
          {:ok, map()} | {:error, {:invalid, invalid_reason()}}
  defp build_permit2_context(kind, accepted, scheme_payload, requirements) do
    with :ok <- check_permit2_scheme(kind, accepted, requirements),
         :ok <- check_permit2_network(kind, accepted, requirements),
         {:ok, domain} <- derive_permit2_domain(requirements),
         {:ok, asset} <- extract_asset(requirements),
         {:ok, signature_bytes} <- extract_signature(scheme_payload),
         {:ok, authorization, permitted, witness} <- extract_permit2_authorization(scheme_payload),
         {:ok, spender} <- check_spender(kind, authorization),
         :ok <- check_permit2_recipient(witness, requirements),
         :ok <- check_facilitator(kind, witness, requirements),
         :ok <- check_permit2_timing(authorization, witness),
         {:ok, permitted_amount} <-
           extract_amount(Utils.map_value(permitted, {"amount", :amount})),
         {:ok, amount} <- extract_amount(Utils.map_value(requirements, {"amount", :amount})),
         {:ok, value} <- check_permit2_amount(kind, permitted_amount, amount),
         :ok <- check_permit2_token(permitted, asset),
         {:ok, nonce} <- extract_amount(Utils.map_value(authorization, {"nonce", :nonce})) do
      {:ok,
       %{
         kind: kind,
         domain: domain,
         authorization: authorization,
         signature_bytes: signature_bytes,
         payer: String.downcase(Utils.map_value(authorization, {"from", :from})),
         asset: asset,
         spender: spender,
         witness: witness,
         chain_id: domain.chain_id,
         value: value,
         nonce: nonce
       }}
    end
  end

  @spec check_permit2_scheme(kind(), map(), map()) ::
          :ok | {:error, {:invalid, :scheme_mismatch | :upto_scheme_mismatch}}
  defp check_permit2_scheme(:permit2_exact, accepted, requirements),
    do: check_scheme(accepted, requirements)

  defp check_permit2_scheme(:permit2_upto, accepted, _requirements) do
    case Utils.map_value(accepted, {"scheme", :scheme}) do
      "upto" -> :ok
      _other -> {:error, {:invalid, :upto_scheme_mismatch}}
    end
  end

  @spec check_permit2_network(kind(), map(), map()) ::
          :ok | {:error, {:invalid, :network_mismatch | :upto_network_mismatch}}
  defp check_permit2_network(kind, accepted, requirements) do
    case {check_network_match(accepted, requirements), kind} do
      {:ok, _kind} -> :ok
      {{:error, _reason}, :permit2_upto} -> {:error, {:invalid, :upto_network_mismatch}}
      {error, _kind} -> error
    end
  end

  @spec derive_permit2_domain(map()) ::
          {:ok, EIP712.domain()} | {:error, {:invalid, :unsupported_network}}
  defp derive_permit2_domain(requirements) do
    case Permit2.domain(requirements) do
      {:ok, domain} -> {:ok, domain}
      {:error, _reason} -> {:error, {:invalid, :unsupported_network}}
    end
  end

  @spec extract_asset(map()) :: {:ok, String.t()} | {:error, {:invalid, :invalid_requirements}}
  defp extract_asset(requirements) do
    asset = Utils.map_value(requirements, {"asset", :asset})

    case Wallet.valid_evm?(asset) do
      true -> {:ok, asset}
      false -> {:error, {:invalid, :invalid_requirements}}
    end
  end

  @spec extract_permit2_authorization(map()) ::
          {:ok, map(), map(), map()} | {:error, {:invalid, :invalid_authorization}}
  defp extract_permit2_authorization(scheme_payload) do
    authorization =
      Utils.map_value(scheme_payload, {"permit2Authorization", :permit2Authorization})

    with true <- is_map(authorization),
         permitted = Utils.map_value(authorization, {"permitted", :permitted}),
         witness = Utils.map_value(authorization, {"witness", :witness}),
         true <- is_map(permitted) and is_map(witness),
         true <- Wallet.valid_evm?(Utils.map_value(authorization, {"from", :from})),
         true <- Wallet.valid_evm?(Utils.map_value(witness, {"to", :to})),
         true <- Wallet.valid_evm?(Utils.map_value(permitted, {"token", :token})) do
      {:ok, authorization, permitted, witness}
    else
      _other -> {:error, {:invalid, :invalid_authorization}}
    end
  end

  @spec check_spender(kind(), map()) ::
          {:ok, String.t()} | {:error, {:invalid, :invalid_permit2_spender}}
  defp check_spender(kind, authorization) do
    expected =
      case kind do
        :permit2_exact -> Permit2.exact_proxy_address()
        :permit2_upto -> Permit2.upto_proxy_address()
      end

    spender = Utils.map_value(authorization, {"spender", :spender})

    case is_binary(spender) and String.downcase(spender) == String.downcase(expected) do
      true -> {:ok, expected}
      false -> {:error, {:invalid, :invalid_permit2_spender}}
    end
  end

  @spec check_permit2_recipient(map(), map()) ::
          :ok | {:error, {:invalid, :permit2_recipient_mismatch}}
  defp check_permit2_recipient(witness, requirements) do
    to = Utils.map_value(witness, {"to", :to})
    pay_to = Utils.map_value(requirements, {"payTo", :payTo})

    case is_binary(pay_to) and String.downcase(to) == String.downcase(pay_to) do
      true -> :ok
      false -> {:error, {:invalid, :permit2_recipient_mismatch}}
    end
  end

  @spec check_facilitator(kind(), map(), map()) ::
          :ok | {:error, {:invalid, :upto_facilitator_mismatch}}
  defp check_facilitator(:permit2_exact, _witness, _requirements), do: :ok

  defp check_facilitator(:permit2_upto, witness, requirements) do
    facilitator = Utils.map_value(witness, {"facilitator", :facilitator})

    with {:ok, expected} <- Permit2.facilitator_address(requirements),
         true <- is_binary(facilitator),
         true <- String.downcase(facilitator) == String.downcase(expected) do
      :ok
    else
      _mismatch -> {:error, {:invalid, :upto_facilitator_mismatch}}
    end
  end

  @spec check_permit2_timing(map(), map()) ::
          :ok
          | {:error,
             {:invalid,
              :invalid_authorization | :permit2_deadline_expired | :permit2_not_yet_valid}}
  defp check_permit2_timing(authorization, witness) do
    with {:ok, deadline} <-
           extract_amount(Utils.map_value(authorization, {"deadline", :deadline})),
         {:ok, valid_after} <-
           extract_amount(Utils.map_value(witness, {"validAfter", :validAfter})) do
      now = System.system_time(:second)

      cond do
        deadline < now + @time_buffer_seconds -> {:error, {:invalid, :permit2_deadline_expired}}
        valid_after > now -> {:error, {:invalid, :permit2_not_yet_valid}}
        true -> :ok
      end
    end
  end

  # Exact: the permitted amount must equal the advertised amount and is what
  # settles. Upto: the advertised amount settles and may not exceed the
  # permitted ceiling.
  @spec check_permit2_amount(kind(), non_neg_integer(), non_neg_integer()) ::
          {:ok, non_neg_integer()}
          | {:error, {:invalid, :permit2_amount_mismatch | :settlement_exceeds_amount}}
  defp check_permit2_amount(:permit2_exact, permitted, amount) when permitted == amount,
    do: {:ok, amount}

  defp check_permit2_amount(:permit2_exact, _permitted, _amount),
    do: {:error, {:invalid, :permit2_amount_mismatch}}

  defp check_permit2_amount(:permit2_upto, permitted, amount) when amount <= permitted,
    do: {:ok, amount}

  defp check_permit2_amount(:permit2_upto, _permitted, _amount),
    do: {:error, {:invalid, :settlement_exceeds_amount}}

  @spec check_permit2_token(map(), String.t()) ::
          :ok | {:error, {:invalid, :permit2_token_mismatch}}
  defp check_permit2_token(permitted, asset) do
    token = Utils.map_value(permitted, {"token", :token})

    case String.downcase(token) == String.downcase(asset) do
      true -> :ok
      false -> {:error, {:invalid, :permit2_token_mismatch}}
    end
  end

  @spec ensure_maps(term(), term()) :: :ok | {:error, {:invalid, :invalid_payload}}
  defp ensure_maps(accepted, scheme_payload)
       when is_map(accepted) and is_map(scheme_payload),
       do: :ok

  defp ensure_maps(_accepted, _scheme_payload), do: {:error, {:invalid, :invalid_payload}}

  @spec check_scheme(map(), map()) :: :ok | {:error, {:invalid, :scheme_mismatch}}
  defp check_scheme(accepted, requirements) do
    accepted_scheme = Utils.map_value(accepted, {"scheme", :scheme})
    required_scheme = Utils.map_value(requirements, {"scheme", :scheme})

    case accepted_scheme == "exact" and required_scheme == "exact" do
      true -> :ok
      false -> {:error, {:invalid, :scheme_mismatch}}
    end
  end

  @spec check_network_match(map(), map()) :: :ok | {:error, {:invalid, :network_mismatch}}
  defp check_network_match(accepted, requirements) do
    accepted_network = Utils.map_value(accepted, {"network", :network})
    required_network = Utils.map_value(requirements, {"network", :network})

    case is_binary(accepted_network) and accepted_network == required_network do
      true -> :ok
      false -> {:error, {:invalid, :network_mismatch}}
    end
  end

  @spec derive_domain(map()) :: {:ok, EIP3009.domain()} | {:error, {:invalid, invalid_reason()}}
  defp derive_domain(requirements) do
    with {:ok, domain} <- map_domain_error(EIP3009.domain(requirements)),
         true <- Wallet.valid_evm?(domain.verifying_contract) do
      {:ok, domain}
    else
      false -> {:error, {:invalid, :invalid_requirements}}
      {:error, _reason} = error -> error
    end
  end

  @spec map_domain_error({:ok, EIP3009.domain()} | {:error, EIP3009.domain_error()}) ::
          {:ok, EIP3009.domain()} | {:error, {:invalid, invalid_reason()}}
  defp map_domain_error({:ok, domain}), do: {:ok, domain}

  defp map_domain_error({:error, {:missing_extra, _key}}),
    do: {:error, {:invalid, :missing_eip712_domain}}

  defp map_domain_error({:error, {:unsupported_transfer_method, _method}}),
    do: {:error, {:invalid, :unsupported_transfer_method}}

  defp map_domain_error({:error, :unsupported_network}),
    do: {:error, {:invalid, :unsupported_network}}

  defp map_domain_error({:error, _reason}), do: {:error, {:invalid, :invalid_requirements}}

  @spec extract_signature(map()) :: {:ok, binary()} | {:error, {:invalid, :invalid_signature}}
  defp extract_signature(scheme_payload) do
    with "0x" <> hex when hex != "" <- Utils.map_value(scheme_payload, {"signature", :signature}),
         {:ok, bytes} <- Base.decode16(hex, case: :mixed) do
      {:ok, bytes}
    else
      _other -> {:error, {:invalid, :invalid_signature}}
    end
  end

  @spec extract_authorization(map()) ::
          {:ok, map()} | {:error, {:invalid, :invalid_authorization}}
  defp extract_authorization(scheme_payload) do
    authorization = Utils.map_value(scheme_payload, {"authorization", :authorization})

    with true <- is_map(authorization),
         from = Utils.map_value(authorization, {"from", :from}),
         to = Utils.map_value(authorization, {"to", :to}),
         nonce = Utils.map_value(authorization, {"nonce", :nonce}),
         true <- Wallet.valid_evm?(from),
         true <- Wallet.valid_evm?(to),
         true <- valid_nonce?(nonce) do
      {:ok, authorization}
    else
      _other -> {:error, {:invalid, :invalid_authorization}}
    end
  end

  @spec valid_nonce?(term()) :: boolean()
  defp valid_nonce?("0x" <> hex) when byte_size(hex) == 64,
    do: match?({:ok, _bytes}, Base.decode16(hex, case: :mixed))

  defp valid_nonce?(_nonce), do: false

  @spec extract_timing(map()) ::
          {:ok, %{valid_after: non_neg_integer(), valid_before: non_neg_integer()}}
          | {:error, {:invalid, :invalid_authorization}}
  defp extract_timing(authorization) do
    with {:ok, valid_after} <-
           parse_non_neg_integer(Utils.map_value(authorization, {"validAfter", :valid_after})),
         {:ok, valid_before} <-
           parse_non_neg_integer(Utils.map_value(authorization, {"validBefore", :valid_before})) do
      {:ok, %{valid_after: valid_after, valid_before: valid_before}}
    else
      :error -> {:error, {:invalid, :invalid_authorization}}
    end
  end

  @spec extract_amount(term()) ::
          {:ok, non_neg_integer()} | {:error, {:invalid, :invalid_authorization}}
  defp extract_amount(value) do
    case parse_non_neg_integer(value) do
      {:ok, parsed} -> {:ok, parsed}
      :error -> {:error, {:invalid, :invalid_authorization}}
    end
  end

  @spec parse_non_neg_integer(term()) :: {:ok, non_neg_integer()} | :error
  # uint256 fields: values at or above 2^256 cannot be ABI-encoded and would
  # crash word encoding downstream — reject them here.
  @uint256_limit Integer.pow(2, 256)

  defp parse_non_neg_integer(value)
       when is_integer(value) and value >= 0 and value < @uint256_limit,
       do: {:ok, value}

  defp parse_non_neg_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} when parsed >= 0 and parsed < @uint256_limit -> {:ok, parsed}
      _parsed -> :error
    end
  end

  defp parse_non_neg_integer(_value), do: :error

  @spec check_recipient(map(), map()) :: :ok | {:error, {:invalid, :recipient_mismatch}}
  defp check_recipient(authorization, requirements) do
    to = Utils.map_value(authorization, {"to", :to})
    pay_to = Utils.map_value(requirements, {"payTo", :payTo})

    case is_binary(pay_to) and String.downcase(to) == String.downcase(pay_to) do
      true -> :ok
      false -> {:error, {:invalid, :recipient_mismatch}}
    end
  end

  @spec check_value(non_neg_integer(), non_neg_integer()) ::
          :ok | {:error, {:invalid, :value_mismatch}}
  defp check_value(value, amount) when value == amount, do: :ok
  defp check_value(_value, _amount), do: {:error, {:invalid, :value_mismatch}}

  @spec check_timing(%{valid_after: non_neg_integer(), valid_before: non_neg_integer()}) ::
          :ok | {:error, {:invalid, :valid_before_expired | :valid_after_in_future}}
  defp check_timing(%{valid_after: valid_after, valid_before: valid_before}) do
    now = System.system_time(:second)

    cond do
      valid_before < now + @time_buffer_seconds -> {:error, {:invalid, :valid_before_expired}}
      valid_after > now -> {:error, {:invalid, :valid_after_in_future}}
      true -> :ok
    end
  end

  # -- Level :signature (EOA crypto, no RPC) ----------------------------------

  @spec signature_verify(map()) :: {:ok, verification()} | {:error, error()}
  defp signature_verify(ctx) do
    with {:ok, parsed} <- parse_signature(ctx.signature_bytes),
         {:ok, digest} <- compute_digest(ctx),
         :ok <- ensure_offline_verifiable(parsed),
         :ok <- verify_eoa(ctx, digest, parsed.inner_signature) do
      {:ok, result(ctx, :signature, :eoa)}
    end
  end

  # A wrapped or non-65-byte signature belongs to a smart wallet; without RPC
  # it cannot be proven valid, so it is rejected rather than assumed.
  @spec ensure_offline_verifiable(ERC6492.parsed()) ::
          :ok | {:error, {:invalid, :smart_wallet_requires_rpc}}
  defp ensure_offline_verifiable(%{wrapped?: false, inner_signature: inner})
       when byte_size(inner) == 65,
       do: :ok

  defp ensure_offline_verifiable(_parsed), do: {:error, {:invalid, :smart_wallet_requires_rpc}}

  @spec parse_signature(binary()) ::
          {:ok, ERC6492.parsed()} | {:error, {:invalid, :invalid_signature}}
  defp parse_signature(signature_bytes) do
    case ERC6492.parse(signature_bytes) do
      {:ok, parsed} -> {:ok, parsed}
      {:error, _reason} -> {:error, {:invalid, :invalid_signature}}
    end
  end

  @spec compute_digest(map()) :: {:ok, <<_::256>>} | {:error, error()}
  defp compute_digest(ctx) do
    case digest_for(ctx) do
      {:ok, digest} -> {:ok, digest}
      {:error, :missing_dependency} -> {:error, :missing_dependency}
      {:error, _reason} -> {:error, {:invalid, :invalid_authorization}}
    end
  end

  @spec digest_for(map()) :: {:ok, <<_::256>>} | {:error, term()}
  defp digest_for(%{kind: :eip3009} = ctx),
    do: EIP3009.eip712_digest(ctx.domain, ctx.authorization)

  defp digest_for(ctx), do: Permit2.digest(ctx.domain, ctx.authorization)

  @spec verify_eoa(map(), binary(), binary()) ::
          :ok | {:error, :missing_dependency | {:invalid, :invalid_signature}}
  defp verify_eoa(_ctx, _digest, inner_signature) when byte_size(inner_signature) != 65,
    do: {:error, {:invalid, :invalid_signature}}

  defp verify_eoa(ctx, digest, inner_signature) do
    case EIP3009.recover_signer(digest, inner_signature) do
      {:ok, recovered} when recovered == ctx.payer -> :ok
      {:ok, _other} -> {:error, {:invalid, :invalid_signature}}
      {:error, :missing_dependency} -> {:error, :missing_dependency}
      {:error, _reason} -> {:error, {:invalid, :invalid_signature}}
    end
  end

  # -- Level :full (RPC) ------------------------------------------------------

  @spec full_verify(map(), keyword()) :: {:ok, verification()} | {:error, error()}
  defp full_verify(ctx, opts) do
    with {:ok, rpc} <- fetch_rpc(opts),
         {:ok, parsed} <- parse_signature(ctx.signature_bytes),
         {:ok, digest} <- compute_digest(ctx),
         {:ok, chain_state} <- preflight(rpc, ctx, opts),
         :ok <- check_chain_id(chain_state, ctx, opts),
         :ok <- check_asset_deployed(chain_state),
         :ok <- check_proxy_deployed(chain_state),
         :ok <- check_balance(chain_state, ctx),
         {:ok, signature_type} <- classify_and_verify(rpc, ctx, parsed, digest, chain_state, opts),
         :ok <- maybe_simulate(rpc, ctx, parsed, signature_type, opts) do
      {:ok, result(ctx, :full, signature_type)}
    end
  end

  @spec fetch_rpc(keyword()) :: {:ok, RPC.t()} | {:error, :rpc_not_configured}
  defp fetch_rpc(opts) do
    case Keyword.get(opts, :rpc) do
      %RPC{} = rpc -> {:ok, rpc}
      nil -> {:error, :rpc_not_configured}
    end
  end

  # One batched round-trip: chain id (optional), payer code, asset code,
  # payer balance, and — for Permit2 kinds — the proxy's code.
  @spec preflight(RPC.t(), map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp preflight(rpc, ctx, opts) do
    verify_chain_id? = Keyword.fetch!(opts, :verify_chain_id)
    proxy = Map.get(ctx, :spender)

    base_requests =
      [
        {"eth_getCode", [ctx.payer, "latest"]},
        {"eth_getCode", [ctx.asset, "latest"]},
        {"eth_call", [%{"to" => ctx.asset, "data" => balance_of_calldata(ctx)}, "latest"]}
      ] ++ List.wrap(proxy && {"eth_getCode", [proxy, "latest"]})

    requests =
      case verify_chain_id? do
        true -> [{"eth_chainId", []} | base_requests]
        false -> base_requests
      end

    with {:ok, results} <- rpc_batch(rpc, requests) do
      {chain_id_result, [payer_code, asset_code, balance | proxy_results]} =
        case verify_chain_id? do
          true ->
            [chain_id_result | rest] = results
            {chain_id_result, rest}

          false ->
            {nil, results}
        end

      with {:ok, payer_code} <- expect_rpc_ok(payer_code),
           {:ok, asset_code} <- expect_rpc_ok(asset_code),
           {:ok, proxy_code} <- expect_proxy_code(proxy_results) do
        {:ok,
         %{
           chain_id: chain_id_result,
           payer_code: payer_code,
           asset_code: asset_code,
           proxy_code: proxy_code,
           balance: balance
         }}
      end
    end
  end

  @spec expect_proxy_code([RPC.batch_result()]) ::
          {:ok, term()} | {:error, {:rpc_error, RPC.error()}}
  defp expect_proxy_code([]), do: {:ok, nil}
  defp expect_proxy_code([proxy_code]), do: expect_rpc_ok(proxy_code)

  @spec rpc_batch(RPC.t(), [RPC.batch_request()]) ::
          {:ok, [RPC.batch_result()]} | {:error, {:rpc_error, RPC.error()}}
  defp rpc_batch(rpc, requests) do
    case RPC.batch(rpc, requests) do
      {:ok, results} -> {:ok, results}
      {:error, reason} -> {:error, {:rpc_error, reason}}
    end
  end

  # eth_getCode / eth_chainId are not expected to fail with a node-side
  # error; when they do, verification cannot conclude anything — fail closed
  # as an RPC error rather than an invalid payment.
  @spec expect_rpc_ok(RPC.batch_result()) :: {:ok, term()} | {:error, {:rpc_error, RPC.error()}}
  defp expect_rpc_ok({:ok, value}), do: {:ok, value}
  defp expect_rpc_ok({:error, reason}), do: {:error, {:rpc_error, reason}}

  @spec check_chain_id(map(), map(), keyword()) ::
          :ok | {:error, {:rpc_error, RPC.error()} | {:chain_id_mismatch, term(), term()}}
  defp check_chain_id(%{chain_id: nil}, _ctx, _opts), do: :ok

  defp check_chain_id(%{chain_id: chain_id_result}, ctx, _opts) do
    with {:ok, hex} <- expect_rpc_ok(chain_id_result) do
      case parse_quantity(hex) do
        {:ok, actual} when actual == ctx.chain_id -> :ok
        {:ok, actual} -> {:error, {:chain_id_mismatch, ctx.chain_id, actual}}
        :error -> {:error, {:rpc_error, {:invalid_response, hex}}}
      end
    end
  end

  # eth_call on an EOA asset returns empty data without reverting, so a
  # simulation would "pass" while settling nothing — reject explicitly.
  @spec check_asset_deployed(map()) :: :ok | {:error, {:invalid, :asset_not_deployed_contract}}
  defp check_asset_deployed(%{asset_code: code}) do
    case deployed_code?(code) do
      true -> :ok
      false -> {:error, {:invalid, :asset_not_deployed_contract}}
    end
  end

  # Permit2 kinds only (`proxy_code` is nil otherwise): a missing proxy on
  # this chain means settle can never succeed.
  @spec check_proxy_deployed(map()) :: :ok | {:error, {:invalid, :permit2_proxy_not_deployed}}
  defp check_proxy_deployed(%{proxy_code: nil}), do: :ok

  defp check_proxy_deployed(%{proxy_code: code}) do
    case deployed_code?(code) do
      true -> :ok
      false -> {:error, {:invalid, :permit2_proxy_not_deployed}}
    end
  end

  @spec check_balance(map(), map()) ::
          :ok | {:error, {:invalid, :insufficient_balance | :balance_check_failed}}
  defp check_balance(%{balance: {:ok, hex}}, ctx) do
    case decode_uint_return(hex) do
      {:ok, balance} when balance >= ctx.value -> :ok
      {:ok, _balance} -> {:error, {:invalid, :insufficient_balance}}
      :error -> {:error, {:invalid, :balance_check_failed}}
    end
  end

  defp check_balance(%{balance: {:error, _reason}}, _ctx),
    do: {:error, {:invalid, :balance_check_failed}}

  # Signature routing mirrors on-chain SignatureChecker semantics: bytecode
  # at the payer decides the path — ecrecover with no code, strict ERC-1271
  # with code (no ECDSA fallback), counterfactual ERC-6492 deferred to the
  # atomic deploy-and-transfer simulation.
  @spec classify_and_verify(RPC.t(), map(), ERC6492.parsed(), binary(), map(), keyword()) ::
          {:ok, signature_type()} | {:error, error()}
  defp classify_and_verify(rpc, ctx, parsed, digest, chain_state, opts) do
    deployed? = deployed_code?(chain_state.payer_code)
    deployment_info? = parsed.factory != nil

    cond do
      deployed? ->
        with :ok <- verify_erc1271(rpc, ctx, digest, parsed.inner_signature) do
          {:ok, :erc1271}
        end

      deployment_info? ->
        with :ok <- check_counterfactual_policy(parsed, opts) do
          {:ok, :erc6492_counterfactual}
        end

      true ->
        with :ok <- verify_eoa(ctx, digest, parsed.inner_signature) do
          {:ok, :eoa}
        end
    end
  end

  @spec verify_erc1271(RPC.t(), map(), binary(), binary()) ::
          :ok | {:error, {:invalid, :invalid_signature} | {:rpc_error, RPC.error()}}
  defp verify_erc1271(rpc, ctx, digest, inner_signature) do
    calldata =
      @selector_is_valid_signature <>
        digest <>
        <<64::unsigned-big-integer-size(256)>> <> EIP712.encode_dynamic_bytes(inner_signature)

    case RPC.call(rpc, %{"to" => ctx.payer, "data" => hex(calldata)}) do
      {:ok, return_hex} ->
        case erc1271_magic?(return_hex) do
          true -> :ok
          false -> {:error, {:invalid, :invalid_signature}}
        end

      # A revert from isValidSignature means the contract rejects the
      # signature — invalid, matching the reference implementations.
      {:error, {:jsonrpc_error, _error}} ->
        {:error, {:invalid, :invalid_signature}}

      {:error, reason} ->
        {:error, {:rpc_error, reason}}
    end
  end

  @spec erc1271_magic?(term()) :: boolean()
  defp erc1271_magic?(return_hex) do
    case unhex(return_hex) do
      {:ok, <<magic::binary-size(4), _rest::binary>>} -> magic == @erc1271_magic_value
      _other -> false
    end
  end

  @spec check_counterfactual_policy(ERC6492.parsed(), keyword()) ::
          :ok
          | {:error, {:invalid, :eip6492_factory_not_allowed | :undeployed_smart_wallet}}
  defp check_counterfactual_policy(parsed, opts) do
    allowed =
      opts
      |> Keyword.fetch!(:eip6492_allowed_factories)
      |> Enum.map(&String.downcase(String.trim(&1)))

    cond do
      String.downcase(parsed.factory) not in allowed ->
        {:error, {:invalid, :eip6492_factory_not_allowed}}

      Keyword.fetch!(opts, :simulate) == false ->
        # A counterfactual signature is only ever proven by simulation;
        # without it the payment stays unproven — fail closed.
        # (:counterfactual_only keeps exactly this proof running.)
        {:error, {:invalid, :undeployed_smart_wallet}}

      true ->
        :ok
    end
  end

  # -- Simulation -------------------------------------------------------------

  @spec maybe_simulate(RPC.t(), map(), ERC6492.parsed(), signature_type(), keyword()) ::
          :ok | {:error, error()}
  defp maybe_simulate(rpc, ctx, parsed, :erc6492_counterfactual, opts),
    do: simulate_counterfactual(rpc, ctx, parsed, opts)

  # Both `false` and `:counterfactual_only` skip here — under
  # `:counterfactual_only` only the atomic counterfactual simulation (the
  # clause above) runs.
  defp maybe_simulate(rpc, ctx, parsed, signature_type, opts) do
    case Keyword.fetch!(opts, :simulate) do
      true -> simulate_transfer(rpc, ctx, parsed, signature_type)
      _skip -> :ok
    end
  end

  @spec simulate_transfer(RPC.t(), map(), ERC6492.parsed(), signature_type()) ::
          :ok | {:error, error()}
  defp simulate_transfer(rpc, ctx, parsed, signature_type) do
    with {:ok, calldata} <- transfer_calldata(ctx, parsed.inner_signature, signature_type) do
      case RPC.call(rpc, simulation_call(ctx, calldata)) do
        {:ok, _return} -> :ok
        {:error, {:jsonrpc_error, error}} -> handle_simulation_revert(rpc, ctx, error)
        {:error, reason} -> {:error, {:rpc_error, reason}}
      end
    end
  end

  # EIP-3009 transfers go to the token; Permit2 settlements go to the proxy.
  # The upto proxy only accepts the witness facilitator as msg.sender, so
  # that simulation must originate from it.
  @spec simulation_call(map(), binary()) :: map()
  defp simulation_call(%{kind: :eip3009} = ctx, calldata),
    do: %{"to" => ctx.asset, "data" => hex(calldata)}

  defp simulation_call(%{kind: :permit2_exact} = ctx, calldata),
    do: %{"to" => ctx.spender, "data" => hex(calldata), "from" => ctx.payer}

  defp simulation_call(%{kind: :permit2_upto} = ctx, calldata) do
    facilitator = Utils.map_value(ctx.witness, {"facilitator", :facilitator})
    %{"to" => ctx.spender, "data" => hex(calldata), "from" => facilitator}
  end

  @spec simulation_target(map()) :: String.t()
  defp simulation_target(%{kind: :eip3009} = ctx), do: ctx.asset
  defp simulation_target(ctx), do: ctx.spender

  # Counterfactual wallets are deployed and charged in a single atomic
  # eth_call through Multicall3 — factory deployment then
  # transferWithAuthorization (or the proxy's settle), with the deployment's
  # state visible to the transfer. This is the only check that can prove an
  # ERC-6492 counterfactual signature. Note the upto proxy rejects
  # Multicall3 as msg.sender, so counterfactual upto payments cannot be
  # proven this way and surface as `:upto_unauthorized_facilitator`.
  @spec simulate_counterfactual(RPC.t(), map(), ERC6492.parsed(), keyword()) ::
          :ok | {:error, error()}
  defp simulate_counterfactual(rpc, ctx, parsed, opts) do
    with {:ok, transfer} <-
           transfer_calldata(ctx, parsed.inner_signature, :erc6492_counterfactual) do
      calldata =
        aggregate3_calldata([
          {parsed.factory, parsed.factory_calldata},
          {simulation_target(ctx), transfer}
        ])

      multicall = Keyword.fetch!(opts, :multicall_address)

      case RPC.call(rpc, %{"to" => multicall, "data" => hex(calldata)}) do
        {:ok, return_hex} -> check_counterfactual_result(rpc, ctx, return_hex)
        {:error, {:jsonrpc_error, error}} -> handle_simulation_revert(rpc, ctx, error)
        {:error, reason} -> {:error, {:rpc_error, reason}}
      end
    end
  end

  @spec check_counterfactual_result(RPC.t(), map(), term()) :: :ok | {:error, error()}
  defp check_counterfactual_result(rpc, ctx, return_hex) do
    case decode_aggregate3_return(return_hex) do
      {:ok, [_deploy_result, {true, _return_data}]} ->
        :ok

      {:ok, [_deploy_result, {false, return_data}]} ->
        error = %{code: nil, message: nil, data: hex(return_data)}

        case classify_for_kind(ctx, error) do
          nil -> diagnose(rpc, ctx)
          reason -> {:error, {:invalid, reason}}
        end

      _other ->
        {:error, {:invalid, :simulation_failed}}
    end
  end

  @spec handle_simulation_revert(RPC.t(), map(), RPC.jsonrpc_error()) :: {:error, error()}
  defp handle_simulation_revert(rpc, ctx, error) do
    case classify_for_kind(ctx, error) do
      nil -> diagnose(rpc, ctx)
      reason -> {:error, {:invalid, reason}}
    end
  end

  @spec classify_for_kind(map(), RPC.jsonrpc_error()) :: invalid_reason() | nil
  defp classify_for_kind(%{kind: :eip3009}, error), do: classify_revert(error)
  defp classify_for_kind(_ctx, error), do: classify_permit2_revert(error)

  # Classifies a node revert (message plus any ABI-encoded Error(string)
  # data) onto the canonical invalid reasons. Public so
  # `X402.Facilitator.Engine` can classify `eth_estimateGas` reverts during
  # settlement — e.g. a retry of an already-confirmed authorization must
  # report `:nonce_already_used`, not a generic simulation failure. Returns
  # `nil` when the revert text is unrecognized.
  @doc false
  @spec classify_revert(RPC.jsonrpc_error()) :: invalid_reason() | nil
  def classify_revert(error), do: classify_revert_text(revert_text(error))

  # Combines the node's error message with any ABI-encoded Error(string)
  # revert reason carried in the error data.
  @spec revert_text(RPC.jsonrpc_error()) :: String.t()
  defp revert_text(error) do
    message = error.message || ""

    data_text =
      case error.data do
        "0x" <> _rest = data ->
          case unhex(data) do
            {:ok, bytes} -> decode_revert_string(bytes) || ""
            _other -> ""
          end

        _other ->
          ""
      end

    message <> " " <> data_text
  end

  # Maps a revert reason onto the reference implementations' error codes
  # (parseEip3009TransferError). Returns nil when unrecognized so the caller
  # can fall back to the diagnostic probes.
  @spec classify_revert_text(String.t()) :: invalid_reason() | nil
  defp classify_revert_text(text) do
    cond do
      text =~ ~r/authorization is (already )?used|AuthorizationAlreadyUsed|used or canceled/i ->
        :nonce_already_used

      text =~ ~r/authorization is expired|AuthorizationExpired|valid before/i ->
        :valid_before_expired

      text =~ ~r/authorization is not yet valid|AuthorizationNotYetValid/i ->
        :valid_after_in_future

      text =~ ~r/transfer amount exceeds balance|insufficient.*balance|ERC20InsufficientBalance/i ->
        :insufficient_balance

      text =~ ~r/invalid signature|SignerMismatch|InvalidSignatureV|InvalidSignatureS/i ->
        :invalid_signature

      true ->
        nil
    end
  end

  # One diagnostic batch after an unclassified simulation failure, mirroring
  # the reference multicall probe: authorizationState, token name/version,
  # and balance, most-specific reason first.
  @spec diagnose(RPC.t(), map()) :: {:error, error()}
  defp diagnose(rpc, %{kind: :eip3009} = ctx) do
    requests = [
      eth_call_request(ctx.asset, @selector_authorization_state <> authorization_state_args(ctx)),
      eth_call_request(ctx.asset, @selector_name),
      eth_call_request(ctx.asset, @selector_version),
      eth_call_request(ctx.asset, @selector_balance_of <> address_word(ctx.payer))
    ]

    case RPC.batch(rpc, requests) do
      {:ok, [auth_state, name, version, balance]} ->
        {:error, {:invalid, diagnose_reason(ctx, auth_state, name, version, balance)}}

      {:error, _reason} ->
        {:error, {:invalid, :simulation_failed}}
    end
  end

  # Permit2 probe, mirroring the reference facilitator: is the proxy
  # deployed (its PERMIT2() getter answers), does the payer hold the amount,
  # and has the payer approved the canonical Permit2 contract for it.
  defp diagnose(rpc, ctx) do
    requests = [
      eth_call_request(ctx.spender, @selector_permit2_getter),
      eth_call_request(ctx.asset, @selector_balance_of <> address_word(ctx.payer)),
      eth_call_request(ctx.asset, @selector_allowance <> allowance_args(ctx))
    ]

    case RPC.batch(rpc, requests) do
      {:ok, [proxy, balance, allowance]} ->
        {:error, {:invalid, diagnose_permit2_reason(ctx, proxy, balance, allowance)}}

      {:error, _reason} ->
        {:error, {:invalid, :permit2_simulation_failed}}
    end
  end

  @spec diagnose_permit2_reason(
          map(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result()
        ) :: invalid_reason()
  defp diagnose_permit2_reason(ctx, proxy, balance, allowance) do
    cond do
      not match?({:ok, _hex}, proxy) or not deployed_code?(elem(proxy, 1)) ->
        :permit2_proxy_not_deployed

      balance_below?(balance, ctx.value) ->
        :permit2_insufficient_balance

      balance_below?(allowance, ctx.value) ->
        :permit2_allowance_required

      true ->
        :permit2_simulation_failed
    end
  end

  @spec allowance_args(map()) :: binary()
  defp allowance_args(ctx),
    do: address_word(ctx.payer) <> address_word(Permit2.permit2_address())

  @spec diagnose_reason(
          map(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result()
        ) :: invalid_reason()
  defp diagnose_reason(ctx, auth_state, name, version, balance) do
    cond do
      match?({:error, _reason}, auth_state) -> :eip3009_not_supported
      decoded_bool(auth_state) == true -> :nonce_already_used
      string_mismatch?(name, ctx.extra_name) -> :token_name_mismatch
      string_mismatch?(version, ctx.extra_version) -> :token_version_mismatch
      balance_below?(balance, ctx.value) -> :insufficient_balance
      true -> :simulation_failed
    end
  end

  @spec decoded_bool(RPC.batch_result()) :: boolean() | nil
  defp decoded_bool({:ok, hex}) do
    case decode_uint_return(hex) do
      {:ok, value} -> value != 0
      :error -> nil
    end
  end

  defp decoded_bool(_result), do: nil

  @spec string_mismatch?(RPC.batch_result(), String.t()) :: boolean()
  defp string_mismatch?({:ok, hex}, expected) do
    case decode_string_return(hex) do
      {:ok, actual} -> actual != expected
      :error -> false
    end
  end

  defp string_mismatch?(_result, _expected), do: false

  @spec balance_below?(RPC.batch_result(), non_neg_integer()) :: boolean()
  defp balance_below?({:ok, hex}, amount) do
    case decode_uint_return(hex) do
      {:ok, balance} -> balance < amount
      :error -> false
    end
  end

  defp balance_below?(_result, _amount), do: false

  # -- Calldata construction --------------------------------------------------

  @spec eth_call_request(String.t(), binary()) :: RPC.batch_request()
  defp eth_call_request(to, calldata),
    do: {"eth_call", [%{"to" => to, "data" => hex(calldata)}, "latest"]}

  @spec balance_of_calldata(map()) :: String.t()
  defp balance_of_calldata(ctx), do: hex(@selector_balance_of <> address_word(ctx.payer))

  @spec authorization_state_args(map()) :: binary()
  defp authorization_state_args(ctx) do
    {:ok, nonce_word} = EIP712.encode_bytes32(ctx.nonce)
    address_word(ctx.payer) <> nonce_word
  end

  @spec address_word(String.t()) :: binary()
  defp address_word(address) do
    {:ok, word} = EIP712.encode_address(address)
    word
  end

  # The calldata is built by the shared EIP-3009 builder — the same code path
  # X402.Facilitator.Engine signs at settlement, so simulation and settlement
  # can never diverge. The overload is selected by the VERIFIED signature
  # type, never byte length: a smart wallet's ERC-1271 signature can be
  # exactly 65 bytes, and the (v, r, s) overload performs on-chain ECDSA,
  # which would wrongly reject it.
  #
  # Permit2 settlements always pass the raw signature bytes: Permit2 routes
  # EOA vs. contract verification itself from the owner's bytecode.
  @spec transfer_calldata(map(), binary(), signature_type()) ::
          {:ok, binary()} | {:error, {:invalid, :invalid_signature}}
  defp transfer_calldata(ctx, inner_signature, signature_type) do
    case settlement_calldata(ctx, inner_signature, signature_type) do
      {:ok, calldata} -> {:ok, calldata}
      {:error, _reason} -> {:error, {:invalid, :invalid_signature}}
    end
  end

  @spec settlement_calldata(map(), binary(), signature_type()) ::
          {:ok, binary()} | {:error, term()}
  defp settlement_calldata(%{kind: :eip3009} = ctx, inner_signature, signature_type),
    do: EIP3009.transfer_calldata(ctx.authorization, inner_signature, signature_type)

  defp settlement_calldata(%{kind: :permit2_exact} = ctx, inner_signature, _signature_type),
    do: Permit2.exact_settle_calldata(ctx.authorization, inner_signature)

  defp settlement_calldata(%{kind: :permit2_upto} = ctx, inner_signature, _signature_type),
    do: Permit2.upto_settle_calldata(ctx.authorization, ctx.value, inner_signature)

  # aggregate3(Call3[] calls) with Call3 = (address target, bool allowFailure,
  # bytes callData). Every sub-call is encoded with allowFailure = true so the
  # transfer leg's individual status can be inspected (mirroring the reference
  # implementations).
  @spec aggregate3_calldata([{String.t(), binary()}]) :: binary()
  defp aggregate3_calldata(calls) do
    encoded_tuples = Enum.map(calls, &encode_call3/1)

    {offsets, _end} =
      Enum.map_reduce(encoded_tuples, 32 * length(calls), fn tuple, position ->
        {position, position + byte_size(tuple)}
      end)

    array =
      <<length(calls)::unsigned-big-integer-size(256)>> <>
        Enum.map_join(offsets, &<<&1::unsigned-big-integer-size(256)>>) <>
        Enum.join(encoded_tuples)

    @selector_aggregate3 <> <<32::unsigned-big-integer-size(256)>> <> array
  end

  @spec encode_call3({String.t(), binary()}) :: binary()
  defp encode_call3({target, calldata}) do
    address_word(target) <>
      <<1::unsigned-big-integer-size(256)>> <>
      <<3 * 32::unsigned-big-integer-size(256)>> <> EIP712.encode_dynamic_bytes(calldata)
  end

  # -- Return-data decoding ---------------------------------------------------

  @spec decode_aggregate3_return(term()) :: {:ok, [{boolean(), binary()}]} | :error
  defp decode_aggregate3_return(return_hex) do
    with {:ok, bytes} <- unhex(return_hex),
         <<32::unsigned-big-integer-size(256), rest::binary>> <- bytes,
         <<count::unsigned-big-integer-size(256), elements::binary>> when count > 0 <- rest do
      decode_aggregate3_elements(elements, count)
    else
      _other -> :error
    end
  end

  @spec decode_aggregate3_elements(binary(), pos_integer()) ::
          {:ok, [{boolean(), binary()}]} | :error
  defp decode_aggregate3_elements(elements, count) do
    results =
      Enum.map(0..(count - 1), fn index ->
        with {:ok, offset} <- word_at(elements, index * 32),
             {:ok, success} <- word_at(elements, offset),
             {:ok, data_offset} <- word_at(elements, offset + 32),
             {:ok, length} <- word_at(elements, offset + data_offset),
             true <- offset + data_offset + 32 + length <= byte_size(elements) do
          {:ok, {success == 1, binary_part(elements, offset + data_offset + 32, length)}}
        else
          _other -> :error
        end
      end)

    case Enum.all?(results, &match?({:ok, _result}, &1)) do
      true -> {:ok, Enum.map(results, fn {:ok, result} -> result end)}
      false -> :error
    end
  end

  @spec word_at(binary(), non_neg_integer()) :: {:ok, non_neg_integer()} | :error
  defp word_at(bytes, position) when position + 32 <= byte_size(bytes) do
    <<word::unsigned-big-integer-size(256)>> = binary_part(bytes, position, 32)
    {:ok, word}
  end

  defp word_at(_bytes, _position), do: :error

  @spec decode_uint_return(term()) :: {:ok, non_neg_integer()} | :error
  defp decode_uint_return(return_hex) when is_binary(return_hex) do
    case unhex(return_hex) do
      {:ok, bytes} when byte_size(bytes) >= 32 ->
        <<value::unsigned-big-integer-size(256), _rest::binary>> = bytes
        {:ok, value}

      _other ->
        :error
    end
  end

  defp decode_uint_return(_return), do: :error

  @spec decode_string_return(term()) :: {:ok, String.t()} | :error
  defp decode_string_return(return_hex) when is_binary(return_hex) do
    with {:ok, bytes} <- unhex(return_hex),
         {:ok, offset} <- word_at(bytes, 0),
         {:ok, length} <- word_at(bytes, offset),
         true <- offset + 32 + length <= byte_size(bytes) do
      {:ok, binary_part(bytes, offset + 32, length)}
    else
      _other -> :error
    end
  end

  defp decode_string_return(_return), do: :error

  # Decodes a standard Error(string) revert payload (selector 0x08c379a0).
  @spec decode_revert_string(binary()) :: String.t() | nil
  defp decode_revert_string(<<0x08, 0xC3, 0x79, 0xA0, encoded::binary>>) do
    case decode_string_return("0x" <> Base.encode16(encoded, case: :lower)) do
      {:ok, reason} -> reason
      :error -> nil
    end
  end

  defp decode_revert_string(_bytes), do: nil

  # -- Hex / padding helpers --------------------------------------------------

  @spec deployed_code?(term()) :: boolean()
  defp deployed_code?(code) when is_binary(code) do
    case unhex(code) do
      {:ok, bytes} -> byte_size(bytes) > 0
      _other -> false
    end
  end

  defp deployed_code?(_code), do: false

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)

  @spec unhex(term()) :: {:ok, binary()} | :error
  defp unhex("0x" <> hex_digits), do: Base.decode16(hex_digits, case: :mixed)
  defp unhex(_value), do: :error

  @spec parse_quantity(term()) :: {:ok, non_neg_integer()} | :error
  defp parse_quantity("0x" <> hex_digits) when hex_digits != "" do
    case Integer.parse(hex_digits, 16) do
      {value, ""} -> {:ok, value}
      _parsed -> :error
    end
  end

  defp parse_quantity(_value), do: :error
end
