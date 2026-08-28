defmodule X402.Facilitator.Engine do
  @moduledoc """
  Facilitator-role engine: verify and settle x402 payments yourself.

  While `X402.Facilitator` is the *client* of a remote facilitator, this
  module is the facilitator itself. It assembles the SDK's local
  verification core (`X402.Verify.EVM`), JSON-RPC client (`X402.RPC`),
  transaction encoder (`X402.Transaction`), and signer behaviour
  (`X402.Signer`) into the engine behind the facilitator API's three
  operations, speaking the same wire shapes as the reference facilitators:

  * `verify/3` — the full exact-EVM verify checklist at `:full` level,
    returning the `POST /verify` response
    (`%{"isValid" => true, "payer" => ...}` /
    `%{"isValid" => false, "invalidReason" => ..., "payer" => ...}`).
  * `settle/3` — **re-verifies independently** (the exact-EVM scheme's
    normative requirement), then broadcasts the `transferWithAuthorization`
    transaction and awaits its receipt, returning the `POST /settle`
    response (`%{"success" => true, "transaction" => ..., ...}` /
    `%{"success" => false, "errorReason" => ..., ...}`).
  * `supported/1` — the `GET /supported` response derived from the
    configured networks.

  Expose the engine over HTTP with `X402.Plug.Facilitator`, or call it
  directly from your own transport.

  ## Fee-payer safety

  The facilitator's signing key pays gas, so what it signs is structurally
  constrained: settlement transactions are always built by this module with
  `to` set to the verified requirements' `asset`, `value` `0`, and calldata
  produced exclusively by `X402.EIP3009.transfer_calldata/3` from the
  authorization fields the signature verification just proved. The single
  exception is ERC-6492 *counterfactual* settlement: the engine signs
  caller-supplied calldata ONLY toward explicitly allowlisted factory
  addresses (`:eip6492_allowed_factories`), capped by
  `:max_deploy_gas_limit` — with the default empty allowlist it never does,
  and counterfactual payments are rejected fail-closed at verify **and** at
  settle's re-verify. Deployed ERC-1271 smart wallets are fully supported
  either way.

  ## Settlement pipeline

  1. Reconcile: with a `:pending_settlement_store` configured, a payload
     whose earlier attempt already broadcast a transaction is re-awaited
     instead of re-verified and re-broadcast.
  2. Re-verify via `X402.Verify.EVM` at `:full` level (transfer simulation
     off by default — verify already simulated; see `:simulate_in_settle` —
     while the atomic ERC-6492 counterfactual simulation always runs, being
     the only possible proof of a counterfactual signature).
  3. For a verified counterfactual payment whose wallet is still
     undeployed, broadcast the wrapper's factory calldata (allowlist-gated,
     `:max_deploy_gas_limit`-capped) and require a successful deploy
     receipt first.
  4. Build `transferWithAuthorization` calldata (shared with verification's
     simulation encoding).
  5. One batched RPC round-trip: `eth_estimateGas` (with a safety margin),
     `eth_maxPriorityFeePerGas` + `eth_feeHistory` (falling back to
     `eth_gasPrice` on nodes without EIP-1559 fee APIs), and
     `eth_getTransactionCount` (`pending`).
  6. Encode the EIP-1559 transaction (`X402.Transaction`), sign its keccak
     digest through the configured `X402.Signer` (the signer must support
     raw digest signing — `X402.Signer.LocalKey` does; the 27/28 recovery id
     it returns is normalized to the EIP-1559 `yParity`), and broadcast via
     `eth_sendRawTransaction`.
  7. Poll `eth_getTransactionReceipt` until confirmation or timeout. A
     confirmed receipt must also carry the matching ERC-20 `Transfer` event
     before success is reported. A broadcast whose confirmation cannot be
     established returns the spec's non-terminal `"settlement_pending"`
     with the transaction hash so callers can reconcile on chain, recording
     the attempt in the `:pending_settlement_store` when one is configured.

  ## Hooks

  `X402.Hooks` callbacks wrap both operations, mirroring the reference
  facilitator's lifecycle hooks: `before_*` returning `{:halt, reason}`
  turns into a rejected wire response (not an exception), `after_*` runs on
  successful results and may replace them, and `on_*_failure` runs for both
  rejected wire responses and infrastructure errors and may `{:recover,
  result}` with a replacement response. The internal re-verify inside
  `settle/3` runs without hooks — the settle hooks already wrap it.

  ## Example

      {:ok, rpc} = X402.RPC.new(rpc_url: "https://sepolia.base.org", finch: MyApp.Finch)
      {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PRIVATE_KEY"))

      {:ok, engine} =
        X402.Facilitator.Engine.new(
          rpc: rpc,
          signer: signer,
          networks: ["eip155:84532"]
        )

      {:ok, %{"isValid" => true, "payer" => payer}} =
        X402.Facilitator.Engine.verify(engine, payment_payload, requirements)

      {:ok, %{"success" => true, "transaction" => tx_hash}} =
        X402.Facilitator.Engine.settle(engine, payment_payload, requirements)

  ## Telemetry

  Emits `[:x402, :facilitator_engine, :verify]` and
  `[:x402, :facilitator_engine, :settle]` with `:status` metadata.
  """

  require Logger

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.ERC6492
  alias X402.Facilitator.NonceManager
  alias X402.Facilitator.PendingSettlementStore
  alias X402.Hooks
  alias X402.Hooks.Context
  alias X402.RPC
  alias X402.Signer
  alias X402.Telemetry
  alias X402.Transaction
  alias X402.Utils
  alias X402.Verify.EVM

  @x402_version 2
  @scheme "exact"

  # keccak256("Transfer(address,address,uint256)")
  @transfer_event_topic "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

  @max_uint256 Integer.pow(2, 256) - 1

  @enforce_keys [:rpc, :signer, :networks]
  defstruct [
    :rpc,
    :signer,
    :networks,
    hooks: X402.Hooks.Default,
    simulate: true,
    simulate_in_settle: false,
    verify_chain_id: true,
    gas_limit_margin_percent: 20,
    receipt_timeout_ms: 60_000,
    receipt_interval_ms: 1_000,
    nonce_manager: nil,
    max_gas_limit: 200_000,
    eip6492_allowed_factories: [],
    max_deploy_gas_limit: 600_000,
    pending_settlement_store: nil
  ]

  @typedoc "A validated engine configuration built by `new/1`."
  @type t :: %__MODULE__{
          rpc: RPC.t(),
          signer: Signer.t(),
          networks: [String.t()],
          hooks: module(),
          simulate: boolean(),
          simulate_in_settle: boolean(),
          verify_chain_id: boolean(),
          gas_limit_margin_percent: non_neg_integer(),
          receipt_timeout_ms: pos_integer(),
          receipt_interval_ms: pos_integer(),
          nonce_manager: GenServer.server() | nil,
          max_gas_limit: pos_integer(),
          eip6492_allowed_factories: [String.t()],
          max_deploy_gas_limit: pos_integer(),
          pending_settlement_store: PendingSettlementStore.adapter() | nil
        }

  @typedoc "A facilitator wire response (`/verify` or `/settle` shape)."
  @type wire_response :: %{optional(String.t()) => term()}

  @config_schema [
    rpc: [
      type: {:custom, RPC, :validate_config, []},
      required: true,
      doc: "An `X402.RPC` configuration for the served network."
    ],
    signer: [
      type: {:custom, __MODULE__, :validate_signer, []},
      required: true,
      doc: """
      The fee-payer signer (a struct implementing `X402.Signer`). Its key
      pays settlement gas and must support signing raw 32-byte digests.
      """
    ],
    networks: [
      type: {:custom, __MODULE__, :validate_networks, []},
      required: true,
      doc: """
      Non-empty list of CAIP-2 networks this engine serves (currently
      `eip155:<chainId>` only). Verify and settle requests for other
      networks are rejected with `invalid_network`.
      """
    ],
    hooks: [
      type: {:custom, Hooks, :validate_module, []},
      default: X402.Hooks.Default,
      doc: "Lifecycle hook module implementing `X402.Hooks`."
    ],
    simulate: [
      type: :boolean,
      default: true,
      doc: """
      Whether `verify/3` simulates `transferWithAuthorization` via
      `eth_call`. Even when `false`, verify keeps the atomic ERC-6492
      counterfactual simulation — the only possible proof of a
      counterfactual signature — so verify predicts settle, whose re-verify
      always keeps that proof too.
      """
    ],
    simulate_in_settle: [
      type: :boolean,
      default: false,
      doc: """
      Whether the independent re-verify inside `settle/3` also simulates.
      Off by default, matching the reference facilitators — verify already
      simulated, and `eth_estimateGas` re-simulates right before broadcast.
      Even when off, the re-verify keeps the atomic ERC-6492 counterfactual
      simulation, the only possible proof of a counterfactual signature.
      """
    ],
    verify_chain_id: [
      type: :boolean,
      default: true,
      doc: "Whether verification cross-checks `eth_chainId` against the CAIP-2 network."
    ],
    gas_limit_margin_percent: [
      type: :non_neg_integer,
      default: 20,
      doc: "Safety margin added to `eth_estimateGas` (percent)."
    ],
    receipt_timeout_ms: [
      type: :pos_integer,
      default: 60_000,
      doc: """
      How long `settle/3` waits for the transaction receipt before returning
      the non-terminal `"settlement_pending"` response.
      """
    ],
    receipt_interval_ms: [
      type: :pos_integer,
      default: 1_000,
      doc: "Interval between `eth_getTransactionReceipt` polls."
    ],
    nonce_manager: [
      type: {:or, [nil, :atom, :pid, :any]},
      default: nil,
      doc: """
      Optional `X402.Facilitator.NonceManager` (pid/name) serializing
      fee-payer nonces. Without it, each settlement reads the pending nonce
      from the node, which races under concurrent settles — configure the
      manager for any deployment that settles concurrently.
      """
    ],
    max_gas_limit: [
      type: :pos_integer,
      default: 200_000,
      doc: """
      Absolute gas ceiling per settlement transaction (margin included). A
      legitimate `transferWithAuthorization` costs well under 100k gas; an
      estimate above this ceiling means the asset contract is burning the
      fee payer's gas and the settlement is refused — the fee payer never
      broadcasts unbounded-gas transactions against unvetted bytecode.
      """
    ],
    eip6492_allowed_factories: [
      type: {:list, :string},
      default: [],
      doc: """
      Factory contract addresses (case-insensitive) trusted to deploy
      counterfactual ERC-6492 smart wallets during settlement. Threaded
      into verification so verify predicts settle. The default empty list
      keeps the fail-closed behavior: every counterfactual payment is
      rejected and the engine never signs caller-supplied factory calldata.
      """
    ],
    max_deploy_gas_limit: [
      type: :pos_integer,
      default: 600_000,
      doc: """
      Absolute gas ceiling for the ERC-6492 factory deployment transaction
      (margin included). Smart-account deployments legitimately cost far
      more than a transfer (~300k gas), so the deployment carries its own
      ceiling; the transfer keeps `:max_gas_limit`.
      """
    ],
    pending_settlement_store: [
      type: {:or, [nil, {:custom, PendingSettlementStore, :validate_adapter, []}]},
      default: nil,
      doc: """
      Optional `{module, store}` adapter implementing
      `X402.Facilitator.PendingSettlementStore`. When configured, `settle/3`
      records broadcasts whose confirmation could not be established and
      reconciles a retried payload against the already-broadcast transaction
      instead of broadcasting a second one.
      """
    ]
  ]

  @doc since: "0.6.0"
  @doc """
  Builds a validated engine configuration.

  ## Options

  #{NimbleOptions.docs(@config_schema)}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, NimbleOptions.ValidationError.t()}
  def new(opts) when is_list(opts) do
    case NimbleOptions.validate(opts, @config_schema) do
      {:ok, validated} -> {:ok, struct!(__MODULE__, validated)}
      {:error, error} -> {:error, error}
    end
  end

  @doc since: "0.6.0"
  @doc group: :verification
  @doc """
  Verifies a payment payload against requirements, returning the
  `POST /verify` wire response.

  Returns `{:ok, response}` for every *protocol-level* outcome — including
  rejected payments, which come back as
  `%{"isValid" => false, "invalidReason" => reason, "payer" => payer}` with
  the canonical cross-SDK reason string (`X402.Verify.EVM.reason_string/1`).
  `{:error, reason}` is reserved for infrastructure failures (RPC transport
  errors, missing crypto dependencies, hook crashes) where no verdict about
  the payment exists; transports should map it to an opaque 500.
  """
  @spec verify(t(), map(), map()) :: {:ok, wire_response()} | {:error, term()}
  def verify(%__MODULE__{} = engine, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    metadata = hook_metadata(:verify, engine)
    context = Context.new(payment_payload, requirements)

    result =
      case run_before_hook(engine.hooks, :before_verify, context, metadata) do
        {:cont, %Context{} = before_context} ->
          engine
          |> verify_result(
            before_context.payload,
            before_context.requirements,
            verify_simulate(engine)
          )
          |> handle_verify_result(engine, before_context, metadata)

        {:halt, reason} ->
          {:ok, invalid_response(stringify_reason(reason), payer(payment_payload))}

        {:error, reason} ->
          {:error, reason}
      end

    emit_telemetry(:verify, result)
    result
  end

  @doc since: "0.6.0"
  @doc group: :settlement
  @doc """
  Settles a payment, returning the `POST /settle` wire response.

  Independently re-verifies the payment first (normative for the exact-EVM
  scheme), then broadcasts `transferWithAuthorization` and awaits the
  receipt — see the module documentation for the full pipeline. Rejected or
  failed settlements come back as `{:ok, %{"success" => false,
  "errorReason" => reason, ...}}`; a broadcast whose confirmation could not
  be established returns the non-terminal `"settlement_pending"` reason
  with the transaction hash. `{:error, reason}` is reserved for
  infrastructure failures where nothing was broadcast.
  """
  @spec settle(t(), map(), map()) :: {:ok, wire_response()} | {:error, term()}
  def settle(%__MODULE__{} = engine, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    metadata = hook_metadata(:settle, engine)
    context = Context.new(payment_payload, requirements)

    result =
      case run_before_hook(engine.hooks, :before_settle, context, metadata) do
        {:cont, %Context{} = before_context} ->
          engine
          |> settle_result(before_context.payload, before_context.requirements)
          |> handle_settle_result(engine, before_context, metadata)

        {:halt, reason} ->
          {:ok,
           failure_response(
             stringify_reason(reason),
             "",
             network(requirements, payment_payload),
             payer(payment_payload)
           )}

        {:error, reason} ->
          {:error, reason}
      end

    emit_telemetry(:settle, result)
    result
  end

  @doc since: "0.6.0"
  @doc group: :discovery
  @doc """
  Returns the `GET /supported` wire response for this engine.

  One `exact` kind per configured network, no extensions, and the signer's
  address under the `eip155:*` family.

  ## Examples

      {:ok, engine} = X402.Facilitator.Engine.new(rpc: rpc, signer: signer, networks: ["eip155:84532"])
      X402.Facilitator.Engine.supported(engine)
      #=> %{
      #     "kinds" => [%{"x402Version" => 2, "scheme" => "exact", "network" => "eip155:84532"}],
      #     "extensions" => [],
      #     "signers" => %{"eip155:*" => ["0x..."]}
      #   }
  """
  @spec supported(t()) :: wire_response()
  def supported(%__MODULE__{} = engine) do
    %{
      "kinds" =>
        Enum.map(engine.networks, fn network ->
          %{"x402Version" => @x402_version, "scheme" => @scheme, "network" => network}
        end),
      "extensions" => [],
      "signers" => signers(engine)
    }
  end

  @doc false
  @spec validate_signer(term()) :: {:ok, Signer.t()} | {:error, String.t()}
  def validate_signer(%module{} = signer) do
    case X402.Behaviour.implements?(module, address: 1, sign_eip712: 3) do
      true -> {:ok, signer}
      false -> {:error, "expected a struct implementing X402.Signer"}
    end
  end

  def validate_signer(_other), do: {:error, "expected a struct implementing X402.Signer"}

  @doc false
  @spec validate_networks(term()) :: {:ok, [String.t()]} | {:error, String.t()}
  def validate_networks([_head | _tail] = networks) do
    case Enum.all?(networks, &evm_network?/1) do
      true -> {:ok, networks}
      false -> {:error, "expected a non-empty list of eip155:<chainId> CAIP-2 networks"}
    end
  end

  def validate_networks(_other),
    do: {:error, "expected a non-empty list of eip155:<chainId> CAIP-2 networks"}

  @doc false
  @spec validate_config(term()) :: {:ok, t()} | {:error, String.t()}
  def validate_config(%__MODULE__{} = engine), do: {:ok, engine}

  def validate_config(_other),
    do:
      {:error, "expected an %X402.Facilitator.Engine{} built with X402.Facilitator.Engine.new/1"}

  # -- Verify -----------------------------------------------------------------

  @typep protocol_result ::
           {:valid, wire_response(), EVM.signature_type()}
           | {:invalid, wire_response()}
           | {:error, term()}

  @spec verify_result(t(), map(), map(), EVM.simulate()) :: protocol_result()
  defp verify_result(engine, payload, requirements, simulate) do
    case route(engine, payload, requirements) do
      :ok ->
        delegate_verify(engine, payload, requirements, simulate)

      {:unsupported, reason_string} ->
        {:invalid, invalid_response(reason_string, payer(payload))}
    end
  end

  @spec delegate_verify(t(), map(), map(), EVM.simulate()) :: protocol_result()
  defp delegate_verify(engine, payload, requirements, simulate) do
    # The engine signs caller-supplied calldata only toward the factories
    # allowlisted here, capped by :max_deploy_gas_limit (see "Fee-payer
    # safety"); with the default [] no counterfactual payment verifies, so
    # settle never deploys anything.
    opts = [
      level: :full,
      rpc: engine.rpc,
      simulate: simulate,
      verify_chain_id: engine.verify_chain_id,
      eip6492_allowed_factories: engine.eip6492_allowed_factories
    ]

    case EVM.verify(payload, requirements, opts) do
      {:ok, %{payer: verified_payer, signature_type: signature_type}} ->
        {:valid, put_payer(%{"isValid" => true}, verified_payer), signature_type}

      {:error, {:invalid, reason}} ->
        {:invalid, invalid_response(EVM.reason_string(reason), payer(payload))}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec route(t(), map(), map()) :: :ok | {:unsupported, String.t()}
  defp route(engine, payload, requirements) do
    version = Utils.map_value(payload, {"x402Version", :x402Version})
    scheme = Utils.map_value(requirements, {"scheme", :scheme})
    network = Utils.map_value(requirements, {"network", :network})

    cond do
      version != @x402_version -> {:unsupported, "invalid_x402_version"}
      scheme != @scheme -> {:unsupported, "unsupported_scheme"}
      network not in engine.networks -> {:unsupported, "invalid_network"}
      true -> :ok
    end
  end

  @spec handle_verify_result(protocol_result(), t(), Context.t(), Hooks.metadata()) ::
          {:ok, wire_response()} | {:error, term()}
  defp handle_verify_result({:valid, response, _signature_type}, engine, context, metadata) do
    finalize_success(engine.hooks, :after_verify, context, response, metadata)
  end

  defp handle_verify_result({:invalid, response}, engine, context, metadata) do
    failure_context = %{context | result: nil, error: response["invalidReason"]}

    case run_failure_hook(engine.hooks, :on_verify_failure, failure_context, metadata) do
      {:recover, result} -> {:ok, result}
      {:cont, _next_context} -> {:ok, response}
      {:error, reason} -> {:error, reason}
    end
  end

  defp handle_verify_result({:error, reason}, engine, context, metadata) do
    recover_or_error(engine.hooks, :on_verify_failure, context, reason, metadata)
  end

  # -- Settle -----------------------------------------------------------------

  @typep settle_result :: {:settled, wire_response()} | {:error, term()}

  @typep settle_context :: %{
           network: String.t(),
           payer: String.t() | nil,
           pending_key: String.t() | nil,
           event: map(),
           entry: PendingSettlementStore.entry() | nil
         }

  @spec settle_result(t(), map(), map()) :: settle_result()
  defp settle_result(engine, payload, requirements) do
    ctx = settle_context(engine, payload, requirements)

    case route(engine, payload, requirements) do
      :ok ->
        case reconcile_pending(engine, ctx) do
          {:settled, _response} = reconciled ->
            reconciled

          :miss ->
            verify_and_settle(engine, payload, requirements, ctx)
        end

      {:unsupported, reason_string} ->
        {:settled, failure_response(reason_string, "", ctx.network, ctx.payer)}
    end
  end

  @spec verify_and_settle(t(), map(), map(), settle_context()) :: settle_result()
  defp verify_and_settle(engine, payload, requirements, ctx) do
    case delegate_verify(engine, payload, requirements, settle_simulate(engine)) do
      {:valid, _response, signature_type} ->
        execute_settlement(engine, payload, requirements, ctx, signature_type)

      {:invalid, response} ->
        {:settled, failure_response(response["invalidReason"], "", ctx.network, ctx.payer)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec settle_context(t(), map(), map()) :: settle_context()
  defp settle_context(engine, payload, requirements) do
    payer = payer(payload)
    authorization = authorization(payload)

    %{
      network: network(requirements, payload),
      payer: payer,
      pending_key: pending_key(engine, payload, requirements),
      # The expected Transfer event is built from the payload's signed
      # authorization — the fields the pending key's signature binds — never
      # from the caller-supplied requirements: the pending-store reconcile
      # path runs without re-verification, so requirements drift on a retry
      # must not turn a completed settlement into a terminal mismatch. Only
      # the log address stays the requirements' asset, matching the
      # reference facilitator's awaitEIP3009Settlement. (The fresh-broadcast
      # path re-verifies, proving authorization and requirements agree.)
      event: %{
        asset: asset(requirements),
        from: payer,
        to: Utils.map_value(authorization, {"to", :to}),
        value: Utils.map_value(authorization, {"value", :value})
      },
      entry: nil
    }
  end

  # Settle's independent re-verify keeps the atomic counterfactual
  # simulation even when :simulate_in_settle is off — it is the only
  # possible proof of a counterfactual signature, and verify must predict
  # settle.
  @spec settle_simulate(t()) :: EVM.simulate()
  defp settle_simulate(%{simulate_in_settle: true}), do: true
  defp settle_simulate(_engine), do: :counterfactual_only

  # verify/3 maps :simulate the same way settle's re-verify maps
  # :simulate_in_settle: with simulation off, counterfactual payments keep
  # the atomic Multicall3 deploy-and-transfer proof instead of being
  # rejected as undeployed — otherwise verify would reject payments settle
  # settles. EOA/ERC-1271 transfer simulation stays off.
  @spec verify_simulate(t()) :: EVM.simulate()
  defp verify_simulate(%{simulate: true}), do: true
  defp verify_simulate(_engine), do: :counterfactual_only

  # The reference SDKs key EVM pending entries by the EIP-3009 signature
  # alone. That is not enough here: the reconcile fast path runs WITHOUT
  # re-verification and checks the receipt's Transfer event against the
  # retry's authorization fields and the requirements' asset — so the key
  # must bind every one of those fields too. Otherwise anyone who saw the
  # PAYMENT-SIGNATURE header could replay the same signature with a mutated
  # authorization, hit the entry, burn it (delete-before-reconcile), and
  # turn a confirmed transfer into a terminal mismatch. With the full
  # binding, a mutated retry simply misses the store and falls through to
  # the normal path, where re-verification rejects it and the honest
  # retry's entry survives. Hashing keeps raw signature material out of
  # adapter keys; the inner signature digest is a fixed 32 bytes, so
  # variable-length signatures cannot alias the appended fields.
  @spec pending_key(t(), map(), map()) :: String.t() | nil
  defp pending_key(%{pending_settlement_store: nil}, _payload, _requirements), do: nil

  defp pending_key(_engine, payload, requirements) do
    signature =
      Utils.nested_map_value(payload, [{"payload", :payload}, {"signature", :signature}])

    authorization = authorization(payload)

    fields =
      [
        Utils.map_value(authorization, {"from", :from}),
        Utils.map_value(authorization, {"to", :to}),
        Utils.map_value(authorization, {"value", :value}),
        Utils.map_value(authorization, {"validAfter", :validAfter}),
        Utils.map_value(authorization, {"validBefore", :validBefore}),
        Utils.map_value(authorization, {"nonce", :nonce}),
        asset(requirements)
      ]
      |> Enum.map(&canonical_key_field/1)

    with {:ok, bytes} <- unhex(signature),
         false <- Enum.any?(fields, &is_nil/1) do
      digest =
        :crypto.hash(:sha256, [:crypto.hash(:sha256, bytes), "\n", Enum.intersperse(fields, "\n")])

      Base.encode16(digest, case: :lower)
    else
      _missing_or_malformed -> nil
    end
  end

  # Reconcile-relevant fields are hex or decimal strings on the wire;
  # integers (permissive JSON producers) canonicalize to their decimal
  # form, everything else makes the payment unkeyable (no store use — the
  # normal path's re-verification owns rejecting it).
  @spec canonical_key_field(term()) :: binary() | nil
  defp canonical_key_field(value) when is_binary(value), do: String.downcase(value)

  defp canonical_key_field(value) when is_integer(value) and value >= 0,
    do: Integer.to_string(value)

  defp canonical_key_field(_value), do: nil

  @spec reconcile_pending(t(), settle_context()) :: {:settled, wire_response()} | :miss
  defp reconcile_pending(%{pending_settlement_store: nil}, _ctx), do: :miss
  defp reconcile_pending(_engine, %{pending_key: nil}), do: :miss

  defp reconcile_pending(engine, ctx) do
    case PendingSettlementStore.get(engine.pending_settlement_store, ctx.pending_key) do
      {:hit, entry} ->
        # Delete before reconciling: a concurrent retry of the same payload
        # misses here and falls through to the normal path, where the chain
        # rejects the duplicate via the EIP-3009 authorization nonce.
        PendingSettlementStore.delete(engine.pending_settlement_store, ctx.pending_key)

        # :local_hash entries are re-awaited exactly like node-acknowledged
        # ones — never rebroadcast: rebroadcasting a transaction the node
        # may have accepted risks a duplicate-spend race. The stored raw
        # bytes exist for operator-driven inspection only.
        await_receipt(engine, entry.transaction, %{ctx | entry: entry})

      :miss ->
        :miss

      {:error, _reason} ->
        # A failing store must not block settlement; falling through to the
        # broadcast path is safe because the chain rejects a duplicate
        # authorization.
        :miss
    end
  end

  @spec execute_settlement(t(), map(), map(), settle_context(), EVM.signature_type()) ::
          settle_result()
  defp execute_settlement(engine, payload, requirements, ctx, signature_type) do
    # Fee-payer safety: `to` is the verified requirements' asset, `value` is
    # 0, and the calldata comes exclusively from the shared EIP-3009 builder
    # over the authorization the re-verify just proved. The one exception is
    # the allowlist-gated counterfactual deployment (deploy_wallet/4). The
    # overload follows the VERIFIED signature type (an ERC-1271 signature
    # can be 65 bytes too).
    with {:ok, parsed} <- parse_wrapper(payload),
         {:ok, from} <- Signer.address(engine.signer),
         {:ok, chain_id} <- chain_id(requirements),
         :ok <- ensure_wallet_deployed(engine, signature_type, parsed, ctx.payer, from, chain_id),
         {:ok, calldata} <- build_calldata(payload, parsed.inner_signature, signature_type),
         {:ok, params} <-
           transaction_params(
             engine,
             from,
             asset(requirements),
             calldata,
             transfer_limits(engine)
           ),
         {:ok, raw} <-
           sign_or_release(engine, chain_id, params, asset(requirements), calldata, from) do
      broadcast_and_await(engine, raw, from, params.nonce, ctx)
    else
      {:settle_failed, reason_string} ->
        {:settled, failure_response(reason_string, "", ctx.network, ctx.payer)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec transfer_limits(t()) :: {pos_integer(), String.t()}
  defp transfer_limits(engine),
    do: {engine.max_gas_limit, "invalid_exact_evm_transaction_simulation_failed"}

  @spec deploy_limits(t()) :: {pos_integer(), String.t()}
  defp deploy_limits(engine),
    do: {engine.max_deploy_gas_limit, "smart_wallet_deployment_failed"}

  # A wallet verified as counterfactual may have been deployed since — the
  # bytes-variant transfer calldata already carries the inner signature, so
  # a deployed wallet just skips the deployment transaction.
  @spec ensure_wallet_deployed(
          t(),
          EVM.signature_type(),
          ERC6492.parsed(),
          String.t() | nil,
          String.t(),
          non_neg_integer()
        ) :: :ok | {:settle_failed, String.t()} | {:error, term()}
  defp ensure_wallet_deployed(engine, :erc6492_counterfactual, parsed, payer, from, chain_id) do
    case rpc_request(engine.rpc, "eth_getCode", [payer, "latest"]) do
      {:ok, code} ->
        case deployed_code?(code) do
          true -> :ok
          false -> deploy_wallet(engine, parsed, from, chain_id)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp ensure_wallet_deployed(_engine, _signature_type, _parsed, _payer, _from, _chain_id),
    do: :ok

  # The only code path that signs caller-supplied calldata: `to` and `data`
  # come from the ERC-6492 wrapper, so the factory is re-checked against the
  # allowlist fail-closed (re-verify already enforced it) and the gas limit
  # is capped by :max_deploy_gas_limit. After a confirmed deployment the
  # transfer is NOT re-simulated: verify's atomic Multicall3 deploy+transfer
  # simulation was the authoritative pre-check, a standalone eth_call here
  # can race the deploy's state propagation across load-balanced RPC nodes
  # into false rejections, and the on-chain transferWithAuthorization is
  # itself the definitive signature check.
  @spec deploy_wallet(t(), ERC6492.parsed(), String.t(), non_neg_integer()) ::
          :ok | {:settle_failed, String.t()} | {:error, term()}
  defp deploy_wallet(engine, parsed, from, chain_id) do
    with :ok <- check_factory_allowlist(engine, parsed.factory),
         {:ok, params} <-
           transaction_params(
             engine,
             from,
             parsed.factory,
             parsed.factory_calldata,
             deploy_limits(engine)
           ),
         {:ok, raw} <-
           sign_or_release(
             engine,
             chain_id,
             params,
             parsed.factory,
             parsed.factory_calldata,
             from
           ) do
      broadcast_deploy(engine, raw, from, params.nonce)
    end
  end

  @spec check_factory_allowlist(t(), String.t() | nil) :: :ok | {:settle_failed, String.t()}
  defp check_factory_allowlist(engine, factory) when is_binary(factory) do
    allowed = Enum.map(engine.eip6492_allowed_factories, &String.downcase(String.trim(&1)))

    case String.downcase(factory) in allowed do
      true -> :ok
      false -> {:settle_failed, "eip6492_factory_not_allowed"}
    end
  end

  defp check_factory_allowlist(_engine, _factory),
    do: {:settle_failed, "eip6492_factory_not_allowed"}

  # The deployment consumes its own fee-payer nonce ahead of the transfer's.
  # Every deploy failure is terminal but safe: the EIP-3009 authorization
  # was not consumed, so the client may retry the identical payment.
  @spec broadcast_deploy(t(), binary(), String.t(), non_neg_integer()) ::
          :ok | {:settle_failed, String.t()} | {:error, term()}
  defp broadcast_deploy(engine, raw, from, nonce) do
    case RPC.request(engine.rpc, "eth_sendRawTransaction", [hex(raw)]) do
      {:ok, transaction_hash} when is_binary(transaction_hash) ->
        complete_nonce(engine, from, nonce)
        await_deploy_receipt(engine, transaction_hash)

      {:ok, other} ->
        complete_nonce(engine, from, nonce)
        {:error, {:rpc_error, {:invalid_response, other}}}

      {:error, {:jsonrpc_error, _error}} ->
        release_nonce(engine, from, nonce)
        {:settle_failed, "smart_wallet_deployment_failed"}

      {:error, _reason} ->
        # Ambiguous transport failure: the node may have accepted the
        # deploy, so the nonce counts as consumed.
        complete_nonce(engine, from, nonce)
        {:settle_failed, "smart_wallet_deployment_failed"}
    end
  end

  @spec await_deploy_receipt(t(), String.t()) :: :ok | {:settle_failed, String.t()}
  defp await_deploy_receipt(engine, transaction_hash) do
    deadline = System.monotonic_time(:millisecond) + engine.receipt_timeout_ms
    poll_deploy_receipt(engine, transaction_hash, deadline)
  end

  @spec poll_deploy_receipt(t(), String.t(), integer()) :: :ok | {:settle_failed, String.t()}
  defp poll_deploy_receipt(engine, transaction_hash, deadline) do
    case RPC.request(engine.rpc, "eth_getTransactionReceipt", [transaction_hash]) do
      {:ok, %{"status" => "0x1"}} ->
        :ok

      {:ok, %{"status" => "0x0"}} ->
        {:settle_failed, "smart_wallet_deployment_failed"}

      _pending_or_error ->
        case System.monotonic_time(:millisecond) + engine.receipt_interval_ms <= deadline do
          true ->
            Process.sleep(engine.receipt_interval_ms)
            poll_deploy_receipt(engine, transaction_hash, deadline)

          false ->
            {:settle_failed, "smart_wallet_deployment_failed"}
        end
    end
  end

  # Once a nonce is checked out, every failure before the node could have
  # seen the transaction must return it — otherwise a gap forms and later
  # settlements stall pending at the node.
  @spec sign_or_release(t(), non_neg_integer(), map(), String.t(), binary(), String.t()) ::
          {:ok, binary()} | {:settle_failed, String.t()} | {:error, term()}
  defp sign_or_release(engine, chain_id, params, to, calldata, from) do
    case sign_transaction(engine, chain_id, params, to, calldata) do
      {:ok, raw} ->
        {:ok, raw}

      failure ->
        release_nonce(engine, from, params.nonce)
        failure
    end
  end

  @spec parse_wrapper(map()) :: {:ok, ERC6492.parsed()} | {:error, term()}
  defp parse_wrapper(payload) do
    signature =
      Utils.nested_map_value(payload, [{"payload", :payload}, {"signature", :signature}])

    # Re-verify already proved the signature parses; the wrapper is retained
    # for counterfactual deployment, while the token contract always
    # receives the inner signature.
    case ERC6492.parse(signature || "") do
      {:ok, parsed} -> {:ok, parsed}
      {:error, reason} -> {:error, {:settle_error, reason}}
    end
  end

  @spec build_calldata(map(), binary(), EVM.signature_type()) ::
          {:ok, binary()} | {:error, term()}
  defp build_calldata(payload, inner_signature, signature_type) do
    authorization =
      Utils.nested_map_value(payload, [{"payload", :payload}, {"authorization", :authorization}])

    case EIP3009.transfer_calldata(authorization || %{}, inner_signature, signature_type) do
      {:ok, calldata} -> {:ok, calldata}
      {:error, reason} -> {:error, {:settle_error, reason}}
    end
  end

  @spec chain_id(map()) :: {:ok, non_neg_integer()} | {:error, term()}
  defp chain_id(requirements) do
    case EIP712.chain_id_from_caip2(Utils.map_value(requirements, {"network", :network})) do
      {:ok, chain_id} -> {:ok, chain_id}
      {:error, reason} -> {:error, {:settle_error, reason}}
    end
  end

  # One batched round-trip: gas estimate, EIP-1559 fee data, pending nonce.
  # `limits` carries the gas ceiling and the estimate-revert reason for the
  # transaction kind being built (transfer vs. factory deployment).
  @spec transaction_params(t(), String.t(), String.t(), binary(), {pos_integer(), String.t()}) ::
          {:ok, map()} | {:settle_failed, String.t()} | {:error, term()}
  defp transaction_params(%{nonce_manager: nil} = engine, from, to, calldata, limits) do
    requests = [
      {"eth_estimateGas", [%{"from" => from, "to" => to, "data" => hex(calldata)}]},
      {"eth_maxPriorityFeePerGas", []},
      {"eth_feeHistory", ["0x1", "latest", []]},
      {"eth_getTransactionCount", [from, "pending"]}
    ]

    case RPC.batch(engine.rpc, requests) do
      {:ok, [estimate, priority, fee_history, nonce]} ->
        assemble_params(engine, estimate, priority, fee_history, nonce, limits)

      {:error, reason} ->
        {:error, {:rpc_error, reason}}
    end
  end

  # With a nonce manager, the nonce is assigned by the manager (fetched from
  # the node only on first use or after a drain-triggered re-fetch), so
  # concurrent settlements get distinct consecutive nonces instead of racing
  # on `pending`. The checkout happens LAST: a fee/gas failure before it
  # needs no release, and an assembly failure after it releases the nonce.
  defp transaction_params(engine, from, to, calldata, limits) do
    requests = [
      {"eth_estimateGas", [%{"from" => from, "to" => to, "data" => hex(calldata)}]},
      {"eth_maxPriorityFeePerGas", []},
      {"eth_feeHistory", ["0x1", "latest", []]}
    ]

    with {:ok, [estimate, priority, fee_history]} <- rpc_batch(engine, requests),
         {:ok, nonce} <- checkout_nonce(engine, from) do
      case assemble_params(
             engine,
             estimate,
             priority,
             fee_history,
             {:ok, integer_hex(nonce)},
             limits
           ) do
        {:ok, params} ->
          {:ok, params}

        failure ->
          release_nonce(engine, from, nonce)
          failure
      end
    end
  end

  # params.nonce is already the integer parsed by assemble_params.
  @spec release_nonce(t(), String.t(), non_neg_integer()) :: :ok
  defp release_nonce(%{nonce_manager: nil}, _from, _nonce), do: :ok

  defp release_nonce(engine, from, nonce),
    do: NonceManager.release(engine.nonce_manager, from, nonce)

  @spec complete_nonce(t(), String.t(), non_neg_integer()) :: :ok
  defp complete_nonce(%{nonce_manager: nil}, _from, _nonce), do: :ok

  defp complete_nonce(engine, from, nonce),
    do: NonceManager.complete(engine.nonce_manager, from, nonce)

  @spec parse_fetched_nonce(String.t()) ::
          {:ok, non_neg_integer()} | {:error, {:invalid_nonce, String.t()}}
  defp parse_fetched_nonce(hex_nonce) do
    case Integer.parse(hex_nonce, 16) do
      {nonce, ""} -> {:ok, nonce}
      _other -> {:error, {:invalid_nonce, "0x" <> hex_nonce}}
    end
  end

  @spec rpc_batch(t(), [{String.t(), list()}]) ::
          {:ok, [RPC.batch_result()]} | {:error, term()}
  defp rpc_batch(engine, requests) do
    case RPC.batch(engine.rpc, requests) do
      {:ok, results} -> {:ok, results}
      {:error, reason} -> {:error, {:rpc_error, reason}}
    end
  end

  @spec checkout_nonce(t(), String.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  defp checkout_nonce(engine, from) do
    fetch = fn ->
      case RPC.request(engine.rpc, "eth_getTransactionCount", [from, "pending"]) do
        {:ok, "0x" <> hex_nonce} -> parse_fetched_nonce(hex_nonce)
        {:ok, other} -> {:error, {:invalid_nonce, other}}
        {:error, reason} -> {:error, reason}
      end
    end

    case NonceManager.checkout(engine.nonce_manager, from, fetch) do
      {:ok, nonce} -> {:ok, nonce}
      {:error, reason} -> {:error, {:rpc_error, reason}}
    end
  end

  @spec integer_hex(non_neg_integer()) :: String.t()
  defp integer_hex(value), do: "0x" <> Integer.to_string(value, 16)

  @spec assemble_params(
          t(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result(),
          {pos_integer(), String.t()}
        ) :: {:ok, map()} | {:settle_failed, String.t()} | {:error, term()}
  defp assemble_params(engine, estimate, priority, fee_history, nonce, limits) do
    with {:ok, gas_limit} <- gas_limit(engine, estimate, limits),
         {:ok, nonce} <- expect_quantity(nonce),
         {:ok, {max_priority, max_fee}} <- fee_fields(engine.rpc, priority, fee_history) do
      {:ok,
       %{
         gas_limit: gas_limit,
         nonce: nonce,
         max_priority_fee_per_gas: max_priority,
         max_fee_per_gas: max_fee
       }}
    end
  end

  # An eth_estimateGas revert means the call would fail on chain — a
  # protocol-level rejection (it is itself a simulation), not an
  # infrastructure error.
  @spec gas_limit(t(), RPC.batch_result(), {pos_integer(), String.t()}) ::
          {:ok, pos_integer()} | {:settle_failed, String.t()} | {:error, term()}
  defp gas_limit(engine, {:ok, hex}, {gas_ceiling, _revert_reason}) do
    case parse_quantity(hex) do
      {:ok, estimate} ->
        margined = div(estimate * (100 + engine.gas_limit_margin_percent), 100)

        # Absolute ceiling per transaction kind: an estimate beyond what a
        # legitimate transfer (or factory deployment) can cost means the
        # contract is burning the fee payer's gas — refuse to settle.
        case margined <= gas_ceiling do
          true -> {:ok, margined}
          false -> {:settle_failed, "settle_gas_limit_exceeded"}
        end

      :error ->
        {:error, {:rpc_error, {:invalid_response, hex}}}
    end
  end

  defp gas_limit(_engine, {:error, {:jsonrpc_error, error}}, {_gas_ceiling, revert_reason}),
    do: {:settle_failed, estimate_revert_reason(error, revert_reason)}

  # The transfer's estimateGas revert carries the token's revert text —
  # classify it onto the canonical wire reasons (matching the reference
  # facilitator's parseEip3009TransferError) so a retry of an
  # already-confirmed authorization reports nonce_already_used instead of a
  # generic simulation failure. Unclassifiable reverts keep the fixed
  # reason, and the factory-deployment path always keeps its own.
  @spec estimate_revert_reason(RPC.jsonrpc_error(), String.t()) :: String.t()
  defp estimate_revert_reason(error, "invalid_exact_evm_transaction_simulation_failed" = fixed) do
    case EVM.classify_revert(error) do
      nil -> fixed
      reason -> EVM.reason_string(reason)
    end
  end

  defp estimate_revert_reason(_error, fixed_reason), do: fixed_reason

  # EIP-1559 fee data: next base fee from eth_feeHistory plus the node's
  # suggested priority fee; maxFeePerGas = 2 * baseFee + priority. Nodes
  # without the EIP-1559 fee APIs fall back to eth_gasPrice.
  @spec fee_fields(RPC.t(), RPC.batch_result(), RPC.batch_result()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}} | {:error, term()}
  defp fee_fields(rpc, {:ok, priority_hex}, {:ok, fee_history}) do
    with {:ok, priority} <- parse_quantity(priority_hex),
         {:ok, base_fee} <- next_base_fee(fee_history) do
      {:ok, {priority, base_fee * 2 + priority}}
    else
      :error -> gas_price_fallback(rpc)
    end
  end

  defp fee_fields(rpc, _priority, _fee_history), do: gas_price_fallback(rpc)

  @spec next_base_fee(term()) :: {:ok, non_neg_integer()} | :error
  defp next_base_fee(%{"baseFeePerGas" => [_head | _tail] = base_fees}),
    do: parse_quantity(List.last(base_fees))

  defp next_base_fee(_fee_history), do: :error

  @spec gas_price_fallback(RPC.t()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}} | {:error, term()}
  defp gas_price_fallback(rpc) do
    with {:ok, hex} <- rpc_request(rpc, "eth_gasPrice", []),
         {:ok, gas_price} <- expect_quantity({:ok, hex}) do
      {:ok, {gas_price, gas_price * 2}}
    end
  end

  @spec sign_transaction(t(), non_neg_integer(), map(), String.t(), binary()) ::
          {:ok, binary()} | {:error, term()}
  defp sign_transaction(engine, chain_id, params, asset, calldata) do
    transaction = %Transaction{
      chain_id: chain_id,
      nonce: params.nonce,
      max_priority_fee_per_gas: params.max_priority_fee_per_gas,
      max_fee_per_gas: params.max_fee_per_gas,
      gas_limit: params.gas_limit,
      to: asset,
      value: 0,
      data: calldata
    }

    with {:ok, digest} <- Transaction.digest(transaction),
         {:ok, signature} <- Signer.sign_eip712(engine.signer, digest, %{}),
         {:ok, raw} <- Transaction.encode_signed(transaction, signature) do
      {:ok, raw}
    else
      {:error, reason} -> {:error, {:settle_error, reason}}
    end
  end

  @spec broadcast_and_await(t(), binary(), String.t(), non_neg_integer(), settle_context()) ::
          settle_result()
  defp broadcast_and_await(engine, raw, from, nonce, ctx) do
    case RPC.request(engine.rpc, "eth_sendRawTransaction", [hex(raw)]) do
      {:ok, transaction_hash} when is_binary(transaction_hash) ->
        complete_nonce(engine, from, nonce)
        await_receipt(engine, transaction_hash, ctx)

      {:ok, other} ->
        complete_nonce(engine, from, nonce)
        {:error, {:rpc_error, {:invalid_response, other}}}

      {:error, {:jsonrpc_error, _error}} ->
        # The node rejected the transaction without seeing it land — return
        # the nonce (tail rollback, or a drain-triggered re-fetch when later
        # settlements are still in flight).
        release_nonce(engine, from, nonce)
        {:settled, failure_response("unexpected_settle_error", "", ctx.network, ctx.payer)}

      {:error, reason} ->
        # A transport failure mid-broadcast is ambiguous — the node may have
        # accepted the transaction, so the nonce counts as consumed (never
        # left in flight, or a later release could never drain to re-fetch).
        # Return the spec's non-terminal settlement_pending with the locally
        # computed hash so the caller can reconcile on chain.
        complete_nonce(engine, from, nonce)
        pending_after_transport_failure(engine, raw, ctx, reason)
    end
  end

  @spec pending_after_transport_failure(t(), binary(), settle_context(), term()) ::
          settle_result()
  defp pending_after_transport_failure(engine, raw, ctx, reason) do
    case EIP712.keccak_module() do
      {:ok, keccak_module} ->
        transaction_hash = hex(keccak_module.hash_256(raw))

        # The node may never have seen this transaction — keep the raw
        # signed bytes with the :local_hash entry so operators can inspect
        # or manually rebroadcast; the engine itself never rebroadcasts.
        entry = %{transaction: transaction_hash, provenance: :local_hash, raw_transaction: raw}
        settlement_pending(engine, ctx, transaction_hash, entry)

      {:error, :missing_dependency} ->
        {:error, {:rpc_error, reason}}
    end
  end

  @spec await_receipt(t(), String.t(), settle_context()) :: settle_result()
  defp await_receipt(engine, transaction_hash, ctx) do
    deadline = System.monotonic_time(:millisecond) + engine.receipt_timeout_ms
    poll_receipt(engine, transaction_hash, ctx, deadline)
  end

  @spec poll_receipt(t(), String.t(), settle_context(), integer()) :: settle_result()
  defp poll_receipt(engine, transaction_hash, ctx, deadline) do
    case RPC.request(engine.rpc, "eth_getTransactionReceipt", [transaction_hash]) do
      {:ok, %{"status" => "0x1"} = receipt} ->
        confirm_transfer(engine, transaction_hash, receipt, ctx)

      {:ok, %{"status" => "0x0"}} ->
        {:settled,
         failure_response(
           "invalid_exact_evm_transaction_failed",
           transaction_hash,
           ctx.network,
           ctx.payer
         )}

      # Pending (null receipt), unexpected shapes, and transient RPC errors
      # all keep polling until the deadline; the transaction is broadcast, so
      # the only safe terminal answer without a receipt is settlement_pending.
      _pending_or_error ->
        retry_or_pending(engine, transaction_hash, ctx, deadline)
    end
  end

  # A confirmed receipt only proves the transaction did not revert; the
  # matching ERC-20 Transfer event is what proves the payment moved.
  @spec confirm_transfer(t(), String.t(), map(), settle_context()) :: settle_result()
  defp confirm_transfer(engine, transaction_hash, receipt, ctx) do
    case check_transfer_event(receipt, ctx.event) do
      :ok ->
        {:settled, success_response(transaction_hash, ctx.network, ctx.payer)}

      :mismatch ->
        {:settled,
         failure_response(
           "invalid_exact_evm_transfer_event_mismatch",
           transaction_hash,
           ctx.network,
           ctx.payer
         )}

      :unparseable ->
        # Logs the engine cannot read leave the transfer unestablished — a
        # non-terminal outcome, unlike a parsed-but-mismatched event.
        settlement_pending(engine, ctx, transaction_hash, pending_entry(ctx, transaction_hash))
    end
  end

  @spec retry_or_pending(t(), String.t(), settle_context(), integer()) :: settle_result()
  defp retry_or_pending(engine, transaction_hash, ctx, deadline) do
    case System.monotonic_time(:millisecond) + engine.receipt_interval_ms <= deadline do
      true ->
        Process.sleep(engine.receipt_interval_ms)
        poll_receipt(engine, transaction_hash, ctx, deadline)

      false ->
        settlement_pending(engine, ctx, transaction_hash, pending_entry(ctx, transaction_hash))
    end
  end

  # Reconciled entries are re-recorded as-is (keeping :local_hash provenance
  # and raw bytes); fresh timeouts record the node-acknowledged hash.
  @spec pending_entry(settle_context(), String.t()) :: PendingSettlementStore.entry()
  defp pending_entry(%{entry: %{} = entry}, _transaction_hash), do: entry

  defp pending_entry(_ctx, transaction_hash),
    do: %{transaction: transaction_hash, provenance: :node_acknowledged, raw_transaction: nil}

  @spec settlement_pending(t(), settle_context(), String.t(), PendingSettlementStore.entry()) ::
          settle_result()
  defp settlement_pending(engine, ctx, transaction_hash, entry) do
    case record_pending(engine, ctx.pending_key, entry) do
      :ok ->
        {:settled,
         failure_response("settlement_pending", transaction_hash, ctx.network, ctx.payer)}

      {:error, reason} ->
        # A pending answer that was not persisted cannot be made good on —
        # the retry would miss the store and double-broadcast. Downgrade to
        # a terminal failure, keeping the hash for manual reconciliation.
        Logger.warning(
          "x402 facilitator settlement_pending, but failed to persist for retry: " <>
            inspect(reason)
        )

        {:settled,
         failure_response(
           "invalid_exact_evm_transaction_failed",
           transaction_hash,
           ctx.network,
           ctx.payer
         )}
    end
  end

  @spec record_pending(t(), String.t() | nil, PendingSettlementStore.entry()) ::
          :ok | {:error, term()}
  defp record_pending(%{pending_settlement_store: nil}, _key, _entry), do: :ok
  defp record_pending(_engine, nil, _entry), do: :ok

  defp record_pending(engine, key, entry),
    do: PendingSettlementStore.put(engine.pending_settlement_store, key, entry)

  # -- Transfer-event verification ---------------------------------------------

  # Wire shapes come straight from the node: a parseable log list with no
  # matching Transfer entry is a terminal mismatch, while logs the engine
  # cannot read structurally make no verdict possible.
  @spec check_transfer_event(map(), map()) :: :ok | :mismatch | :unparseable
  defp check_transfer_event(receipt, event) do
    with {:ok, logs} <- receipt_logs(receipt),
         {:ok, expected} <- expected_transfer_log(event),
         {:ok, normalized} <- normalize_logs(logs, []) do
      case expected in normalized do
        true -> :ok
        false -> :mismatch
      end
    else
      :unparseable -> :unparseable
    end
  end

  @spec receipt_logs(map()) :: {:ok, [term()]} | :unparseable
  defp receipt_logs(%{"logs" => logs}) when is_list(logs), do: {:ok, logs}
  defp receipt_logs(_receipt), do: :unparseable

  @spec normalize_logs([term()], [map()]) :: {:ok, [map()]} | :unparseable
  defp normalize_logs([], acc), do: {:ok, acc}

  defp normalize_logs([%{"address" => address, "topics" => topics, "data" => data} | rest], acc)
       when is_binary(address) and is_list(topics) and is_binary(data) do
    case Enum.all?(topics, &is_binary/1) do
      true ->
        normalized = %{
          address: String.downcase(address),
          topics: Enum.map(topics, &String.downcase/1),
          data: String.downcase(data)
        }

        normalize_logs(rest, [normalized | acc])

      false ->
        :unparseable
    end
  end

  defp normalize_logs(_malformed, _acc), do: :unparseable

  @spec expected_transfer_log(map()) :: {:ok, map()} | :unparseable
  defp expected_transfer_log(%{asset: asset} = event) when is_binary(asset) do
    with {:ok, from_topic} <- address_topic(event.from),
         {:ok, to_topic} <- address_topic(event.to),
         {:ok, value} <- parse_amount(event.value) do
      {:ok,
       %{
         address: String.downcase(asset),
         topics: [@transfer_event_topic, from_topic, to_topic],
         data: "0x" <> Base.encode16(<<value::unsigned-big-integer-size(256)>>, case: :lower)
       }}
    else
      :error -> :unparseable
    end
  end

  defp expected_transfer_log(_event), do: :unparseable

  @spec address_topic(term()) :: {:ok, String.t()} | :error
  defp address_topic("0x" <> hex_address) when byte_size(hex_address) == 40 do
    case Base.decode16(hex_address, case: :mixed) do
      {:ok, _bytes} -> {:ok, "0x" <> String.duplicate("0", 24) <> String.downcase(hex_address)}
      :error -> :error
    end
  end

  defp address_topic(_address), do: :error

  @spec parse_amount(term()) :: {:ok, non_neg_integer()} | :error
  defp parse_amount(value) when is_integer(value) and value >= 0 and value <= @max_uint256,
    do: {:ok, value}

  defp parse_amount(value) when is_binary(value) do
    case Integer.parse(value) do
      {amount, ""} when amount >= 0 and amount <= @max_uint256 -> {:ok, amount}
      _other -> :error
    end
  end

  defp parse_amount(_value), do: :error

  @spec handle_settle_result(settle_result(), t(), Context.t(), Hooks.metadata()) ::
          {:ok, wire_response()} | {:error, term()}
  defp handle_settle_result(
         {:settled, %{"success" => true} = response},
         engine,
         context,
         metadata
       ) do
    finalize_success(engine.hooks, :after_settle, context, response, metadata)
  end

  defp handle_settle_result({:settled, response}, engine, context, metadata) do
    failure_context = %{context | result: nil, error: response["errorReason"]}

    case run_failure_hook(engine.hooks, :on_settle_failure, failure_context, metadata) do
      {:recover, result} -> {:ok, result}
      {:cont, _next_context} -> {:ok, response}
      {:error, reason} -> {:error, reason}
    end
  end

  defp handle_settle_result({:error, reason}, engine, context, metadata) do
    recover_or_error(engine.hooks, :on_settle_failure, context, reason, metadata)
  end

  # -- Hook plumbing ----------------------------------------------------------

  @spec hook_metadata(:verify | :settle, t()) :: Hooks.metadata()
  defp hook_metadata(operation, engine) do
    %{
      operation: operation,
      endpoint: "/" <> Atom.to_string(operation),
      hook_module: engine.hooks
    }
  end

  @spec run_before_hook(module(), Hooks.callback_name(), Context.t(), Hooks.metadata()) ::
          {:cont, Context.t()} | {:halt, term()} | {:error, term()}
  defp run_before_hook(hooks_module, callback, context, metadata) do
    case invoke_hook(hooks_module, callback, context, metadata) do
      {:ok, {:cont, %Context{} = next_context}} -> {:cont, next_context}
      {:ok, {:halt, reason}} -> {:halt, reason}
      {:ok, invalid_return} -> {:error, {:hook_invalid_return, callback, invalid_return}}
      {:error, reason} -> {:error, {:hook_callback_failed, callback, reason}}
    end
  end

  @spec finalize_success(module(), Hooks.callback_name(), Context.t(), map(), Hooks.metadata()) ::
          {:ok, wire_response()} | {:error, term()}
  defp finalize_success(hooks_module, callback, context, response, metadata) do
    success_context = %{context | result: response, error: nil}

    case invoke_hook(hooks_module, callback, success_context, metadata) do
      {:ok, {:cont, %Context{result: result}}} when is_map(result) -> {:ok, result}
      {:ok, {:cont, %Context{result: nil}}} -> {:ok, response}
      {:ok, invalid_return} -> {:error, {:hook_invalid_return, callback, invalid_return}}
      {:error, reason} -> {:error, {:hook_callback_failed, callback, reason}}
    end
  end

  @spec run_failure_hook(module(), Hooks.callback_name(), Context.t(), Hooks.metadata()) ::
          {:cont, Context.t()} | {:recover, map()} | {:error, term()}
  defp run_failure_hook(hooks_module, callback, context, metadata) do
    case invoke_hook(hooks_module, callback, context, metadata) do
      {:ok, {:cont, %Context{} = next_context}} -> {:cont, next_context}
      {:ok, {:recover, result}} when is_map(result) -> {:recover, result}
      {:ok, invalid_return} -> {:error, {:hook_invalid_return, callback, invalid_return}}
      {:error, reason} -> {:error, {:hook_callback_failed, callback, reason}}
    end
  end

  @spec recover_or_error(module(), Hooks.callback_name(), Context.t(), term(), Hooks.metadata()) ::
          {:ok, wire_response()} | {:error, term()}
  defp recover_or_error(hooks_module, callback, context, reason, metadata) do
    failure_context = %{context | result: nil, error: reason}

    case run_failure_hook(hooks_module, callback, failure_context, metadata) do
      {:recover, result} -> {:ok, result}
      {:cont, next_context} -> {:error, next_context.error || reason}
      {:error, hook_error} -> {:error, hook_error}
    end
  end

  @spec invoke_hook(module(), Hooks.callback_name(), Context.t(), Hooks.metadata()) ::
          {:ok, term()} | {:error, term()}
  defp invoke_hook(hooks_module, callback, context, metadata) do
    {:ok, apply(hooks_module, callback, [context, metadata])}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  # -- Wire responses ---------------------------------------------------------

  @spec invalid_response(String.t(), String.t() | nil) :: wire_response()
  defp invalid_response(reason_string, payer) do
    put_payer(%{"isValid" => false, "invalidReason" => reason_string}, payer)
  end

  @spec success_response(String.t(), String.t(), String.t() | nil) :: wire_response()
  defp success_response(transaction_hash, network, payer) do
    put_payer(
      %{"success" => true, "transaction" => transaction_hash, "network" => network},
      payer
    )
  end

  @spec failure_response(String.t(), String.t(), String.t(), String.t() | nil) :: wire_response()
  defp failure_response(reason_string, transaction_hash, network, payer) do
    put_payer(
      %{
        "success" => false,
        "errorReason" => reason_string,
        "transaction" => transaction_hash,
        "network" => network
      },
      payer
    )
  end

  @spec put_payer(map(), term()) :: wire_response()
  defp put_payer(response, payer) when is_binary(payer), do: Map.put(response, "payer", payer)
  defp put_payer(response, _payer), do: response

  # -- Helpers ----------------------------------------------------------------

  @spec signers(t()) :: %{optional(String.t()) => [String.t()]}
  defp signers(engine) do
    case Signer.address(engine.signer) do
      {:ok, address} -> %{"eip155:*" => [address]}
      {:error, _reason} -> %{}
    end
  end

  @spec payer(map()) :: String.t() | nil
  defp payer(payload) do
    Utils.nested_map_value(payload, [
      {"payload", :payload},
      {"authorization", :authorization},
      {"from", :from}
    ])
  end

  @spec authorization(map()) :: map()
  defp authorization(payload) do
    case Utils.nested_map_value(payload, [
           {"payload", :payload},
           {"authorization", :authorization}
         ]) do
      %{} = authorization -> authorization
      _missing -> %{}
    end
  end

  @spec network(map(), map()) :: String.t()
  defp network(requirements, payload) do
    Utils.map_value(requirements, {"network", :network}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"network", :network}]) || ""
  end

  # Nil when the requirements are missing the field — re-verify rejects such
  # requirements before any code that needs a real address runs, but the
  # pending-store fast path builds its event context before re-verify.
  @spec asset(map()) :: String.t() | nil
  defp asset(requirements), do: Utils.map_value(requirements, {"asset", :asset})

  @spec evm_network?(term()) :: boolean()
  defp evm_network?(network),
    do: is_binary(network) and match?({:ok, _id}, EIP712.chain_id_from_caip2(network))

  @spec rpc_request(RPC.t(), String.t(), list()) :: {:ok, term()} | {:error, term()}
  defp rpc_request(rpc, method, params) do
    case RPC.request(rpc, method, params) do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, {:rpc_error, reason}}
    end
  end

  @spec expect_quantity(RPC.batch_result() | {:ok, term()}) ::
          {:ok, non_neg_integer()} | {:error, term()}
  defp expect_quantity({:ok, hex}) do
    case parse_quantity(hex) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:rpc_error, {:invalid_response, hex}}}
    end
  end

  defp expect_quantity({:error, reason}), do: {:error, {:rpc_error, reason}}

  @spec parse_quantity(term()) :: {:ok, non_neg_integer()} | :error
  defp parse_quantity("0x" <> hex_digits) when hex_digits != "" do
    case Integer.parse(hex_digits, 16) do
      {value, ""} -> {:ok, value}
      _parsed -> :error
    end
  end

  defp parse_quantity(_value), do: :error

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)

  @spec unhex(term()) :: {:ok, binary()} | :error
  defp unhex("0x" <> hex_digits), do: Base.decode16(hex_digits, case: :mixed)
  defp unhex(_value), do: :error

  @spec deployed_code?(term()) :: boolean()
  defp deployed_code?(code) when is_binary(code) do
    case unhex(code) do
      {:ok, bytes} -> byte_size(bytes) > 0
      :error -> false
    end
  end

  defp deployed_code?(_code), do: false

  @spec stringify_reason(term()) :: String.t()
  defp stringify_reason(reason) when is_binary(reason), do: reason
  defp stringify_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp stringify_reason(reason), do: inspect(reason)

  @spec emit_telemetry(:verify | :settle, {:ok, wire_response()} | {:error, term()}) :: :ok
  defp emit_telemetry(:verify, {:ok, response}) do
    Telemetry.emit(:facilitator_engine, :verify, :ok, %{valid: response["isValid"] == true})
  end

  defp emit_telemetry(:settle, {:ok, response}) do
    metadata = %{success: response["success"] == true, reason: response["errorReason"]}
    Telemetry.emit(:facilitator_engine, :settle, :ok, metadata)
  end

  defp emit_telemetry(operation, {:error, reason}) do
    Telemetry.emit(:facilitator_engine, operation, :error, %{reason: reason})
  end
end
