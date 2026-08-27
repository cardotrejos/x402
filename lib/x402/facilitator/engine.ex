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
  authorization fields the signature verification just proved — the engine
  has no code path that signs caller-supplied calldata. Consequently
  ERC-6492 *counterfactual* payments (which would require broadcasting
  arbitrary factory calldata to deploy the wallet) are rejected fail-closed
  at verify **and** at settle's re-verify; deployed ERC-1271 smart wallets
  are fully supported.

  ## Settlement pipeline

  1. Re-verify via `X402.Verify.EVM` at `:full` level (simulation off by
     default — verify already simulated; see `:simulate_in_settle`).
  2. Build `transferWithAuthorization` calldata (shared with verification's
     simulation encoding).
  3. One batched RPC round-trip: `eth_estimateGas` (with a safety margin),
     `eth_maxPriorityFeePerGas` + `eth_feeHistory` (falling back to
     `eth_gasPrice` on nodes without EIP-1559 fee APIs), and
     `eth_getTransactionCount` (`pending`).
  4. Encode the EIP-1559 transaction (`X402.Transaction`), sign its keccak
     digest through the configured `X402.Signer` (the signer must support
     raw digest signing — `X402.Signer.LocalKey` does; the 27/28 recovery id
     it returns is normalized to the EIP-1559 `yParity`), and broadcast via
     `eth_sendRawTransaction`.
  5. Poll `eth_getTransactionReceipt` until confirmation or timeout. A
     broadcast whose confirmation cannot be established returns the spec's
     non-terminal `"settlement_pending"` with the transaction hash so
     callers can reconcile on chain.

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

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.ERC6492
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
    receipt_interval_ms: 1_000
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
          receipt_interval_ms: pos_integer()
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
      doc: "Whether `verify/3` simulates `transferWithAuthorization` via `eth_call`."
    ],
    simulate_in_settle: [
      type: :boolean,
      default: false,
      doc: """
      Whether the independent re-verify inside `settle/3` also simulates.
      Off by default, matching the reference facilitators — verify already
      simulated, and `eth_estimateGas` re-simulates right before broadcast.
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
          |> verify_result(before_context.payload, before_context.requirements, engine.simulate)
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

  @spec verify_result(t(), map(), map(), boolean()) :: protocol_result()
  defp verify_result(engine, payload, requirements, simulate) do
    case route(engine, payload, requirements) do
      :ok ->
        delegate_verify(engine, payload, requirements, simulate)

      {:unsupported, reason_string} ->
        {:invalid, invalid_response(reason_string, payer(payload))}
    end
  end

  @spec delegate_verify(t(), map(), map(), boolean()) :: protocol_result()
  defp delegate_verify(engine, payload, requirements, simulate) do
    # eip6492_allowed_factories stays [] by design: settling a counterfactual
    # wallet would require signing arbitrary factory calldata, which the
    # fee-payer-safety invariant forbids — so verify must reject what settle
    # cannot broadcast.
    opts = [
      level: :full,
      rpc: engine.rpc,
      simulate: simulate,
      verify_chain_id: engine.verify_chain_id,
      eip6492_allowed_factories: []
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

  @spec settle_result(t(), map(), map()) :: settle_result()
  defp settle_result(engine, payload, requirements) do
    network = network(requirements, payload)
    payer = payer(payload)

    case verify_result(engine, payload, requirements, engine.simulate_in_settle) do
      {:valid, _response, signature_type} ->
        execute_settlement(engine, payload, requirements, network, payer, signature_type)

      {:invalid, response} ->
        {:settled, failure_response(response["invalidReason"], "", network, payer)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec execute_settlement(t(), map(), map(), String.t(), String.t() | nil, EVM.signature_type()) ::
          settle_result()
  defp execute_settlement(engine, payload, requirements, network, payer, signature_type) do
    # Fee-payer safety: `to` is the verified requirements' asset, `value` is
    # 0, and the calldata comes exclusively from the shared EIP-3009 builder
    # over the authorization the re-verify just proved — the engine never
    # signs caller-supplied calldata. The overload follows the VERIFIED
    # signature type (an ERC-1271 signature can be 65 bytes too).
    with {:ok, inner_signature} <- inner_signature(payload),
         {:ok, calldata} <- build_calldata(payload, inner_signature, signature_type),
         {:ok, from} <- Signer.address(engine.signer),
         {:ok, chain_id} <- chain_id(requirements) do
      asset = asset(requirements)
      outcome = sign_and_broadcast(engine, from, chain_id, asset, calldata)
      handle_broadcast(engine, outcome, network, payer)
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @typep broadcast_outcome ::
           {:sent, String.t()}
           | :jsonrpc_rejected
           | {:transport_failed, binary(), term()}
           | {:invalid_response, term()}
           | {:settle_failed, String.t()}
           | {:error, term()}

  # Nonce-critical section: fetching the pending nonce, signing the EIP-1559
  # transaction, and broadcasting it must be serialized per fee-payer address,
  # or two concurrent settles would sign different transactions with the same
  # nonce and one would be rejected as `unexpected_settle_error` (or the
  # broadcasts would race to replace each other). The lock is released as
  # soon as the node accepts the broadcast — receipt polling does not
  # consume a nonce and can run concurrently.
  @spec sign_and_broadcast(t(), String.t(), non_neg_integer(), String.t(), binary()) ::
          broadcast_outcome()
  defp sign_and_broadcast(engine, from, chain_id, asset, calldata) do
    with_fee_payer_lock(from, fn ->
      with {:ok, params} <- transaction_params(engine, from, asset, calldata),
           {:ok, raw} <- sign_transaction(engine, chain_id, params, asset, calldata) do
        broadcast(engine, raw)
      end
    end)
  end

  @spec broadcast(t(), binary()) :: broadcast_outcome()
  defp broadcast(engine, raw) do
    case RPC.request(engine.rpc, "eth_sendRawTransaction", [hex(raw)]) do
      {:ok, transaction_hash} when is_binary(transaction_hash) ->
        {:sent, transaction_hash}

      {:ok, other} ->
        {:invalid_response, other}

      {:error, {:jsonrpc_error, _error}} ->
        :jsonrpc_rejected

      # A transport failure mid-broadcast is ambiguous — the node may have
      # accepted the transaction. Kept out of the lock's return path so the
      # locally computed hash resolution happens without holding the lock.
      {:error, reason} ->
        {:transport_failed, raw, reason}
    end
  end

  @spec handle_broadcast(t(), broadcast_outcome(), String.t(), String.t() | nil) ::
          settle_result()
  defp handle_broadcast(engine, {:sent, transaction_hash}, network, payer),
    do: await_receipt(engine, transaction_hash, network, payer)

  defp handle_broadcast(_engine, :jsonrpc_rejected, network, payer),
    do: {:settled, failure_response("unexpected_settle_error", "", network, payer)}

  defp handle_broadcast(_engine, {:transport_failed, raw, reason}, network, payer),
    do: pending_after_transport_failure(raw, network, payer, reason)

  defp handle_broadcast(_engine, {:invalid_response, other}, _network, _payer),
    do: {:error, {:rpc_error, {:invalid_response, other}}}

  defp handle_broadcast(_engine, {:settle_failed, reason_string}, network, payer),
    do: {:settled, failure_response(reason_string, "", network, payer)}

  defp handle_broadcast(_engine, {:error, reason}, _network, _payer),
    do: {:error, reason}

  # `:global.trans/3` blocks until the lock is acquired (infinite retries)
  # and is released automatically if the caller crashes; scoped to `[node()]`
  # because the nonce sequence is node-local.
  @spec with_fee_payer_lock(String.t(), (-> broadcast_outcome())) :: broadcast_outcome()
  defp with_fee_payer_lock(from, fun) do
    :global.trans({{__MODULE__, :settle_nonce, String.downcase(from)}, self()}, fun, [node()])
  end

  @spec inner_signature(map()) :: {:ok, binary()} | {:error, term()}
  defp inner_signature(payload) do
    signature =
      Utils.nested_map_value(payload, [{"payload", :payload}, {"signature", :signature}])

    # Re-verify already proved the signature parses; a deployed ERC-1271
    # wallet's ERC-6492 wrapper is unwrapped here because the token contract
    # expects the inner signature.
    case ERC6492.parse(signature || "") do
      {:ok, %{inner_signature: inner}} -> {:ok, inner}
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
  @spec transaction_params(t(), String.t(), String.t(), binary()) ::
          {:ok, map()} | {:settle_failed, String.t()} | {:error, term()}
  defp transaction_params(engine, from, asset, calldata) do
    requests = [
      {"eth_estimateGas", [%{"from" => from, "to" => asset, "data" => hex(calldata)}]},
      {"eth_maxPriorityFeePerGas", []},
      {"eth_feeHistory", ["0x1", "latest", []]},
      {"eth_getTransactionCount", [from, "pending"]}
    ]

    case RPC.batch(engine.rpc, requests) do
      {:ok, [estimate, priority, fee_history, nonce]} ->
        assemble_params(engine, estimate, priority, fee_history, nonce)

      {:error, reason} ->
        {:error, {:rpc_error, reason}}
    end
  end

  @spec assemble_params(
          t(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result(),
          RPC.batch_result()
        ) :: {:ok, map()} | {:settle_failed, String.t()} | {:error, term()}
  defp assemble_params(engine, estimate, priority, fee_history, nonce) do
    with {:ok, gas_limit} <- gas_limit(engine, estimate),
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

  # An eth_estimateGas revert means the transfer would fail on chain — a
  # protocol-level rejection (it is itself a simulation), not an
  # infrastructure error.
  @spec gas_limit(t(), RPC.batch_result()) ::
          {:ok, pos_integer()} | {:settle_failed, String.t()} | {:error, term()}
  defp gas_limit(engine, {:ok, hex}) do
    case parse_quantity(hex) do
      {:ok, estimate} -> {:ok, div(estimate * (100 + engine.gas_limit_margin_percent), 100)}
      :error -> {:error, {:rpc_error, {:invalid_response, hex}}}
    end
  end

  defp gas_limit(_engine, {:error, {:jsonrpc_error, _error}}),
    do: {:settle_failed, "invalid_exact_evm_transaction_simulation_failed"}

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

  @spec pending_after_transport_failure(binary(), String.t(), String.t() | nil, term()) ::
          settle_result()
  defp pending_after_transport_failure(raw, network, payer, reason) do
    case EIP712.keccak_module() do
      {:ok, keccak_module} ->
        transaction_hash = hex(keccak_module.hash_256(raw))
        {:settled, failure_response("settlement_pending", transaction_hash, network, payer)}

      {:error, :missing_dependency} ->
        {:error, {:rpc_error, reason}}
    end
  end

  @spec await_receipt(t(), String.t(), String.t(), String.t() | nil) :: settle_result()
  defp await_receipt(engine, transaction_hash, network, payer) do
    deadline = System.monotonic_time(:millisecond) + engine.receipt_timeout_ms
    poll_receipt(engine, transaction_hash, network, payer, deadline)
  end

  @spec poll_receipt(t(), String.t(), String.t(), String.t() | nil, integer()) :: settle_result()
  defp poll_receipt(engine, transaction_hash, network, payer, deadline) do
    case RPC.request(engine.rpc, "eth_getTransactionReceipt", [transaction_hash]) do
      {:ok, %{"status" => "0x1"}} ->
        {:settled, success_response(transaction_hash, network, payer)}

      {:ok, %{"status" => "0x0"}} ->
        {:settled,
         failure_response(
           "invalid_exact_evm_transaction_failed",
           transaction_hash,
           network,
           payer
         )}

      # Pending (null receipt), unexpected shapes, and transient RPC errors
      # all keep polling until the deadline; the transaction is broadcast, so
      # the only safe terminal answer without a receipt is settlement_pending.
      _pending_or_error ->
        retry_or_pending(engine, transaction_hash, network, payer, deadline)
    end
  end

  @spec retry_or_pending(t(), String.t(), String.t(), String.t() | nil, integer()) ::
          settle_result()
  defp retry_or_pending(engine, transaction_hash, network, payer, deadline) do
    case System.monotonic_time(:millisecond) + engine.receipt_interval_ms <= deadline do
      true ->
        Process.sleep(engine.receipt_interval_ms)
        poll_receipt(engine, transaction_hash, network, payer, deadline)

      false ->
        {:settled, failure_response("settlement_pending", transaction_hash, network, payer)}
    end
  end

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

  @spec network(map(), map()) :: String.t()
  defp network(requirements, payload) do
    Utils.map_value(requirements, {"network", :network}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"network", :network}]) || ""
  end

  @spec asset(map()) :: String.t()
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
