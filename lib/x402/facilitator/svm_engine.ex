defmodule X402.Facilitator.SVMEngine do
  @moduledoc """
  Facilitator-role engine for `exact` payments on Solana (`solana:*`).

  The SVM counterpart of `X402.Facilitator.Engine`: it assembles the SDK's
  local SVM verification (`X402.Verify.SVM`), Solana JSON-RPC calls
  (`X402.Solana.RPC`), transaction primitives (`X402.Solana.Transaction`),
  and the signer behaviour (`X402.Signer`) into the engine behind the
  facilitator API's three operations, speaking the same wire shapes as the
  reference facilitators:

  * `verify/3` — the full exact-SVM static-path checklist, returning the
    `POST /verify` response.
  * `settle/3` — **re-verifies independently**, co-signs the fee-payer slot
    with the configured signer, broadcasts via `sendTransaction`, and polls
    `getSignatureStatuses` until the transaction is confirmed, returning the
    `POST /settle` response with the Base58 transaction signature.
  * `supported/1` — the `GET /supported` response derived from the
    configured networks.

  Expose the engine over HTTP with `X402.Plug.Facilitator` (alone, or next
  to an EVM `X402.Facilitator.Engine` via the `:engines` option), or call it
  directly from your own transport.

  ## Fee-payer safety

  The facilitator's Ed25519 key co-signs client-built transactions, so what
  it signs is strictly constrained by verification: the requirements'
  `extra.feePayer` must be this engine's signer, account 0 must be that fee
  payer, the fee payer must not be referenced by any instruction (isolation
  — the sponsor's signature can never move the sponsor's funds), the
  instruction layout must match the static whitelist, and every other
  required signer's Ed25519 signature is verified locally over the message
  bytes. Smart-wallet (CPI-wrapped) payments and address-lookup-table
  transactions are rejected fail-closed.

  ## Settlement pipeline

  1. Compute the settlement key — SHA-256 of the transaction's message
     bytes — and **atomically claim it** in the `:settlement_cache`
     (`duplicate_settlement` when already claimed). The claim is released on
     verify failure, node-side broadcast rejection, and terminal on-chain
     failure, and kept on success. On `settlement_pending` the claim is
     kept only when the `:pending_settlement_store` recorded the broadcast
     (a retry then reconciles against the recorded signature); without a
     store it is released, so a retry re-verifies and re-broadcasts the
     identical wire bytes instead of dead-ending on `duplicate_settlement`.
  2. Pending-settlement fast path: when a prior settle for this exact
     transaction broadcast but could not confirm, re-await the recorded
     signature instead of re-verifying and re-broadcasting (Solana
     transactions embed an expiring blockhash, so a resend can fail while
     the original is still perfectly valid).
  3. Re-verify via `X402.Verify.SVM` at `:full` level, re-simulating by
     default exactly as the reference facilitators do (see
     `:simulate_in_settle`).
  4. Sign the message bytes with the configured signer, splice the
     signature into the fee payer's slot 0
     (`X402.Solana.Transaction.attach_signature/3`), and broadcast with
     `skipPreflight: true`.
  5. Poll `getSignatureStatuses` until `confirmed`/`finalized` or
     `:confirm_timeout_ms`. A broadcast whose confirmation cannot be
     established returns the spec's non-terminal `"settlement_pending"`
     with the transaction signature and records it in the
     `:pending_settlement_store` for the fast path above.

  ## Duplicate-settlement protection

  > #### Configure a settlement cache and a pending store {: .warning}
  >
  > With the default `settlement_cache: nil`, duplicate-settlement
  > protection is **disabled**: concurrent settles of the same payment all
  > broadcast (the network still collapses them to one transaction id, but
  > every call burns RPC round-trips and races the confirmation poll).
  > Production engines should configure **both** the cache the reference
  > facilitators use — 120 seconds, roughly twice the blockhash lifetime —
  > and a `:pending_settlement_store`. The two interact: on a
  > `settlement_pending` verdict the cache claim is kept only when the
  > store recorded the broadcast, letting the retry reconcile against the
  > recorded signature; with a cache but no store the claim is released so
  > the retry can re-broadcast the identical wire bytes (collapsed by the
  > network to one transaction id) instead of being rejected as
  > `duplicate_settlement`.
  >
  >     children = [
  >       {X402.Extensions.PaymentIdentifier.ETSCache,
  >        name: MyApp.SettlementCache, ttl_ms: 120_000},
  >       {X402.Facilitator.PendingSettlementStore.ETS,
  >        name: MyApp.PendingSettlements}
  >     ]
  >
  >     settlement_cache:
  >       {X402.Extensions.PaymentIdentifier.ETSCache, MyApp.SettlementCache},
  >     pending_settlement_store:
  >       {X402.Facilitator.PendingSettlementStore.ETS, MyApp.PendingSettlements}

  ## Example

      {:ok, rpc} = X402.RPC.new(rpc_url: "https://api.devnet.solana.com", finch: MyApp.Finch)
      {:ok, signer} = X402.Signer.SolanaKey.new(System.fetch_env!("SOLANA_FEE_PAYER_KEY"))

      {:ok, engine} =
        X402.Facilitator.SVMEngine.new(
          rpc: rpc,
          signer: signer,
          networks: ["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]
        )

      {:ok, %{"isValid" => true, "payer" => payer}} =
        X402.Facilitator.SVMEngine.verify(engine, payment_payload, requirements)

      {:ok, %{"success" => true, "transaction" => signature}} =
        X402.Facilitator.SVMEngine.settle(engine, payment_payload, requirements)

  ## Hooks and telemetry

  `X402.Hooks` callbacks wrap both operations exactly as on
  `X402.Facilitator.Engine`, and the same
  `[:x402, :facilitator_engine, :verify]` / `[:x402, :facilitator_engine,
  :settle]` telemetry events are emitted with `:status` metadata.
  """

  alias X402.Base58
  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Facilitator.PendingSettlementStore
  alias X402.Hooks
  alias X402.Hooks.Context
  alias X402.RPC
  alias X402.Signer
  alias X402.Solana
  alias X402.Solana.Transaction
  alias X402.Telemetry
  alias X402.Utils
  alias X402.Verify.SVM

  require Logger

  @x402_version 2
  @scheme "exact"

  # Namespaces settlement claims inside a cache that may be shared with
  # other consumers of the PaymentIdentifier.Cache behaviour.
  @dedup_prefix "svm:"

  @enforce_keys [:rpc, :signer, :networks]
  defstruct [
    :rpc,
    :signer,
    :networks,
    hooks: X402.Hooks.Default,
    simulate: true,
    simulate_in_settle: true,
    settlement_cache: nil,
    pending_settlement_store: nil,
    confirm_timeout_ms: 30_000,
    confirm_interval_ms: 1_000,
    max_required_signatures: nil
  ]

  @typedoc "A validated engine configuration built by `new/1`."
  @type t :: %__MODULE__{
          rpc: RPC.t(),
          signer: Signer.t(),
          networks: [String.t()],
          hooks: module(),
          simulate: boolean(),
          simulate_in_settle: boolean(),
          settlement_cache: Cache.adapter() | nil,
          pending_settlement_store: PendingSettlementStore.adapter() | nil,
          confirm_timeout_ms: pos_integer(),
          confirm_interval_ms: pos_integer(),
          max_required_signatures: pos_integer() | nil
        }

  @typedoc "A facilitator wire response (`/verify` or `/settle` shape)."
  @type wire_response :: %{optional(String.t()) => term()}

  @config_schema [
    rpc: [
      type: {:custom, RPC, :validate_config, []},
      required: true,
      doc: "An `X402.RPC` configuration pointed at a Solana JSON-RPC node."
    ],
    signer: [
      type: {:custom, __MODULE__, :validate_signer, []},
      required: true,
      doc: """
      The fee-payer signer (a struct implementing `X402.Signer` with the
      `sign_ed25519/2` callback — `X402.Signer.SolanaKey` does). Its key
      pays transaction fees and co-signs every settlement.
      """
    ],
    networks: [
      type: {:custom, __MODULE__, :validate_networks, []},
      required: true,
      doc: """
      Non-empty list of CAIP-2 networks this engine serves
      (`solana:<reference>` only). Verify and settle requests for other
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
      doc: "Whether `verify/3` runs `simulateTransaction`."
    ],
    simulate_in_settle: [
      type: :boolean,
      default: true,
      doc: """
      Whether the independent re-verify inside `settle/3` also simulates.
      On by default, matching the reference facilitators, whose settle
      always re-simulates: it is the blockhash-freshness and balance guard
      right before the preflight-skipping broadcast, and the fee payer is
      charged for a transaction that fails on-chain. Disabling it is an
      explicit operator optimization that trades that guard for one fewer
      RPC round-trip per settle.
      """
    ],
    settlement_cache: [
      type: {:custom, __MODULE__, :validate_settlement_cache, []},
      default: nil,
      doc: """
      Optional `{module, cache}` adapter implementing
      `X402.Extensions.PaymentIdentifier.Cache`, used as the atomic
      duplicate-settlement claim (`duplicate_settlement`). **`nil` disables
      duplicate protection entirely** — see the module documentation for
      the recommended `ETSCache` configuration with `ttl_ms: 120_000`,
      paired with a `:pending_settlement_store`.
      """
    ],
    pending_settlement_store: [
      type: {:custom, __MODULE__, :validate_pending_settlement_store, []},
      default: nil,
      doc: """
      Optional `{module, store}` adapter implementing
      `X402.Facilitator.PendingSettlementStore`. Lets a retried settle for
      the same transaction reconcile against the already-broadcast
      signature instead of re-verifying and re-broadcasting. `nil` disables
      reconciliation: a `settlement_pending` verdict is returned but not
      recorded, and the `:settlement_cache` claim is released so the retry
      can re-broadcast the identical wire bytes rather than dead-end on
      `duplicate_settlement`.
      """
    ],
    confirm_timeout_ms: [
      type: :pos_integer,
      default: 30_000,
      doc: """
      How long `settle/3` waits for confirmation before returning the
      non-terminal `"settlement_pending"` response.
      """
    ],
    confirm_interval_ms: [
      type: :pos_integer,
      default: 1_000,
      doc: "Interval between `getSignatureStatuses` polls."
    ],
    max_required_signatures: [
      type: {:or, [nil, :pos_integer]},
      default: nil,
      doc: """
      Cap on a transaction's required signature count (every signature adds
      5000 lamports of base fee, paid by this engine's key). `nil` disables
      the cap.
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
  `%{"isValid" => false, "invalidReason" => reason, ...}` with the
  canonical cross-SDK reason string (`X402.Verify.SVM.reason_string/1`).
  `{:error, reason}` is reserved for infrastructure failures (RPC transport
  errors, hook crashes) where no verdict about the payment exists;
  transports should map it to an opaque 500.
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

  Independently re-verifies the payment first, then co-signs the fee-payer
  slot and broadcasts — see the module documentation for the full pipeline,
  including duplicate-settlement claims and pending-settlement
  reconciliation. Rejected or failed settlements come back as
  `{:ok, %{"success" => false, "errorReason" => reason, ...}}`; a broadcast
  whose confirmation could not be established returns the non-terminal
  `"settlement_pending"` reason with the transaction signature.
  `{:error, reason}` is reserved for infrastructure failures where nothing
  was broadcast.
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
  address under the `solana:*` family. Each kind advertises the fee payer
  under `"extra"` — the channel through which reference resource servers
  discover which `extra.feePayer` to inject into their 402 challenges
  (omitted only when the signer's address is unavailable).

  ## Examples

      {:ok, engine} = X402.Facilitator.SVMEngine.new(rpc: rpc, signer: signer, networks: [network])
      X402.Facilitator.SVMEngine.supported(engine)
      #=> %{
      #     "kinds" => [
      #       %{
      #         "x402Version" => 2,
      #         "scheme" => "exact",
      #         "network" => network,
      #         "extra" => %{"feePayer" => "9hSR..."}
      #       }
      #     ],
      #     "extensions" => [],
      #     "signers" => %{"solana:*" => ["9hSR..."]}
      #   }
  """
  @spec supported(t()) :: wire_response()
  def supported(%__MODULE__{} = engine) do
    extra =
      case Signer.address(engine.signer) do
        {:ok, address} -> %{"feePayer" => address}
        {:error, _reason} -> nil
      end

    %{
      "kinds" => Enum.map(engine.networks, &kind(&1, extra)),
      "extensions" => [],
      "signers" => signers(engine)
    }
  end

  @spec kind(String.t(), %{optional(String.t()) => String.t()} | nil) :: wire_response()
  defp kind(network, nil),
    do: %{"x402Version" => @x402_version, "scheme" => @scheme, "network" => network}

  defp kind(network, extra),
    do: %{
      "x402Version" => @x402_version,
      "scheme" => @scheme,
      "network" => network,
      "extra" => extra
    }

  @doc false
  @spec validate_signer(term()) :: {:ok, Signer.t()} | {:error, String.t()}
  def validate_signer(%module{} = signer) do
    case X402.Behaviour.implements?(module, address: 1, sign_ed25519: 2) do
      true -> {:ok, signer}
      false -> {:error, "expected a struct implementing X402.Signer with sign_ed25519/2"}
    end
  end

  def validate_signer(_other),
    do: {:error, "expected a struct implementing X402.Signer with sign_ed25519/2"}

  @doc false
  @spec validate_networks(term()) :: {:ok, [String.t()]} | {:error, String.t()}
  def validate_networks([_head | _tail] = networks) do
    case Enum.all?(networks, &svm_network?/1) do
      true -> {:ok, networks}
      false -> {:error, "expected a non-empty list of solana:<reference> CAIP-2 networks"}
    end
  end

  def validate_networks(_other),
    do: {:error, "expected a non-empty list of solana:<reference> CAIP-2 networks"}

  @doc false
  @spec validate_settlement_cache(term()) :: {:ok, Cache.adapter() | nil} | {:error, String.t()}
  def validate_settlement_cache(nil), do: {:ok, nil}

  def validate_settlement_cache(adapter) do
    case Cache.validate_adapter(adapter) do
      :ok -> {:ok, adapter}
      {:error, message} -> {:error, message}
    end
  end

  @doc false
  @spec validate_pending_settlement_store(term()) ::
          {:ok, PendingSettlementStore.adapter() | nil} | {:error, String.t()}
  def validate_pending_settlement_store(nil), do: {:ok, nil}

  def validate_pending_settlement_store(adapter),
    do: PendingSettlementStore.validate_adapter(adapter)

  @doc false
  @spec validate_config(term()) :: {:ok, t()} | {:error, String.t()}
  def validate_config(%__MODULE__{} = engine), do: {:ok, engine}

  def validate_config(_other),
    do:
      {:error,
       "expected an %X402.Facilitator.SVMEngine{} built with X402.Facilitator.SVMEngine.new/1"}

  # -- Verify -----------------------------------------------------------------

  @typep protocol_result ::
           {:valid, wire_response(), String.t()}
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
    with {:ok, fee_payer} <- signer_address(engine) do
      opts = [
        level: :full,
        rpc: engine.rpc,
        simulate: simulate,
        fee_payer: fee_payer,
        max_required_signatures: engine.max_required_signatures
      ]

      case SVM.verify(payload, requirements, opts) do
        {:ok, %{payer: verified_payer}} ->
          {:valid, %{"isValid" => true, "payer" => verified_payer}, verified_payer}

        {:error, {:invalid, reason}} ->
          {:invalid, invalid_response(SVM.reason_string(reason), payer(payload))}

        {:error, reason} ->
          {:error, reason}
      end
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
  defp handle_verify_result({:valid, response, _payer}, engine, context, metadata) do
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

    case route(engine, payload, requirements) do
      :ok ->
        execute_settlement(engine, payload, requirements, network)

      {:unsupported, reason_string} ->
        {:settled, failure_response(reason_string, "", network, payer(payload))}
    end
  end

  @spec execute_settlement(t(), map(), map(), String.t()) :: settle_result()
  defp execute_settlement(engine, payload, requirements, network) do
    case decode_payload_transaction(payload) do
      {:ok, decoded} ->
        txkey = transaction_key(decoded)
        settle_keyed(engine, payload, requirements, network, decoded, txkey)

      :error ->
        # Undecodable payloads cannot be keyed for dedup or reconciliation;
        # the re-verify produces the canonical decode rejection.
        verify_and_broadcast(engine, payload, requirements, network, nil, nil)
    end
  end

  @spec settle_keyed(t(), map(), map(), String.t(), Transaction.decoded(), String.t()) ::
          settle_result()
  defp settle_keyed(engine, payload, requirements, network, decoded, txkey) do
    # The dedup claim happens FIRST, before any RPC: concurrent settles of
    # the same payment must be caught before any broadcast work begins. A
    # pending-store hit takes precedence over the duplicate verdict — the
    # entry means the claim holder already broadcast and returned, and this
    # retry's job is to reconcile that broadcast, not to be rejected by its
    # leftover claim.
    with {:ok, claim} <- claim_settlement(engine, txkey) do
      case {pending_entry(engine, txkey), claim} do
        {{:hit, entry}, _claim} ->
          reconcile_pending(engine, txkey, entry, network, transfer_authority(decoded))

        {:miss, :duplicate} ->
          {:settled,
           failure_response("duplicate_settlement", "", network, transfer_authority(decoded))}

        {:miss, _claimed_or_disabled} ->
          verify_and_broadcast(engine, payload, requirements, network, decoded, txkey)
      end
    end
  end

  @spec verify_and_broadcast(
          t(),
          map(),
          map(),
          String.t(),
          Transaction.decoded() | nil,
          String.t() | nil
        ) :: settle_result()
  defp verify_and_broadcast(engine, payload, requirements, network, decoded, txkey) do
    case delegate_verify(engine, payload, requirements, engine.simulate_in_settle) do
      {:valid, _response, verified_payer} when decoded != nil ->
        broadcast(engine, decoded, txkey, network, verified_payer)

      {:valid, _response, _payer} ->
        # A successful verify implies the payload decoded; unreachable in
        # practice, but nothing may be broadcast without the decoded bytes.
        release_claim(engine, txkey)
        {:error, {:settle_error, :invalid_transaction}}

      {:invalid, response} ->
        # Nothing was broadcast — release the claim so a corrected retry
        # is not blocked for the cache TTL.
        release_claim(engine, txkey)
        {:settled, failure_response(response["invalidReason"], "", network, response["payer"])}

      {:error, reason} ->
        release_claim(engine, txkey)
        {:error, reason}
    end
  end

  @spec broadcast(t(), Transaction.decoded(), String.t() | nil, String.t(), String.t()) ::
          settle_result()
  defp broadcast(engine, decoded, txkey, network, verified_payer) do
    with {:ok, fee_payer_signature} <- sign_fee_payer(engine, decoded),
         {:ok, wire} <- splice_signature(decoded, fee_payer_signature) do
      send_and_await(engine, wire, fee_payer_signature, txkey, network, verified_payer)
    else
      {:error, reason} ->
        release_claim(engine, txkey)
        {:error, {:settle_error, reason}}
    end
  end

  @spec sign_fee_payer(t(), Transaction.decoded()) :: {:ok, binary()} | {:error, term()}
  defp sign_fee_payer(engine, decoded),
    do: Signer.sign_ed25519(engine.signer, decoded.message_bytes)

  @spec splice_signature(Transaction.decoded(), binary()) :: {:ok, binary()} | {:error, term()}
  defp splice_signature(decoded, fee_payer_signature),
    do: Transaction.attach_signature(decoded, 0, fee_payer_signature)

  @spec send_and_await(t(), binary(), binary(), String.t() | nil, String.t(), String.t()) ::
          settle_result()
  defp send_and_await(engine, wire, fee_payer_signature, txkey, network, verified_payer) do
    case Solana.RPC.send_transaction(engine.rpc, Base.encode64(wire)) do
      {:ok, signature} ->
        await_and_respond(engine, txkey, signature, network, verified_payer)

      {:error, {:jsonrpc_error, _error}} ->
        # The node rejected the transaction without accepting it — release
        # the claim so a retry is not blocked.
        release_claim(engine, txkey)
        {:settled, failure_response("unexpected_settle_error", "", network, verified_payer)}

      {:error, _transport} ->
        # A transport failure mid-broadcast is ambiguous — the node may have
        # accepted the transaction — so it is treated as pending, never
        # terminal. On Solana the transaction id IS the first signature, so
        # it is computable locally even though the node's answer never
        # arrived. A retry either reconciles via the pending store or
        # re-broadcasts the identical wire bytes (same transaction id).
        entry = %{
          transaction: Base58.encode(fee_payer_signature),
          provenance: :local_hash,
          raw_transaction: wire
        }

        record_pending_or_terminal(engine, txkey, entry, network, verified_payer)
    end
  end

  @spec await_and_respond(t(), String.t() | nil, String.t(), String.t(), String.t() | nil) ::
          settle_result()
  defp await_and_respond(engine, txkey, signature, network, verified_payer) do
    case await_confirmation(engine, signature) do
      :confirmed ->
        {:settled, success_response(signature, network, verified_payer)}

      {:failed, _err} ->
        # Definite on-chain rejection: release the claim so a retry with a
        # fresh blockhash is not blocked by this settlement's leftover claim.
        release_claim(engine, txkey)

        {:settled,
         failure_response(
           "invalid_exact_svm_transaction_failed",
           signature,
           network,
           verified_payer
         )}

      :timeout ->
        entry = %{transaction: signature, provenance: :node_acknowledged, raw_transaction: nil}
        record_pending_or_terminal(engine, txkey, entry, network, verified_payer)
    end
  end

  # -- Pending-settlement reconciliation ---------------------------------------

  @spec reconcile_pending(
          t(),
          String.t(),
          PendingSettlementStore.entry(),
          String.t(),
          String.t() | nil
        ) :: settle_result()
  defp reconcile_pending(engine, txkey, entry, network, payer) do
    # Delete before reconciling (not after) so a concurrent retry of the
    # same payload misses here and falls through to the dedup claim, which
    # independently rejects it as a duplicate.
    delete_pending(engine, txkey)

    case await_confirmation(engine, entry.transaction) do
      :confirmed ->
        {:settled, success_response(entry.transaction, network, payer)}

      {:failed, _err} ->
        release_claim(engine, txkey)

        {:settled,
         failure_response(
           "invalid_exact_svm_transaction_failed",
           entry.transaction,
           network,
           payer
         )}

      :timeout ->
        record_pending_or_terminal(engine, txkey, entry, network, payer)
    end
  end

  # -- Confirmation polling -----------------------------------------------------

  @spec await_confirmation(t(), String.t()) :: :confirmed | {:failed, term()} | :timeout
  defp await_confirmation(engine, signature) do
    deadline = System.monotonic_time(:millisecond) + engine.confirm_timeout_ms
    poll_status(engine, signature, deadline)
  end

  @spec poll_status(t(), String.t(), integer()) :: :confirmed | {:failed, term()} | :timeout
  defp poll_status(engine, signature, deadline) do
    case Solana.RPC.get_signature_statuses(engine.rpc, [signature]) do
      # An on-chain err is terminal only at "confirmed"/"finalized"
      # commitment, mirroring the reference signer's confirmTransaction: a
      # "processed"-level err can sit on a minority fork that is later
      # discarded, so it keeps polling until the deadline.
      {:ok, [%{confirmation_status: status, err: err}]}
      when status in ["confirmed", "finalized"] and not is_nil(err) ->
        {:failed, err}

      {:ok, [%{confirmation_status: status}]} when status in ["confirmed", "finalized"] ->
        :confirmed

      # Unknown signature, "processed" (with or without an err), unexpected
      # shapes, and transient RPC errors all keep polling until the
      # deadline; the transaction is broadcast, so the only safe terminal
      # answer without a confirmed status is settlement_pending.
      _pending_or_error ->
        retry_or_timeout(engine, signature, deadline)
    end
  end

  @spec retry_or_timeout(t(), String.t(), integer()) :: :confirmed | {:failed, term()} | :timeout
  defp retry_or_timeout(engine, signature, deadline) do
    case System.monotonic_time(:millisecond) + engine.confirm_interval_ms <= deadline do
      true ->
        Process.sleep(engine.confirm_interval_ms)
        poll_status(engine, signature, deadline)

      false ->
        :timeout
    end
  end

  # -- Settlement claims and pending store --------------------------------------

  # SHA-256 of the message bytes — used for BOTH the dedup claim and the
  # pending store. The fee-payer signature at slot 0 is mutable (this engine
  # overwrites it), so hashing the wire bytes would let an attacker
  # randomize the key; the message is what every signer commits to.
  @spec transaction_key(Transaction.decoded()) :: String.t()
  defp transaction_key(decoded),
    do: Base.encode16(:crypto.hash(:sha256, decoded.message_bytes), case: :lower)

  @spec claim_settlement(t(), String.t()) ::
          {:ok, :claimed | :duplicate | :disabled} | {:error, term()}
  defp claim_settlement(%{settlement_cache: nil}, _txkey), do: {:ok, :disabled}

  defp claim_settlement(%{settlement_cache: cache}, txkey) do
    case Cache.put_new(cache, @dedup_prefix <> txkey, :verified) do
      :ok -> {:ok, :claimed}
      {:error, :already_exists} -> {:ok, :duplicate}
      # A broken or full cache fails closed as an infrastructure error —
      # settling without the claim would silently drop replay protection.
      {:error, reason} -> {:error, {:settlement_cache_error, reason}}
    end
  end

  @spec release_claim(t(), String.t() | nil) :: :ok
  defp release_claim(_engine, nil), do: :ok
  defp release_claim(%{settlement_cache: nil}, _txkey), do: :ok

  defp release_claim(%{settlement_cache: cache}, txkey) do
    Cache.delete(cache, @dedup_prefix <> txkey)
    :ok
  end

  @spec pending_entry(t(), String.t()) :: {:hit, PendingSettlementStore.entry()} | :miss
  defp pending_entry(%{pending_settlement_store: nil}, _txkey), do: :miss

  defp pending_entry(%{pending_settlement_store: store}, txkey) do
    case PendingSettlementStore.get(store, txkey) do
      {:hit, entry} -> {:hit, entry}
      :miss -> :miss
      # Best-effort: a store failure falls through to the normal path,
      # where the dedup claim still guards against double-broadcast.
      {:error, _reason} -> :miss
    end
  end

  @spec delete_pending(t(), String.t()) :: :ok
  defp delete_pending(%{pending_settlement_store: store}, txkey) do
    PendingSettlementStore.delete(store, txkey)
    :ok
  end

  @spec record_pending_or_terminal(
          t(),
          String.t() | nil,
          PendingSettlementStore.entry(),
          String.t(),
          String.t() | nil
        ) :: settle_result()
  defp record_pending_or_terminal(
         %{pending_settlement_store: nil} = engine,
         txkey,
         entry,
         network,
         payer
       ) do
    # No store configured: the pending verdict is returned but not recorded,
    # so a retry has nothing to reconcile against. Release the dedup claim —
    # a kept claim would dead-end the retry on duplicate_settlement — so the
    # retry re-verifies and re-broadcasts the identical wire bytes, which
    # the network collapses to the same transaction id.
    release_claim(engine, txkey)
    {:settled, failure_response("settlement_pending", entry.transaction, network, payer)}
  end

  defp record_pending_or_terminal(
         %{pending_settlement_store: store} = engine,
         txkey,
         entry,
         network,
         payer
       ) do
    case PendingSettlementStore.put(store, txkey, entry) do
      :ok ->
        {:settled, failure_response("settlement_pending", entry.transaction, network, payer)}

      {:error, reason} ->
        # A retry would have no record to reconcile against and would
        # re-broadcast blindly — downgrade to a terminal failure, keeping
        # the signature in the response for manual reconciliation. Release
        # the dedup claim (like the no-store branch does) so a retry is not
        # dead-ended at `duplicate_settlement`: without this, the claim
        # outlives the missing pending record and the charged transaction
        # cannot be reconciled or re-broadcast.
        Logger.warning(
          "x402 SVM settlement pending, but failed to persist for retry: #{inspect(reason)}"
        )

        release_claim(engine, txkey)

        {:settled,
         failure_response(
           "invalid_exact_svm_transaction_failed",
           entry.transaction,
           network,
           payer
         )}
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
  defp success_response(signature, network, payer) do
    put_payer(%{"success" => true, "transaction" => signature, "network" => network}, payer)
  end

  @spec failure_response(String.t(), String.t(), String.t(), String.t() | nil) :: wire_response()
  defp failure_response(reason_string, signature, network, payer) do
    put_payer(
      %{
        "success" => false,
        "errorReason" => reason_string,
        "transaction" => signature,
        "network" => network
      },
      payer
    )
  end

  @spec put_payer(map(), term()) :: wire_response()
  defp put_payer(response, payer) when is_binary(payer), do: Map.put(response, "payer", payer)
  defp put_payer(response, _payer), do: response

  # -- Helpers ----------------------------------------------------------------

  @spec signer_address(t()) :: {:ok, String.t()} | {:error, term()}
  defp signer_address(engine) do
    case Signer.address(engine.signer) do
      {:ok, address} -> {:ok, address}
      {:error, reason} -> {:error, {:signer_error, reason}}
    end
  end

  @spec signers(t()) :: %{optional(String.t()) => [String.t()]}
  defp signers(engine) do
    case Signer.address(engine.signer) do
      {:ok, address} -> %{"solana:*" => [address]}
      {:error, _reason} -> %{}
    end
  end

  @spec decode_payload_transaction(map()) :: {:ok, Transaction.decoded()} | :error
  defp decode_payload_transaction(payload) do
    with transaction when is_binary(transaction) <-
           Utils.nested_map_value(payload, [
             {"payload", :payload},
             {"transaction", :transaction}
           ]),
         {:ok, wire} <- Base.decode64(transaction),
         {:ok, decoded} <- Transaction.decode(wire) do
      {:ok, decoded}
    else
      _error -> :error
    end
  end

  # Best-effort payer for responses produced before or without a full
  # verification: the authority of the first token-program instruction with
  # a TransferChecked account shape ([source, mint, destination, authority]).
  @spec payer(map()) :: String.t() | nil
  defp payer(payload) do
    case decode_payload_transaction(payload) do
      {:ok, decoded} -> transfer_authority(decoded)
      :error -> nil
    end
  end

  @spec transfer_authority(Transaction.decoded()) :: String.t() | nil
  defp transfer_authority(decoded) do
    token_programs = [token_pubkey(), token_2022_pubkey()]

    Enum.find_value(decoded.instructions, fn instruction ->
      with true <- Enum.at(decoded.static_accounts, instruction.program_index) in token_programs,
           [_source, _mint, _destination, authority_index | _rest] <-
             instruction.account_indices,
           pubkey when is_binary(pubkey) <-
             Enum.at(decoded.static_accounts, authority_index) do
        Base58.encode(pubkey)
      else
        _mismatch -> nil
      end
    end)
  end

  @spec token_pubkey() :: binary()
  defp token_pubkey do
    {:ok, pubkey} = Solana.decode_address(Solana.token_program())
    pubkey
  end

  @spec token_2022_pubkey() :: binary()
  defp token_2022_pubkey do
    {:ok, pubkey} = Solana.decode_address(Solana.token_2022_program())
    pubkey
  end

  @spec network(map(), map()) :: String.t()
  defp network(requirements, payload) do
    Utils.map_value(requirements, {"network", :network}) ||
      Utils.nested_map_value(payload, [{"accepted", :accepted}, {"network", :network}]) || ""
  end

  @spec svm_network?(term()) :: boolean()
  defp svm_network?("solana:" <> reference), do: reference != ""
  defp svm_network?(_network), do: false

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
