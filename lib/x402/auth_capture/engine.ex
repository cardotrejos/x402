defmodule X402.AuthCapture.Engine do
  @moduledoc """
  Explicit-consent auth-capture transaction execution and reconciliation.

  Uses a dedicated EVM gas account, full pinned verification, a durable
  `X402.AuthCapture.Journal`, and strict escrow receipt checks. No caller
  supplied verification result is accepted. Transactions are signed through
  `X402.Signer.sign_transaction/2`, frozen before dispatch, and sent at most
  once. A timeout after dispatch is pending, not permission to rebroadcast.

  `execute/3` performs one transaction and one receipt check. Applications
  schedule `reconcile/1`; there is no polling process or automatic replacement.
  Confirmed results retain the signer scope until the caller durably records
  its payment effects and calls `acknowledge/2`. Reverted transactions follow
  the same acknowledgement rule. Abandoned preparations, expired frozen
  transactions, and missing receipts require application recovery.

  A combined capture-and-void payload is rejected rather than silently
  ignoring its second leg. An orchestration layer must durably record the
  capture result before submitting the separately consented void.

  Refunds require a request-specific `:refund_authorize` callback and existing
  token liquidity/allowances. This executor never approves or obtains refund
  funding itself. The callback receives canonical, signature-verified payment
  identity and terms; return `:ok` only for the exact application funding
  agreement. It must tolerate repeated evaluation.

  Receipt confirmation uses the configured depth on the trusted RPC and
  rechecks the inclusion block hash. This is not an independent finality proof
  and cannot protect against reorgs deeper than the chosen depth.
  """

  alias X402.AuthCapture
  alias X402.AuthCapture.EVM
  alias X402.AuthCapture.Journal
  alias X402.AuthCapture.Receipt
  alias X402.AuthCapture.Store
  alias X402.Behaviour
  alias X402.EIP3009
  alias X402.RPC
  alias X402.Signer
  alias X402.Transaction
  alias X402.Utils
  alias X402.Verify.AuthCaptureEVM, as: Verify

  @enforce_keys [:rpc, :signer, :address, :network, :chain_id, :journal, :options]
  defstruct [:rpc, :signer, :address, :network, :chain_id, :journal, :options]

  @type t :: %__MODULE__{
          rpc: RPC.t(),
          signer: Signer.t(),
          address: String.t(),
          network: String.t(),
          chain_id: pos_integer(),
          journal: Journal.t(),
          options: keyword()
        }
  @type result :: %{
          id: binary(),
          status: :pending | :confirmed | :reverted,
          transaction: String.t() | nil,
          operation: atom(),
          payer: String.t(),
          amount: non_neg_integer(),
          payment_info_hash: String.t(),
          receipt: map() | nil
        }

  @options [
    rpc: [type: {:custom, RPC, :validate_config, []}, required: true],
    signer: [type: {:custom, __MODULE__, :validate_signer, []}, required: true],
    network: [type: :string, required: true],
    store: [type: {:custom, Store, :validate, []}, required: true],
    max_fee_per_gas: [type: :pos_integer, required: true],
    max_priority_fee_per_gas: [type: :non_neg_integer, required: true],
    gas_limit: [type: :pos_integer, default: 1_000_000],
    confirmations: [type: :pos_integer, default: 2],
    history_limit: [type: :pos_integer, default: 10_000],
    clock: [type: {:fun, 0}, required: true],
    eip6492_allowed_factories: [type: {:list, :string}, default: []],
    refund_authorize: [type: {:fun, 3}]
  ]

  @doc since: "0.9.0"
  @doc """
  Builds an executor with explicit gas-price caps and mandatory storage.

  `:clock` returns Unix seconds. The default uses the system clock.

  #{NimbleOptions.docs(@options)}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    opts = Keyword.put_new(opts, :clock, fn -> System.os_time(:second) end)

    with {:ok, opts} <- NimbleOptions.validate(opts, @options),
         {:ok, address} <- Signer.address(opts[:signer]),
         {:ok, journal} <-
           Journal.new(
             Keyword.take(opts, [:store, :network, :history_limit]) ++ [signer: address]
           ),
         {:ok, chain_id} <-
           EVM.parse_uint256(String.replace_prefix(opts[:network], "eip155:", "")),
         :ok <- fee_bounds(opts) do
      {:ok,
       %__MODULE__{
         rpc: opts[:rpc],
         signer: opts[:signer],
         address: String.downcase(address),
         network: opts[:network],
         chain_id: chain_id,
         journal: journal,
         options: opts
       }}
    end
  end

  @doc false
  @spec validate_signer(term()) :: {:ok, Signer.t()} | {:error, String.t()}
  def validate_signer(%module{} = signer) do
    if Behaviour.implements?(module, address: 1, sign_transaction: 3),
      do: {:ok, signer},
      else: {:error, "expected an EVM transaction signer"}
  end

  def validate_signer(_signer), do: {:error, "expected an EVM transaction signer"}

  @doc since: "0.9.0"
  @doc """
  Verifies and executes a single lifecycle transaction, or reconciles its retry.

  Exact retries retain their request identity even after authorization expiry.
  A pending result never indicates that paid content may be released.
  """
  @spec execute(t(), map(), map()) :: {:ok, result()} | {:error, term()}
  def execute(engine, envelope, requirements) when is_map(envelope) and is_map(requirements) do
    with :ok <- route(engine, requirements),
         {:ok, id} <- request_id(envelope, requirements),
         {:ok, existing} <- Journal.fetch(engine.journal, id) do
      execute_entry(engine, id, existing, envelope, requirements)
    end
  end

  @doc since: "0.9.0"
  @doc """
  Reconciles the active transaction without signing or sending anything.

  An idle journal performs no RPC. Prepared but undispatched work remains
  pending; this conservative recovery path never assumes an interrupted caller
  relinquished permission to continue.
  """
  @spec reconcile(t()) :: {:ok, result() | nil} | {:error, term()}
  def reconcile(engine) do
    with {:ok, entry} <- Journal.active(engine.journal) do
      reconcile_active(engine, entry)
    end
  end

  @doc since: "0.9.0"
  @doc "Releases a finished scope after the caller durably mirrors its payment effects."
  @spec acknowledge(t(), binary()) :: {:ok, result()} | {:error, term()}
  def acknowledge(engine, id) do
    with {:ok, entry} <- Journal.fetch(engine.journal, id) do
      acknowledge_entry(engine, entry)
    end
  end

  @spec execute_entry(t(), binary(), Journal.entry() | nil, map(), map()) ::
          {:ok, result()} | {:error, term()}
  defp execute_entry(engine, id, nil, envelope, requirements) do
    with {:ok, proof} <- verify(engine, envelope, requirements),
         :ok <- single_leg(proof),
         {:ok, event} <- Receipt.expected_event(proof),
         intent = %{
           envelope: envelope,
           requirements: requirements,
           proof: proof,
           event: event,
           from: engine.address,
           to: proof.target
         },
         {:ok, reservation} <- Journal.reserve(engine.journal, id, intent) do
      execute_reserved(engine, reservation)
    end
  end

  defp execute_entry(engine, id, %{phase: :cancelled}, envelope, requirements),
    do: execute_entry(engine, id, nil, envelope, requirements)

  defp execute_entry(engine, _id, entry, _envelope, _requirements),
    do: reconcile_entry(engine, entry)

  @spec execute_reserved(t(), {:reserved | :existing, Journal.entry()}) ::
          {:ok, result()} | {:error, term()}
  defp execute_reserved(engine, {:existing, entry}), do: reconcile_entry(engine, entry)

  defp execute_reserved(engine, {:reserved, entry}) do
    case signed_transaction(engine, entry) do
      {:ok, raw} ->
        freeze_and_send(engine, entry, raw)

      {:error, reason} ->
        case Journal.cancel_preparation(engine.journal, entry.id, entry.owner) do
          {:ok, _cancelled} -> {:error, reason}
          {:error, error} -> {:error, {:preparation_uncertain, error}}
        end
    end
  end

  @spec freeze_and_send(t(), Journal.entry(), binary()) :: {:ok, result()} | {:error, term()}
  defp freeze_and_send(engine, entry, raw) do
    with {:ok, prepared} <- Journal.prepare(engine.journal, entry.id, entry.owner, raw),
         {:ok, _proof} <- verify(engine, entry.intent.envelope, entry.intent.requirements),
         {:ok, dispatched} <- Journal.dispatch(engine.journal, prepared.id, prepared.owner) do
      # Every send outcome is potentially delivered; receipt identity is local.
      RPC.request(engine.rpc, "eth_sendRawTransaction", [hex(dispatched.transaction.raw)])
      reconcile_entry(engine, dispatched)
    end
  end

  @spec signed_transaction(t(), Journal.entry()) :: {:ok, binary()} | {:error, term()}
  defp signed_transaction(engine, entry) do
    call = %{
      "from" => engine.address,
      "to" => entry.intent.to,
      "data" => hex(entry.intent.proof.calldata),
      "value" => "0x0"
    }

    with {:ok, nonce_hex} <-
           RPC.request(engine.rpc, "eth_getTransactionCount", [engine.address, "pending"]),
         {:ok, nonce} <- RPC.decode_quantity(nonce_hex),
         {:ok, gas_hex} <- RPC.request(engine.rpc, "eth_estimateGas", [call]),
         {:ok, gas} <- RPC.decode_quantity(gas_hex),
         :ok <- within_gas_limit(gas, engine.options[:gas_limit]),
         transaction = %Transaction{
           chain_id: engine.chain_id,
           nonce: nonce,
           max_fee_per_gas: engine.options[:max_fee_per_gas],
           max_priority_fee_per_gas: engine.options[:max_priority_fee_per_gas],
           gas_limit: engine.options[:gas_limit],
           to: entry.intent.to,
           data: entry.intent.proof.calldata
         },
         {:ok, signature} <- Signer.sign_transaction(engine.signer, transaction),
         {:ok, digest} <- Transaction.digest(transaction),
         {:ok, recovered} <- EIP3009.recover_signer(digest, signature),
         :ok <- same_sender(recovered, engine.address) do
      Transaction.encode_signed(transaction, signature)
    end
  end

  @doc since: "0.9.0"
  @doc "Performs full, read-only verification with this executor's bound submission policy."
  @spec verify(t(), map(), map()) :: {:ok, Verify.verification()} | {:error, term()}
  def verify(engine, envelope, requirements) do
    with :ok <- route(engine, requirements),
         {:ok, _id} <- request_id(envelope, requirements),
         {:ok, now} <- now(engine),
         {:ok, operation} <- AuthCapture.operation(envelope, requirements),
         {:ok, funded?} <- refund_authorized(engine, operation, envelope, requirements, now) do
      Verify.verify(envelope, requirements, verify_opts(engine, now) ++ [refund_funding: funded?])
    end
  end

  @doc false
  @spec identify(t(), map(), map()) :: {:ok, String.t()} | {:error, term()}
  def identify(engine, envelope, requirements) do
    with :ok <- route(engine, requirements),
         {:ok, _id} <- request_id(envelope, requirements),
         {:ok, now} <- now(engine),
         {:ok, proof} <-
           Verify.verify(
             envelope,
             requirements,
             Keyword.put(verify_opts(engine, now), :level, :structural)
           ) do
      # This identity is unverified and may only reject an existing payment,
      # never authorize a handler, expose stored output or bypass verification.
      EVM.payment_info_hash(proof.chain_id, proof.deployment.escrow, proof.payment_info)
    end
  end

  @doc since: "0.9.0"
  @doc """
  Verifies a pre-signed lifecycle consent without requiring its future escrow state.

  This establishes signature-level authorization only. Execution always repeats
  full verification. Used to validate the retained void before funding a hold.
  """
  @spec verify_consent(t(), map(), map()) :: {:ok, Verify.verification()} | {:error, term()}
  def verify_consent(engine, envelope, requirements) do
    with :ok <- route(engine, requirements),
         {:ok, _id} <- request_id(envelope, requirements),
         {:ok, now} <- now(engine) do
      Verify.verify_consent(envelope, requirements, verify_opts(engine, now))
    end
  end

  @doc since: "0.9.0"
  @doc "Checks a current, unconsumed hold and remaining service deadline before handler admission."
  @spec verify_hold(t(), map(), map(), pos_integer()) :: :ok | {:error, term()}
  def verify_hold(engine, void, requirements, maximum) do
    with {:ok, proof} <- verify(engine, void, requirements),
         {:ok, now} <- now(engine),
         :ok <- AuthCapture.check_deadlines(requirements, now: now),
         true <-
           proof.operation == :void and proof.payment_state.collected? and
             proof.payment_state.capturable_amount == maximum and
             proof.payment_state.refundable_amount == 0 do
      :ok
    else
      false -> {:error, :unexpected_payment_state}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec verify_opts(t(), non_neg_integer()) :: keyword()
  defp verify_opts(engine, now),
    do: [
      rpc: engine.rpc,
      level: :full,
      now: now,
      settlement: true,
      submitters: [engine.address],
      eip6492_allowed_factories: engine.options[:eip6492_allowed_factories]
    ]

  @spec refund_authorized(t(), atom(), map(), map(), non_neg_integer()) ::
          {:ok, boolean()} | {:error, term()}
  defp refund_authorized(engine, :refund, envelope, requirements, now) do
    with callback when is_function(callback, 3) <- engine.options[:refund_authorize],
         {:ok, proof} <-
           Verify.verify_consent(
             envelope,
             requirements,
             verify_opts(engine, now) ++ [refund_funding: true]
           ),
         :ok <- callback.(proof, envelope, requirements) do
      {:ok, true}
    else
      _rejected -> {:error, :refund_funding_not_authorized}
    end
  catch
    _kind, _reason -> {:error, :refund_funding_not_authorized}
  end

  defp refund_authorized(_engine, _operation, _envelope, _requirements, _now), do: {:ok, false}

  @spec reconcile_active(t(), Journal.entry() | nil) :: {:ok, result() | nil} | {:error, term()}
  defp reconcile_active(_engine, nil), do: {:ok, nil}

  defp reconcile_active(engine, entry), do: reconcile_entry(engine, entry)

  @spec reconcile_entry(t(), Journal.entry()) :: {:ok, result()} | {:error, term()}
  defp reconcile_entry(engine, %{phase: :dispatched} = entry) do
    with :ok <- check_chain(engine) do
      case RPC.request(engine.rpc, "eth_getTransactionReceipt", [entry.transaction.hash]) do
        {:ok, receipt} when is_map(receipt) -> confirm_receipt(engine, entry, receipt)
        _pending -> {:ok, result(entry)}
      end
    end
  end

  defp reconcile_entry(_engine, %{phase: :cancelled}), do: {:error, :preparation_cancelled}
  defp reconcile_entry(_engine, entry), do: {:ok, result(entry)}

  @spec confirm_receipt(t(), Journal.entry(), map()) :: {:ok, result()} | {:error, term()}
  defp confirm_receipt(engine, entry, receipt) do
    identity = %{hash: entry.transaction.hash, from: entry.intent.from, to: entry.intent.to}

    with {:ok, inclusion} <- Receipt.check(receipt, identity, entry.intent.event),
         :ok <- canonical_confirmation(engine, inclusion),
         {:ok, finished} <-
           Journal.finish(engine.journal, entry.id, entry.owner, inclusion.outcome, receipt) do
      {:ok, result(finished)}
    else
      {:error, :not_confirmed} -> {:ok, result(entry)}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec canonical_confirmation(t(), Receipt.inclusion()) :: :ok | {:error, term()}
  defp canonical_confirmation(engine, inclusion) do
    with {:ok, head_hex} <- RPC.request(engine.rpc, "eth_blockNumber", []),
         {:ok, head} <- RPC.decode_quantity(head_hex),
         true <- head - inclusion.block_number + 1 >= engine.options[:confirmations],
         {:ok, %{"hash" => hash, "number" => number}} <-
           RPC.request(engine.rpc, "eth_getBlockByNumber", [
             quantity(inclusion.block_number),
             false
           ]),
         {:ok, block_number} <- RPC.decode_quantity(number),
         true <- block_number == inclusion.block_number,
         true <- is_binary(hash) and String.downcase(hash) == inclusion.block_hash do
      :ok
    else
      _unconfirmed -> {:error, :not_confirmed}
    end
  end

  @spec acknowledge_entry(t(), Journal.entry() | nil) :: {:ok, result()} | {:error, term()}
  defp acknowledge_entry(_engine, nil), do: {:error, :unknown_operation}

  defp acknowledge_entry(_engine, %{phase: phase} = entry) when phase in [:succeeded, :failed],
    do: {:ok, result(entry)}

  defp acknowledge_entry(engine, entry) do
    with {:ok, final} <- Journal.acknowledge(engine.journal, entry.id, entry.owner),
         do: {:ok, result(final)}
  end

  @spec result(Journal.entry()) :: result()
  defp result(entry) do
    proof = entry.intent.proof

    %{
      id: entry.id,
      status: status(entry.phase),
      transaction: entry.transaction && entry.transaction.hash,
      operation: proof.operation,
      payer: proof.payer,
      amount: result_amount(proof),
      payment_info_hash: proof.payment_info_hash,
      receipt: entry.receipt
    }
  end

  @spec result_amount(Verify.verification()) :: non_neg_integer()
  defp result_amount(%{operation: :void, payment_state: state}), do: state.capturable_amount
  defp result_amount(proof), do: proof.amount

  @spec status(atom()) :: :pending | :confirmed | :reverted
  defp status(phase) when phase in [:confirmed, :succeeded], do: :confirmed
  defp status(phase) when phase in [:reverted, :failed], do: :reverted
  defp status(_phase), do: :pending

  @spec request_id(map(), map()) :: {:ok, binary()} | {:error, atom()}
  defp request_id(envelope, requirements) do
    request = {envelope, requirements}

    if :erlang.external_size(request) <= 262_144,
      do:
        {:ok,
         Base.encode16(
           :crypto.hash(
             :sha256,
             :erlang.term_to_binary(request, [:deterministic])
           ),
           case: :lower
         )},
      else: {:error, :request_too_large}
  end

  @spec route(t(), map()) :: :ok | {:error, atom()}
  defp route(engine, requirements) do
    if Utils.map_value(requirements, {"network", :network}) == engine.network,
      do: :ok,
      else: {:error, :network_mismatch}
  end

  @spec check_chain(t()) :: :ok | {:error, term()}
  defp check_chain(engine) do
    with {:ok, hex} <- RPC.chain_id(engine.rpc),
         {:ok, chain} <- RPC.decode_quantity(hex) do
      if chain == engine.chain_id, do: :ok, else: {:error, :chain_id_mismatch}
    end
  end

  @spec single_leg(Verify.verification()) :: :ok | {:error, atom()}
  defp single_leg(%{void_calldata: nil}), do: :ok
  defp single_leg(_proof), do: {:error, :multi_leg_requires_orchestration}

  @spec now(t()) :: {:ok, non_neg_integer()} | {:error, atom()}
  defp now(engine) do
    case engine.options[:clock].() do
      value when is_integer(value) and value >= 0 -> {:ok, value}
      _invalid -> {:error, :invalid_clock}
    end
  end

  @spec within_gas_limit(non_neg_integer(), pos_integer()) :: :ok | {:error, atom()}
  defp within_gas_limit(gas, limit) when gas > 0 and gas <= limit, do: :ok
  defp within_gas_limit(_gas, _limit), do: {:error, :gas_limit_exceeded}

  @spec same_sender(String.t(), String.t()) :: :ok | {:error, atom()}
  defp same_sender(recovered, expected) do
    if String.downcase(recovered) == expected, do: :ok, else: {:error, :signer_mismatch}
  end

  @spec fee_bounds(keyword()) :: :ok | {:error, atom()}
  defp fee_bounds(opts) do
    if opts[:max_priority_fee_per_gas] <= opts[:max_fee_per_gas] and
         Enum.all?(
           Keyword.take(opts, [:max_fee_per_gas, :max_priority_fee_per_gas, :gas_limit]),
           fn {_key, value} -> match?({:ok, _}, EVM.parse_uint256(value)) end
         ), do: :ok, else: {:error, :invalid_gas_policy}
  end

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)
  @spec quantity(non_neg_integer()) :: String.t()
  defp quantity(value), do: "0x" <> Integer.to_string(value, 16)
end
