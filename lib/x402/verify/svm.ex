defmodule X402.Verify.SVM do
  @moduledoc """
  Local verification of SVM `exact` payment payloads.

  Runs the facilitator verify checklist from the exact-SVM scheme
  specification's *static verification path* (Path 1), mirroring the
  reference TypeScript facilitator check for check: scheme/network match,
  fee-payer requirements, transaction decoding, **local Ed25519 verification
  of every required signer except the fee payer**, the static instruction
  whitelist (via `X402.Scheme.ExactSVM`'s pre-checks), and — at `:full` —
  an RPC `simulateTransaction` round-trip.

  Smart-wallet (CPI-wrapped) payments — the spec's opt-in Path 2 — are out
  of scope and fail the static checks, and transactions using address
  lookup tables are rejected fail-closed (their account set cannot be
  verified without table resolution).

  ## Verification levels

  The `:level` option is required and explicit — a level whose capabilities
  are unavailable returns an error instead of silently downgrading:

  * `:structural` — no RPC: scheme, network, and fee-payer requirements;
    transaction decoding; Ed25519 signature verification of the required
    signers (pure `:crypto`, no optional dependency); the address-lookup-
    table rejection; and the static instruction-layout checks against the
    requirements (amount, mint, destination ATA, memo, compute budget
    bounds, fee-payer isolation).

  * `:full` — everything in `:structural`, plus `simulateTransaction` over
    a configured `X402.RPC` endpoint (otherwise
    `{:error, :rpc_not_configured}`). The simulation runs with
    `sigVerify: false` — the fee-payer slot is unsigned until settlement —
    which is exactly why the local signature checks above are mandatory at
    every level.

  ## Example

      {:ok, payload} = X402.PaymentSignature.decode_and_validate(header, requirements)

      {:ok, rpc} = X402.RPC.new(rpc_url: "https://api.devnet.solana.com", finch: MyApp.Finch)

      case X402.Verify.SVM.verify(payload, requirements,
             level: :full,
             rpc: rpc,
             fee_payer: facilitator_address
           ) do
        {:ok, %{payer: payer}} -> grant_access(payer)
        {:error, _reason} -> deny_access()
      end

  `payer` is the Base58 authority of the `TransferChecked` instruction —
  the account whose tokens move. The result never silently downgrades:
  `{:ok, result}` means the payment passed every check the stated `:level`
  includes, and `result.level` echoes that level.
  """

  alias X402.Base58
  alias X402.RPC
  alias X402.Solana
  alias X402.Solana.Transaction
  alias X402.Telemetry
  alias X402.Utils

  @typedoc "Requested verification depth."
  @type level :: :structural | :full

  @typedoc """
  A successful verification.

  `payer` is the Base58 `TransferChecked` authority. `level` echoes the
  level that was run.
  """
  @type verification :: %{payer: String.t(), level: level()}

  @typedoc """
  Why a payment was rejected.

  Reasons map onto the canonical cross-SDK `invalidReason` strings via
  `reason_string/1` where an equivalent exists.
  """
  @type invalid_reason ::
          :invalid_payload
          | :unsupported_scheme
          | :network_mismatch
          | :missing_fee_payer
          | :fee_payer_not_managed
          | :transaction_could_not_be_decoded
          | :fee_payer_mismatch
          | :excessive_signers
          | :signature_invalid
          | :alt_resolution_not_available
          | :instruction_count
          | :invalid_compute_limit_instruction
          | :invalid_compute_price_instruction
          | :compute_price_too_high
          | :missing_transfer_instruction
          | :fee_payer_not_isolated
          | :amount_mismatch
          | :mint_mismatch
          | :recipient_mismatch
          | :unknown_optional_instruction
          | :memo_count
          | :memo_mismatch
          | :verification_failed
          | :simulation_failed

  @typedoc "Verification errors."
  @type error ::
          {:invalid, invalid_reason()}
          | :rpc_not_configured
          | {:rpc_error, RPC.error()}

  # Precheck failures with a dedicated reason string; anything else the
  # scheme's static checks report collapses to :verification_failed.
  @precheck_reasons [
    :instruction_count,
    :invalid_compute_limit_instruction,
    :invalid_compute_price_instruction,
    :compute_price_too_high,
    :missing_transfer_instruction,
    :fee_payer_not_isolated,
    :amount_mismatch,
    :mint_mismatch,
    :recipient_mismatch,
    :unknown_optional_instruction,
    :memo_count,
    :memo_mismatch
  ]

  @verify_opts_schema [
    level: [
      type: {:in, [:structural, :full]},
      required: true,
      doc: """
      Verification depth. `:structural` needs no RPC; `:full` additionally
      simulates the transaction (requires `:rpc` unless `simulate: false`).
      A level never silently downgrades.
      """
    ],
    fee_payer: [
      type: :string,
      required: true,
      doc: """
      The facilitator-managed fee-payer address (Base58). The requirements'
      `extra.feePayer` must equal it — a facilitator must never co-sign a
      transaction whose fee payer it does not control.
      """
    ],
    rpc: [
      type: {:custom, RPC, :validate_config, []},
      doc: "An `X402.RPC` configuration. Required for level `:full` with simulation."
    ],
    simulate: [
      type: :boolean,
      default: true,
      doc: "Whether level `:full` runs `simulateTransaction`."
    ],
    max_required_signatures: [
      type: {:or, [nil, :pos_integer]},
      default: nil,
      doc: """
      Cap on the transaction's required signature count (every signature
      adds 5000 lamports of base fee, paid by the facilitator). `nil`
      disables the cap. A typical x402 payment needs two.
      """
    ],
    commitment: [
      type: :string,
      default: "confirmed",
      doc: "Commitment level for the simulation."
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
  fails, and `{:error, :rpc_not_configured}` when the level cannot run —
  never a silent downgrade. RPC transport failures return
  `{:error, {:rpc_error, reason}}` (fail closed: the payment is not proven
  valid).

  ## Options

  #{NimbleOptions.docs(@verify_opts_schema)}

  ## Examples

      iex> X402.Verify.SVM.verify(%{"x402Version" => 2}, %{},
      ...>   level: :structural,
      ...>   fee_payer: "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
      ...> )
      {:error, {:invalid, :invalid_payload}}
  """
  @spec verify(map(), map(), keyword()) :: {:ok, verification()} | {:error, error()}
  def verify(payment_payload, requirements, opts)
      when is_map(payment_payload) and is_map(requirements) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @verify_opts_schema)
    level = Keyword.fetch!(opts, :level)

    case do_verify(payment_payload, requirements, level, opts) do
      {:ok, result} ->
        Telemetry.emit(:verify, :svm, :ok, %{level: level})
        {:ok, result}

      {:error, reason} ->
        Telemetry.emit(:verify, :svm, :error, %{level: level, reason: reason})
        {:error, reason}
    end
  end

  @doc since: "0.6.0", group: :verification
  @doc """
  Maps an `invalid` reason atom to the canonical cross-SDK `invalidReason`
  string used by the reference facilitators.

  The vocabulary is the TypeScript reference's `invalid_exact_svm_*` set —
  the strings the hosted facilitator emits. (The Go SDK currently diverges
  with an `invalid_exact_solana_*` prefix despite its cross-SDK parity
  comment; TypeScript is authoritative here.) Local-only reasons without a
  canonical wire equivalent fall back to their atom name.

  ## Examples

      iex> X402.Verify.SVM.reason_string(:amount_mismatch)
      "invalid_exact_svm_payload_amount_mismatch"

      iex> X402.Verify.SVM.reason_string(:fee_payer_mismatch)
      "invalid_exact_svm_fee_payer_mismatch"

      iex> X402.Verify.SVM.reason_string(:invalid_payload)
      "invalid_payload"
  """
  @spec reason_string(invalid_reason()) :: String.t()
  def reason_string(reason) when is_atom(reason) do
    Map.get(reason_strings(), reason, Atom.to_string(reason))
  end

  @spec reason_strings() :: %{invalid_reason() => String.t()}
  defp reason_strings do
    %{
      unsupported_scheme: "invalid_exact_svm_unsupported_scheme",
      network_mismatch: "invalid_exact_svm_network_mismatch",
      missing_fee_payer: "invalid_exact_svm_payload_missing_fee_payer",
      fee_payer_not_managed: "invalid_exact_svm_fee_payer_not_managed_by_facilitator",
      transaction_could_not_be_decoded:
        "invalid_exact_svm_payload_transaction_could_not_be_decoded",
      fee_payer_mismatch: "invalid_exact_svm_fee_payer_mismatch",
      excessive_signers: "invalid_exact_svm_payload_excessive_signers",
      signature_invalid: "invalid_exact_svm_payload_signature_invalid",
      alt_resolution_not_available: "invalid_exact_svm_smart_wallet_alt_resolution_not_available",
      instruction_count: "invalid_exact_svm_payload_transaction_instructions_length",
      invalid_compute_limit_instruction:
        "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
      invalid_compute_price_instruction:
        "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
      compute_price_too_high:
        "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
      missing_transfer_instruction: "invalid_exact_svm_payload_no_transfer_instruction",
      fee_payer_not_isolated:
        "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
      amount_mismatch: "invalid_exact_svm_payload_amount_mismatch",
      mint_mismatch: "invalid_exact_svm_payload_mint_mismatch",
      recipient_mismatch: "invalid_exact_svm_payload_recipient_mismatch",
      unknown_optional_instruction: "invalid_exact_svm_payload_unknown_optional_instruction",
      memo_count: "invalid_exact_svm_payload_memo_count",
      memo_mismatch: "invalid_exact_svm_payload_memo_mismatch",
      verification_failed: "invalid_exact_svm_verification_failed",
      simulation_failed: "invalid_exact_svm_transaction_simulation_failed"
    }
  end

  # -- Pipeline ---------------------------------------------------------------

  @spec do_verify(map(), map(), level(), keyword()) ::
          {:ok, verification()} | {:error, error()}
  defp do_verify(payment_payload, requirements, level, opts) do
    with {:ok, ctx} <- build_context(payment_payload, requirements, opts),
         :ok <- check_signatures(ctx),
         :ok <- check_lookups(ctx),
         :ok <- run_precheck(payment_payload, requirements),
         :ok <- maybe_simulate(ctx, level, opts) do
      {:ok, %{payer: transfer_authority(ctx.decoded), level: level}}
    end
  end

  # -- Checks 1–7: envelope, routing, fee payer, decoding ---------------------

  @spec build_context(map(), map(), keyword()) :: {:ok, map()} | {:error, error()}
  defp build_context(payment_payload, requirements, opts) do
    accepted = Utils.map_value(payment_payload, {"accepted", :accepted})
    scheme_payload = Utils.map_value(payment_payload, {"payload", :payload})

    with :ok <- ensure_maps(accepted, scheme_payload),
         :ok <- check_scheme(accepted, requirements),
         :ok <- check_network(accepted, requirements),
         {:ok, fee_payer} <- required_fee_payer(requirements),
         :ok <- check_fee_payer_managed(fee_payer, opts),
         {:ok, transaction_base64, decoded} <- decode_transaction(scheme_payload),
         :ok <- check_fee_payer_account(decoded, fee_payer),
         :ok <- check_signer_cap(decoded, opts) do
      {:ok, %{decoded: decoded, transaction_base64: transaction_base64}}
    end
  end

  @spec ensure_maps(term(), term()) :: :ok | {:error, {:invalid, :invalid_payload}}
  defp ensure_maps(accepted, scheme_payload)
       when is_map(accepted) and is_map(scheme_payload),
       do: :ok

  defp ensure_maps(_accepted, _scheme_payload), do: {:error, {:invalid, :invalid_payload}}

  @spec check_scheme(map(), map()) :: :ok | {:error, {:invalid, :unsupported_scheme}}
  defp check_scheme(accepted, requirements) do
    accepted_scheme = Utils.map_value(accepted, {"scheme", :scheme})
    required_scheme = Utils.map_value(requirements, {"scheme", :scheme})

    case accepted_scheme == "exact" and required_scheme == "exact" do
      true -> :ok
      false -> {:error, {:invalid, :unsupported_scheme}}
    end
  end

  @spec check_network(map(), map()) :: :ok | {:error, {:invalid, :network_mismatch}}
  defp check_network(accepted, requirements) do
    accepted_network = Utils.map_value(accepted, {"network", :network})
    required_network = Utils.map_value(requirements, {"network", :network})

    case accepted_network == required_network and svm_network?(required_network) do
      true -> :ok
      false -> {:error, {:invalid, :network_mismatch}}
    end
  end

  @spec svm_network?(term()) :: boolean()
  defp svm_network?("solana:" <> reference), do: reference != ""
  defp svm_network?(_network), do: false

  @spec required_fee_payer(map()) :: {:ok, String.t()} | {:error, {:invalid, :missing_fee_payer}}
  defp required_fee_payer(requirements) do
    fee_payer =
      case Utils.map_value(requirements, {"extra", :extra}) do
        extra when is_map(extra) -> Utils.map_value(extra, {"feePayer", :fee_payer})
        _extra -> nil
      end

    case Solana.valid_address?(fee_payer) do
      true -> {:ok, fee_payer}
      false -> {:error, {:invalid, :missing_fee_payer}}
    end
  end

  @spec check_fee_payer_managed(String.t(), keyword()) ::
          :ok | {:error, {:invalid, :fee_payer_not_managed}}
  defp check_fee_payer_managed(fee_payer, opts) do
    case fee_payer == Keyword.fetch!(opts, :fee_payer) do
      true -> :ok
      false -> {:error, {:invalid, :fee_payer_not_managed}}
    end
  end

  @spec decode_transaction(map()) ::
          {:ok, String.t(), Transaction.decoded()}
          | {:error, {:invalid, :transaction_could_not_be_decoded}}
  defp decode_transaction(scheme_payload) do
    with transaction when is_binary(transaction) <-
           Utils.map_value(scheme_payload, {"transaction", :transaction}),
         {:ok, wire} <- Base.decode64(transaction),
         {:ok, decoded} <- Transaction.decode(wire) do
      {:ok, transaction, decoded}
    else
      _error -> {:error, {:invalid, :transaction_could_not_be_decoded}}
    end
  end

  @spec check_fee_payer_account(Transaction.decoded(), String.t()) ::
          :ok | {:error, {:invalid, :fee_payer_mismatch}}
  defp check_fee_payer_account(decoded, fee_payer) do
    {:ok, expected} = Solana.decode_address(fee_payer)

    case decoded.static_accounts do
      [^expected | _rest] -> :ok
      _mismatch -> {:error, {:invalid, :fee_payer_mismatch}}
    end
  end

  @spec check_signer_cap(Transaction.decoded(), keyword()) ::
          :ok | {:error, {:invalid, :excessive_signers}}
  defp check_signer_cap(decoded, opts) do
    case Keyword.fetch!(opts, :max_required_signatures) do
      nil ->
        :ok

      cap when decoded.num_required_signatures <= cap ->
        :ok

      _cap ->
        {:error, {:invalid, :excessive_signers}}
    end
  end

  # -- Check 8: local Ed25519 verification -------------------------------------

  # Slot 0 is the fee payer, signed by the facilitator at settlement.
  # Simulation runs with sigVerify: false (that unsigned slot would fail it),
  # so this local check is mandatory — without it a forged payload would pass
  # simulation and only the broadcast would reject it.
  @spec check_signatures(map()) :: :ok | {:error, {:invalid, :signature_invalid}}
  defp check_signatures(%{decoded: decoded}) do
    1..(decoded.num_required_signatures - 1)//1
    |> Enum.all?(fn index ->
      valid_signature?(
        decoded.message_bytes,
        Enum.at(decoded.signatures, index),
        Enum.at(decoded.static_accounts, index)
      )
    end)
    |> case do
      true -> :ok
      false -> {:error, {:invalid, :signature_invalid}}
    end
  end

  @spec valid_signature?(binary(), term(), term()) :: boolean()
  defp valid_signature?(message, <<signature::binary-size(64)>>, <<pubkey::binary-size(32)>>),
    do: :crypto.verify(:eddsa, :none, message, signature, [pubkey, :ed25519])

  defp valid_signature?(_message, _signature, _pubkey), do: false

  # -- Check 9: address lookup tables ------------------------------------------

  # Fail closed: the lookup tables' contents are not resolved locally, so the
  # account set of an ALT transaction cannot be verified. ALT resolution is a
  # documented non-goal for now (the reference's smart-wallet path).
  @spec check_lookups(map()) :: :ok | {:error, {:invalid, :alt_resolution_not_available}}
  defp check_lookups(%{decoded: %{address_table_lookups: 0}}), do: :ok
  defp check_lookups(_ctx), do: {:error, {:invalid, :alt_resolution_not_available}}

  # -- Check 10: static instruction layout -------------------------------------

  # Dispatched through the public X402.Scheme behaviour rather than the
  # scheme module directly; ALT transactions never reach this (the scheme's
  # precheck passes them through, but check 9 already rejected them).
  @spec run_precheck(map(), map()) :: :ok | {:error, {:invalid, invalid_reason()}}
  defp run_precheck(payment_payload, requirements) do
    case X402.Scheme.precheck(X402.Scheme.ExactSVM, payment_payload, requirements, []) do
      :ok -> :ok
      {:error, {:precheck_failed, reason}} -> {:error, {:invalid, map_precheck_reason(reason)}}
      {:error, _other} -> {:error, {:invalid, :verification_failed}}
    end
  end

  @spec map_precheck_reason(atom()) :: invalid_reason()
  defp map_precheck_reason(reason) when reason in @precheck_reasons, do: reason
  defp map_precheck_reason(_other), do: :verification_failed

  # -- Check 11: simulation (level :full) ---------------------------------------

  @spec maybe_simulate(map(), level(), keyword()) :: :ok | {:error, error()}
  defp maybe_simulate(_ctx, :structural, _opts), do: :ok

  defp maybe_simulate(ctx, :full, opts) do
    case Keyword.fetch!(opts, :simulate) do
      true ->
        with {:ok, rpc} <- fetch_rpc(opts) do
          simulate(rpc, ctx, opts)
        end

      false ->
        :ok
    end
  end

  @spec fetch_rpc(keyword()) :: {:ok, RPC.t()} | {:error, :rpc_not_configured}
  defp fetch_rpc(opts) do
    case Keyword.get(opts, :rpc) do
      %RPC{} = rpc -> {:ok, rpc}
      nil -> {:error, :rpc_not_configured}
    end
  end

  # Simulates the ORIGINAL base64 payload — the exact bytes settlement would
  # co-sign and broadcast.
  @spec simulate(RPC.t(), map(), keyword()) :: :ok | {:error, error()}
  defp simulate(rpc, ctx, opts) do
    commitment = Keyword.fetch!(opts, :commitment)

    case Solana.RPC.simulate_transaction(rpc, ctx.transaction_base64, commitment: commitment) do
      {:ok, %{err: nil}} -> :ok
      {:ok, %{err: _err}} -> {:error, {:invalid, :simulation_failed}}
      {:error, reason} -> {:error, {:rpc_error, reason}}
    end
  end

  # -- Helpers ------------------------------------------------------------------

  # The TransferChecked accounts are [source, mint, destination, authority];
  # the static precheck guaranteed instruction 2 carries that layout.
  @spec transfer_authority(Transaction.decoded()) :: String.t()
  defp transfer_authority(decoded) do
    transfer = Enum.at(decoded.instructions, 2)
    authority_index = Enum.at(transfer.account_indices, 3)

    decoded.static_accounts
    |> Enum.at(authority_index)
    |> Base58.encode()
  end
end
