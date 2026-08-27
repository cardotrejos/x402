defmodule X402.Scheme.ExactSVM do
  @moduledoc """
  Built-in `X402.Scheme` for `exact` payments on Solana (`solana:*`) networks.

  Follows the x402 `exact` SVM scheme specification: the client builds a
  **version 0** Solana transaction with the reference instruction layout —

  1. Compute Budget `SetComputeUnitLimit`
  2. Compute Budget `SetComputeUnitPrice`
  3. SPL Token / Token-2022 `TransferChecked` to the Associated Token
     Account derived from `payTo` and `asset`
  4. SPL Memo (the seller's `extra.memo`, or a random nonce for
     transaction uniqueness)

  — signs it with the payer's Ed25519 key, and leaves the fee payer's
  signature slot as a 64-byte zero placeholder (a *partially signed*
  transaction). The wire payload is `%{"transaction" => base64}`, exactly
  as the reference TypeScript and Python clients produce.

  ## Roles

  * **Client** — `sign/3` builds and partially signs the transaction. The
    signer must implement the optional `c:X402.Signer.sign_ed25519/2`
    callback (`X402.Signer.SolanaKey` does). An entry is signable when
    `extra.feePayer` is present: the sponsor's public key is **required**
    (it becomes account 0 / the empty signature slot).
  * **Server** — `validate_payload/3` runs structural checks that any
    valid `exact` SVM payment must satisfy (decodable Base64, the 1232-byte
    transaction size cap, a parseable v0/legacy transaction, fee payer
    match). `precheck/3` additionally enforces the facilitator's *static
    verification path* whitelist (spec §3.1): 3–7 instructions in the
    reference order, compute-budget bounds, fee payer isolation, transfer
    semantics against the requirements, and memo enforcement.

  **On-chain verification and settlement remain facilitator-delegated**:
  this module never talks to a Solana RPC node. The facilitator resolves
  address lookup tables, simulates, signs as `feePayer`, and submits
  (spec §2–3). Transactions using address lookup tables skip `precheck/3`
  (the account set cannot be resolved locally) and are left to the
  facilitator, and smart-wallet (CPI-wrapped) payments — the spec's opt-in
  Path 2 — will fail the static-path pre-checks; gates fronting a
  facilitator with `enableSmartWalletVerification` should disable
  `:local_prechecks` for those routes.

  ## Client options

  `sign/3` honors these `X402.Client.build_payment/3` options:

  * `:svm_blockhash` — a Base58 recent blockhash for the transaction
    lifetime. Used when the requirements' `extra.recentBlockhash` hint is
    absent or malformed; keeps the module RPC-free.
  * `:svm_blockhash_fetcher` — a 1-arity fun receiving the CAIP-2 network
    and returning `{:ok, blockhash}` (for example a wrapper around your
    RPC client's `getLatestBlockhash`). Consulted after `:svm_blockhash`.
  * `:svm_decimals` / `:svm_token_program` — the mint's decimals and
    owning token program, needed by `TransferChecked`. Defaults come from
    the reference SDKs' known-asset table (USDC, USDT, USDG, PYUSD, CASH);
    for other mints pass both explicitly (production clients read them
    from the mint account via RPC).

  Blockhash resolution order (per the spec): a valid
  `extra.recentBlockhash` from the server wins, then `:svm_blockhash`,
  then `:svm_blockhash_fetcher`; with none, `{:error, :missing_blockhash}`.
  """

  @behaviour X402.Scheme

  alias X402.Signer
  alias X402.Solana
  alias X402.Solana.Transaction
  alias X402.Utils

  # Reference client defaults (typescript/packages/mechanisms/svm constants).
  @default_compute_unit_limit 20_000
  @default_compute_unit_price_microlamports 1
  # Static-path cap: 5 lamports per compute unit (spec §3.1).
  @max_compute_unit_price_microlamports 5_000_000
  @max_memo_bytes 256
  @nonce_bytes 16
  @u64_max 0xFFFFFFFFFFFFFFFF

  # Known mints from the reference SDKs' default-asset tables
  # (mainnet/devnet/testnet). Mint addresses are globally unique, so the
  # table is keyed by mint alone: {decimals, token_program}.
  @known_assets %{
    # USDC (mainnet)
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => {6, :token},
    # USDT (mainnet)
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => {6, :token},
    # USDG (mainnet)
    "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH" => {6, :token_2022},
    # PYUSD (mainnet)
    "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo" => {6, :token_2022},
    # CASH (mainnet)
    "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH" => {6, :token_2022},
    # USDC (devnet/testnet)
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" => {6, :token},
    # USDG (devnet/testnet)
    "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7" => {6, :token_2022},
    # PYUSD (devnet/testnet)
    "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM" => {6, :token_2022}
  }

  @typedoc "Reasons `precheck/3` fails fast with `{:error, {:precheck_failed, reason}}`."
  @type precheck_failure ::
          :invalid_transaction
          | :fee_payer_not_isolated
          | :instruction_count
          | :invalid_compute_limit_instruction
          | :invalid_compute_price_instruction
          | :compute_price_too_high
          | :missing_transfer_instruction
          | :amount_mismatch
          | :mint_mismatch
          | :recipient_mismatch
          | :unknown_optional_instruction
          | :memo_count
          | :memo_mismatch

  @doc since: "0.6.0"
  @doc """
  Returns `"exact"`.

  ## Examples

      iex> X402.Scheme.ExactSVM.scheme()
      "exact"
  """
  @impl X402.Scheme
  @spec scheme() :: String.t()
  def scheme, do: "exact"

  @doc since: "0.6.0"
  @doc """
  Returns `["solana:*"]` — every Solana network.

  ## Examples

      iex> X402.Scheme.ExactSVM.networks()
      ["solana:*"]
  """
  @impl X402.Scheme
  @spec networks() :: [String.t()]
  def networks, do: ["solana:*"]

  @doc since: "0.6.0"
  @doc """
  Whether the entry carries the required sponsor data.

  `extra.feePayer` is required by the SVM `exact` scheme (the sponsor's
  public key becomes the transaction's fee payer), and `asset`/`payTo`
  must be valid Solana addresses.

  ## Examples

      iex> X402.Scheme.ExactSVM.signable?(%{
      ...>   "asset" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      ...>   "payTo" => "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse",
      ...>   "extra" => %{"feePayer" => "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"}
      ...> })
      true

      iex> X402.Scheme.ExactSVM.signable?(%{"extra" => %{}})
      false
  """
  @impl X402.Scheme
  @spec signable?(map()) :: boolean()
  def signable?(requirements) when is_map(requirements) do
    Solana.valid_address?(fee_payer(requirements)) and
      Solana.valid_address?(Utils.map_value(requirements, {"asset", :asset})) and
      Solana.valid_address?(Utils.map_value(requirements, {"payTo", :pay_to}))
  end

  def signable?(_requirements), do: false

  @doc since: "0.6.0"
  @doc """
  Builds and partially signs the SVM `exact` transaction.

  Returns `{:ok, %{"transaction" => base64}}` — the wire scheme payload —
  or a structured error: `{:error, :missing_fee_payer}` when the
  requirements lack `extra.feePayer`, `{:error, :missing_blockhash}` when
  no blockhash source is available, `{:error, {:unknown_asset, mint}}`
  for mints outside the known-asset table without explicit
  `:svm_decimals`/`:svm_token_program`, and `{:error, :unsupported_signer}`
  when the signer cannot sign Ed25519.
  """
  @impl X402.Scheme
  @spec sign(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(requirements, signer, opts) do
    asset = Utils.map_value(requirements, {"asset", :asset})
    pay_to = Utils.map_value(requirements, {"payTo", :pay_to})

    with {:ok, fee_payer} <- require_fee_payer(requirements),
         {:ok, payer} <- payer_address(signer),
         {:ok, amount} <- parse_amount(Utils.map_value(requirements, {"amount", :amount})),
         :ok <- validate_address(asset, :invalid_asset),
         :ok <- validate_address(pay_to, :invalid_pay_to),
         {:ok, decimals, token_program} <- resolve_asset(asset, opts),
         {:ok, blockhash} <- resolve_blockhash(requirements, opts),
         {:ok, memo_data} <- resolve_memo(requirements),
         {:ok, source_ata} <- Solana.associated_token_address(payer, asset, token_program),
         {:ok, dest_ata} <- Solana.associated_token_address(pay_to, asset, token_program),
         {:ok, compiled} <-
           compile_transfer(fee_payer, %{
             source: source_ata,
             mint: asset,
             destination: dest_ata,
             authority: payer,
             amount: amount,
             decimals: decimals,
             token_program: token_program,
             memo: memo_data,
             blockhash: blockhash
           }),
         {:ok, signature} <- Signer.sign_ed25519(signer, compiled.bytes) do
      wire = Transaction.serialize(compiled, %{payer => signature})
      {:ok, %{"transaction" => Base.encode64(wire)}}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Structural validation of a decoded `PAYMENT-SIGNATURE` payload.

  Checks what any valid `exact` SVM payment must satisfy without RPC:
  `payload.transaction` present, Base64-decodable, within the network's
  1232-byte transaction size cap, parseable as a v0 or legacy Solana
  transaction, and — when the requirements advertise `extra.feePayer` —
  carrying that fee payer as account 0. Failures return
  `{:error, {:invalid_scheme_payment, reason}}`.

  ## Examples

      iex> X402.Scheme.ExactSVM.validate_payload(%{"payload" => %{}}, %{}, [])
      {:error, {:invalid_scheme_payment, :missing_transaction}}

      iex> X402.Scheme.ExactSVM.validate_payload(
      ...>   %{"payload" => %{"transaction" => "!!!"}},
      ...>   %{},
      ...>   []
      ...> )
      {:error, {:invalid_scheme_payment, :invalid_base64}}
  """
  @impl X402.Scheme
  @spec validate_payload(map(), map(), keyword()) ::
          :ok | {:error, {:invalid_scheme_payment, atom()}}
  def validate_payload(payload, requirements, _opts) do
    with {:ok, wire} <- decode_wire(payload),
         {:ok, decoded} <- decode_transaction(wire) do
      validate_fee_payer(decoded, requirements)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Static-path pre-checks (spec §3.1) before the facilitator round-trip.

  Enforces the facilitator's static verification whitelist as far as it is
  verifiable without RPC: 3–7 top-level instructions in the reference
  order (`SetComputeUnitLimit`, `SetComputeUnitPrice`, `TransferChecked`,
  then only Lighthouse/Memo), the ≤ 5 lamports/CU priority-fee cap, fee
  payer isolation (§2.1.1 — the fee payer referenced by no instruction),
  transfer semantics against the requirements (amount equality, mint,
  destination ATA), and memo enforcement when `extra.memo` is present.

  Transactions using address lookup tables pass through with `:ok` — their
  account set cannot be resolved without RPC, so the facilitator remains
  the authority (§2.1.2). Failures return
  `{:error, {:precheck_failed, reason}}` and the gate answers 402 without
  a facilitator call.
  """
  @impl X402.Scheme
  @spec precheck(map(), map(), keyword()) ::
          :ok | {:error, {:precheck_failed, precheck_failure()}}
  def precheck(payload, requirements, _opts) do
    with {:ok, wire} <- precheck_wire(payload),
         {:ok, decoded} <- precheck_decode(wire) do
      case decoded.address_table_lookups do
        0 -> run_static_prechecks(decoded, requirements)
        _lookups -> :ok
      end
    end
  end

  # -- sign/3 internals -------------------------------------------------------

  @spec fee_payer(map()) :: term()
  defp fee_payer(requirements) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      extra when is_map(extra) -> Utils.map_value(extra, {"feePayer", :fee_payer})
      _extra -> nil
    end
  end

  @spec require_fee_payer(map()) :: {:ok, String.t()} | {:error, :missing_fee_payer}
  defp require_fee_payer(requirements) do
    case fee_payer(requirements) do
      fee_payer when is_binary(fee_payer) ->
        case Solana.valid_address?(fee_payer) do
          true -> {:ok, fee_payer}
          false -> {:error, :missing_fee_payer}
        end

      _missing ->
        {:error, :missing_fee_payer}
    end
  end

  @spec payer_address(Signer.t()) :: {:ok, String.t()} | {:error, term()}
  defp payer_address(signer) do
    with {:ok, address} <- Signer.address(signer) do
      case Solana.valid_address?(address) do
        true -> {:ok, address}
        false -> {:error, :invalid_payer_address}
      end
    end
  end

  @spec parse_amount(term()) :: {:ok, non_neg_integer()} | {:error, :invalid_amount}
  defp parse_amount(amount) when is_integer(amount) and amount >= 0 and amount <= @u64_max,
    do: {:ok, amount}

  defp parse_amount(amount) when is_binary(amount) do
    case Integer.parse(amount) do
      {value, ""} when value >= 0 and value <= @u64_max -> {:ok, value}
      _other -> {:error, :invalid_amount}
    end
  end

  defp parse_amount(_amount), do: {:error, :invalid_amount}

  @spec validate_address(term(), atom()) :: :ok | {:error, atom()}
  defp validate_address(address, error) do
    case Solana.valid_address?(address) do
      true -> :ok
      false -> {:error, error}
    end
  end

  @spec resolve_asset(String.t(), keyword()) ::
          {:ok, byte(), String.t()} | {:error, term()}
  defp resolve_asset(asset, opts) do
    case {Keyword.get(opts, :svm_decimals), Keyword.get(opts, :svm_token_program)} do
      {nil, nil} ->
        known_asset(asset)

      {nil, program} ->
        with {:ok, decimals, _default_program} <- known_asset(asset), do: {:ok, decimals, program}

      {decimals, nil} ->
        case known_asset(asset) do
          {:ok, _decimals, program} -> {:ok, decimals, program}
          {:error, _unknown} -> {:ok, decimals, Solana.token_program()}
        end

      {decimals, program} ->
        {:ok, decimals, program}
    end
  end

  @spec known_asset(String.t()) ::
          {:ok, byte(), String.t()} | {:error, {:unknown_asset, String.t()}}
  defp known_asset(asset) do
    case Map.fetch(@known_assets, asset) do
      {:ok, {decimals, :token}} -> {:ok, decimals, Solana.token_program()}
      {:ok, {decimals, :token_2022}} -> {:ok, decimals, Solana.token_2022_program()}
      :error -> {:error, {:unknown_asset, asset}}
    end
  end

  @spec resolve_blockhash(map(), keyword()) :: {:ok, String.t()} | {:error, term()}
  defp resolve_blockhash(requirements, opts) do
    hinted = extra_value(requirements, {"recentBlockhash", :recent_blockhash})

    cond do
      Solana.valid_address?(hinted) ->
        {:ok, hinted}

      is_binary(Keyword.get(opts, :svm_blockhash)) ->
        blockhash = Keyword.fetch!(opts, :svm_blockhash)

        case Solana.valid_address?(blockhash) do
          true -> {:ok, blockhash}
          false -> {:error, :invalid_blockhash}
        end

      is_function(Keyword.get(opts, :svm_blockhash_fetcher), 1) ->
        fetch_blockhash(
          Keyword.fetch!(opts, :svm_blockhash_fetcher),
          Utils.map_value(requirements, {"network", :network})
        )

      true ->
        {:error, :missing_blockhash}
    end
  end

  @spec fetch_blockhash((String.t() -> term()), term()) ::
          {:ok, String.t()} | {:error, term()}
  defp fetch_blockhash(fetcher, network) do
    case fetcher.(network) do
      {:ok, blockhash} ->
        case Solana.valid_address?(blockhash) do
          true -> {:ok, blockhash}
          false -> {:error, :invalid_blockhash}
        end

      {:error, reason} ->
        {:error, {:blockhash_fetch_failed, reason}}

      other ->
        {:error, {:blockhash_fetch_failed, other}}
    end
  end

  @spec resolve_memo(map()) :: {:ok, binary()} | {:error, :memo_too_long}
  defp resolve_memo(requirements) do
    case extra_value(requirements, {"memo", :memo}) do
      memo when is_binary(memo) and byte_size(memo) <= @max_memo_bytes ->
        {:ok, memo}

      memo when is_binary(memo) ->
        {:error, :memo_too_long}

      _absent ->
        {:ok, Base.encode16(:crypto.strong_rand_bytes(@nonce_bytes), case: :lower)}
    end
  end

  @spec extra_value(map(), {String.t(), atom()}) :: term()
  defp extra_value(requirements, keys) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      extra when is_map(extra) -> Utils.map_value(extra, keys)
      _extra -> nil
    end
  end

  @spec compile_transfer(String.t(), map()) ::
          {:ok, Transaction.compiled()} | {:error, :invalid_address}
  defp compile_transfer(fee_payer, params) do
    instructions = [
      Transaction.set_compute_unit_limit(@default_compute_unit_limit),
      Transaction.set_compute_unit_price(@default_compute_unit_price_microlamports),
      Transaction.transfer_checked(Map.take(params, transfer_keys())),
      Transaction.memo(params.memo)
    ]

    Transaction.compile(fee_payer, instructions, params.blockhash)
  end

  @spec transfer_keys() :: [atom()]
  defp transfer_keys,
    do: [:source, :mint, :destination, :authority, :amount, :decimals, :token_program]

  # -- validate_payload/3 internals -------------------------------------------

  @spec decode_wire(map()) :: {:ok, binary()} | {:error, {:invalid_scheme_payment, atom()}}
  defp decode_wire(payload) do
    case scheme_transaction(payload) do
      transaction when is_binary(transaction) ->
        case Base.decode64(transaction) do
          {:ok, wire} -> check_size(wire)
          :error -> {:error, {:invalid_scheme_payment, :invalid_base64}}
        end

      _missing ->
        {:error, {:invalid_scheme_payment, :missing_transaction}}
    end
  end

  @spec check_size(binary()) ::
          {:ok, binary()} | {:error, {:invalid_scheme_payment, :transaction_too_large}}
  defp check_size(wire) do
    case byte_size(wire) <= Transaction.max_transaction_size() do
      true -> {:ok, wire}
      false -> {:error, {:invalid_scheme_payment, :transaction_too_large}}
    end
  end

  @spec scheme_transaction(map()) :: term()
  defp scheme_transaction(payload) when is_map(payload) do
    case Utils.map_value(payload, {"payload", :payload}) do
      scheme_payload when is_map(scheme_payload) ->
        Utils.map_value(scheme_payload, {"transaction", :transaction})

      _other ->
        nil
    end
  end

  defp scheme_transaction(_payload), do: nil

  @spec decode_transaction(binary()) ::
          {:ok, Transaction.decoded()} | {:error, {:invalid_scheme_payment, atom()}}
  defp decode_transaction(wire) do
    case Transaction.decode(wire) do
      {:ok, decoded} when decoded.num_required_signatures >= 1 -> {:ok, decoded}
      _error -> {:error, {:invalid_scheme_payment, :invalid_transaction}}
    end
  end

  @spec validate_fee_payer(Transaction.decoded(), map()) ::
          :ok | {:error, {:invalid_scheme_payment, :fee_payer_mismatch}}
  defp validate_fee_payer(decoded, requirements) do
    with fee_payer when is_binary(fee_payer) <- fee_payer(requirements),
         {:ok, expected} <- Solana.decode_address(fee_payer) do
      case decoded.static_accounts do
        [^expected | _rest] -> :ok
        _mismatch -> {:error, {:invalid_scheme_payment, :fee_payer_mismatch}}
      end
    else
      # No (valid) advertised fee payer to compare against.
      _absent -> :ok
    end
  end

  # -- precheck/3 internals ---------------------------------------------------

  @spec precheck_wire(map()) :: {:ok, binary()} | {:error, {:precheck_failed, atom()}}
  defp precheck_wire(payload) do
    case decode_wire(payload) do
      {:ok, wire} -> {:ok, wire}
      {:error, {:invalid_scheme_payment, _reason}} -> precheck_error(:invalid_transaction)
    end
  end

  @spec precheck_decode(binary()) ::
          {:ok, Transaction.decoded()} | {:error, {:precheck_failed, atom()}}
  defp precheck_decode(wire) do
    case Transaction.decode(wire) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, _reason} -> precheck_error(:invalid_transaction)
    end
  end

  @spec run_static_prechecks(Transaction.decoded(), map()) ::
          :ok | {:error, {:precheck_failed, precheck_failure()}}
  defp run_static_prechecks(decoded, requirements) do
    instructions = decoded.instructions

    with :ok <- check_fee_payer_isolation(instructions),
         :ok <- check_instruction_count(instructions),
         :ok <- check_indices_in_range(decoded),
         [limit_ix, price_ix, transfer_ix | optional] = instructions,
         :ok <- check_compute_limit(limit_ix, decoded),
         :ok <- check_compute_price(price_ix, decoded),
         :ok <- check_transfer(transfer_ix, decoded, requirements),
         :ok <- check_optional_instructions(optional, decoded) do
      check_memo(optional, decoded, requirements)
    end
  end

  # §2.1.1 — the fee payer (account 0) must not be referenced by any
  # instruction, as a program or an account. Holds for both verification
  # paths, so it is always a certain mismatch.
  @spec check_fee_payer_isolation([map()]) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_fee_payer_isolation(instructions) do
    isolated? =
      Enum.all?(instructions, fn instruction ->
        instruction.program_index != 0 and 0 not in instruction.account_indices
      end)

    case isolated? do
      true -> :ok
      false -> precheck_error(:fee_payer_not_isolated)
    end
  end

  @spec check_instruction_count([map()]) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_instruction_count(instructions) when length(instructions) in 3..7, do: :ok
  defp check_instruction_count(_instructions), do: precheck_error(:instruction_count)

  @spec check_indices_in_range(Transaction.decoded()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_indices_in_range(decoded) do
    account_count = length(decoded.static_accounts)

    in_range? =
      Enum.all?(decoded.instructions, fn instruction ->
        instruction.program_index < account_count and
          Enum.all?(instruction.account_indices, &(&1 < account_count))
      end)

    case in_range? do
      true -> :ok
      false -> precheck_error(:invalid_transaction)
    end
  end

  @spec check_compute_limit(map(), Transaction.decoded()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_compute_limit(instruction, decoded) do
    compute_budget? = program_at(decoded, instruction.program_index) == compute_budget_pubkey()

    case {compute_budget?, instruction.data} do
      {true, <<2, _units::32-little>>} -> :ok
      _invalid -> precheck_error(:invalid_compute_limit_instruction)
    end
  end

  @spec check_compute_price(map(), Transaction.decoded()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_compute_price(instruction, decoded) do
    compute_budget? = program_at(decoded, instruction.program_index) == compute_budget_pubkey()

    case {compute_budget?, instruction.data} do
      {true, <<3, price::64-little>>} when price <= @max_compute_unit_price_microlamports ->
        :ok

      {true, <<3, _price::64-little>>} ->
        precheck_error(:compute_price_too_high)

      _invalid ->
        precheck_error(:invalid_compute_price_instruction)
    end
  end

  @spec check_transfer(map(), Transaction.decoded(), map()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_transfer(instruction, decoded, requirements) do
    program = program_at(decoded, instruction.program_index)
    token_program = token_program_for(program)

    with {:token_program, {:ok, token_program_address}} <- {:token_program, token_program},
         {:layout, <<12, amount::64-little, _decimals>>} <- {:layout, instruction.data},
         {:accounts, [_source, mint_index, destination_index, _authority | _rest]} <-
           {:accounts, instruction.account_indices} do
      check_transfer_semantics(
        %{
          amount: amount,
          mint: account_at(decoded, mint_index),
          destination: account_at(decoded, destination_index),
          token_program: token_program_address
        },
        requirements
      )
    else
      {_step, _mismatch} -> precheck_error(:missing_transfer_instruction)
    end
  end

  # Semantic mismatches on the positional transfer are terminal on both
  # verification paths (spec §3.3: semantic failures never fall through to
  # Path 2), so they are certain mismatches. Each check is skipped when the
  # corresponding requirements field cannot be interpreted locally.
  @spec check_transfer_semantics(map(), map()) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_transfer_semantics(transfer, requirements) do
    with :ok <- check_amount(transfer.amount, requirements),
         :ok <- check_mint(transfer.mint, requirements) do
      check_recipient(transfer, requirements)
    end
  end

  @spec check_amount(non_neg_integer(), map()) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_amount(amount, requirements) do
    case parse_amount(Utils.map_value(requirements, {"amount", :amount})) do
      {:ok, ^amount} -> :ok
      {:ok, _other} -> precheck_error(:amount_mismatch)
      {:error, _invalid} -> :ok
    end
  end

  @spec check_mint(binary() | nil, map()) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_mint(mint, requirements) do
    case Solana.decode_address(Utils.map_value(requirements, {"asset", :asset})) do
      {:ok, ^mint} -> :ok
      {:ok, _other} -> precheck_error(:mint_mismatch)
      {:error, _invalid} -> :ok
    end
  end

  @spec check_recipient(map(), map()) :: :ok | {:error, {:precheck_failed, atom()}}
  defp check_recipient(transfer, requirements) do
    pay_to = Utils.map_value(requirements, {"payTo", :pay_to})
    asset = Utils.map_value(requirements, {"asset", :asset})

    with true <- Solana.valid_address?(pay_to),
         true <- Solana.valid_address?(asset),
         {:ok, expected_ata} <-
           Solana.associated_token_address(pay_to, asset, transfer.token_program),
         {:ok, expected} <- Solana.decode_address(expected_ata) do
      case transfer.destination do
        ^expected -> :ok
        _mismatch -> precheck_error(:recipient_mismatch)
      end
    else
      # Requirements not locally interpretable — leave it to the facilitator.
      _skip -> :ok
    end
  end

  @spec check_optional_instructions([map()], Transaction.decoded()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_optional_instructions(optional, decoded) do
    allowed = [memo_pubkey(), lighthouse_pubkey()]

    valid? =
      Enum.all?(optional, fn instruction ->
        program_at(decoded, instruction.program_index) in allowed
      end)

    case valid? do
      true -> :ok
      false -> precheck_error(:unknown_optional_instruction)
    end
  end

  @spec check_memo([map()], Transaction.decoded(), map()) ::
          :ok | {:error, {:precheck_failed, atom()}}
  defp check_memo(optional, decoded, requirements) do
    case extra_value(requirements, {"memo", :memo}) do
      memo when is_binary(memo) ->
        memos =
          Enum.filter(optional, fn instruction ->
            program_at(decoded, instruction.program_index) == memo_pubkey()
          end)

        case memos do
          [%{data: ^memo}] -> :ok
          [_one] -> precheck_error(:memo_mismatch)
          _other -> precheck_error(:memo_count)
        end

      _absent ->
        :ok
    end
  end

  @spec program_at(Transaction.decoded(), non_neg_integer()) :: binary() | nil
  defp program_at(decoded, index), do: account_at(decoded, index)

  @spec account_at(Transaction.decoded(), non_neg_integer()) :: binary() | nil
  defp account_at(decoded, index), do: Enum.at(decoded.static_accounts, index)

  @spec precheck_error(atom()) :: {:error, {:precheck_failed, atom()}}
  defp precheck_error(reason), do: {:error, {:precheck_failed, reason}}

  @spec token_program_for(binary() | nil) :: {:ok, String.t()} | :error
  defp token_program_for(program_pubkey) do
    cond do
      program_pubkey == token_pubkey() -> {:ok, Solana.token_program()}
      program_pubkey == token_2022_pubkey() -> {:ok, Solana.token_2022_program()}
      true -> :error
    end
  end

  @spec token_pubkey() :: binary()
  defp token_pubkey, do: decode_known!(Solana.token_program())

  @spec token_2022_pubkey() :: binary()
  defp token_2022_pubkey, do: decode_known!(Solana.token_2022_program())

  @spec compute_budget_pubkey() :: binary()
  defp compute_budget_pubkey, do: decode_known!(Solana.compute_budget_program())

  @spec memo_pubkey() :: binary()
  defp memo_pubkey, do: decode_known!(Solana.memo_program())

  @spec lighthouse_pubkey() :: binary()
  defp lighthouse_pubkey, do: decode_known!(Solana.lighthouse_program())

  @spec decode_known!(String.t()) :: binary()
  defp decode_known!(address) do
    {:ok, pubkey} = Solana.decode_address(address)
    pubkey
  end
end
