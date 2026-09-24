defmodule X402.AuthCapture do
  @moduledoc """
  The `auth-capture` payment scheme: flows, operations, deadlines, lifecycle
  payloads, and reason strings.

  `auth-capture` adds refundable, two-phase payments to x402 on top of
  Base's commerce-payments escrow. The client signs one token
  authorization; how it settles follows `extra.paymentFlow`:

  * `"escrow"` (default) — the collect is an `authorize` that holds the
    funds; the resource server later relays `capture`, `void`, or
    `refund` lifecycle payloads through the facilitator.
  * `"authorization"` — the collect is a terminal `charge` the server
    completes with an amount, fee, and authorizer signature; only `refund`
    follows.

  This module is chain-agnostic in shape but the only binding today is EVM
  (`X402.AuthCapture.EVM`, `X402.Scheme.AuthCaptureEVM`,
  `X402.Verify.AuthCaptureEVM`), so the
  lifecycle builders here produce the EVM binding's wire payloads.

  ## Lifecycle payloads

  A resource server authors lifecycle settles from the stored `PaymentInfo`
  and client `saltNonce`:

      {:ok, capture} =
        X402.AuthCapture.capture_payload(requirements, payment_info,
          salt_nonce: salt_nonce,
          amount: "750000",
          expected_capturable_amount: "1000000",
          expected_refundable_amount: "0",
          authorizer: receiver_authorizer_signer
        )

  These builders do not broadcast or persist the operation. Submit the
  resulting envelope through an auth-capture-capable facilitator only
  after authenticating the request and establishing any refund funding
  agreement. An explicit `:authorizer` signer is required; implicit
  receiver-authorizer delegation is not supported.

  ## Reason strings

  Every reason this scheme defines is namespaced
  `invalid_auth_capture_evm_*`; standard x402 reasons keep their canonical
  names. See `reason_string/1`.
  """

  alias X402.AuthCapture.EVM
  alias X402.EIP712
  alias X402.Signer
  alias X402.Utils
  alias X402.Verify.AuthCaptureEVM, as: Verify

  @scheme "auth-capture"
  @x402_version 2
  @skew_seconds 6

  @standard_reasons [
    :invalid_network,
    :invalid_x402_version,
    :unsupported_scheme,
    :settlement_pending,
    :unexpected_settle_error,
    :insufficient_funds
  ]

  @scheme_reasons [
    :payload_format,
    :payload_type,
    :void_authorizer_signature,
    :void_remainder_full_capture,
    :unsupported_payment_flow,
    :scheme,
    :network_mismatch,
    :extra,
    :missing_receiver_authorizer,
    :unsupported_operator_type,
    :policy,
    :lifecycle_not_relayed,
    :operator_type_mismatch,
    :operator_not_admitted,
    :operator_mismatch,
    :salt_binding_mismatch,
    :authorizer_signature,
    :unauthenticated_authorizer_request,
    :unexpected_payment_state,
    :refund_funding_unavailable,
    :unsupported_asset_transfer_method,
    :payload_method_mismatch,
    :capture_deadline_expired,
    :refund_deadline_expired,
    :deadline_ordering,
    :authorization_expired,
    :authorization_not_yet_valid,
    :signature,
    :erc6492_factory_not_allowed,
    :amount_mismatch,
    :token_collector_mismatch,
    :token_mismatch,
    :nonce_mismatch,
    :insufficient_balance,
    :simulation_failed,
    :payment_already_collected,
    :token_collection_failed,
    :collector,
    :amount_overflow,
    :fee_bps,
    :fee_bps_range,
    :fee_bps_out_of_range,
    :zero_fee_receiver,
    :fee_receiver,
    :insufficient_authorization,
    :zero_authorization,
    :refund_exceeds_capture,
    :before_authorization_expiry,
    :verification_failed,
    :transaction_reverted,
    :transaction_failed,
    :transaction_simulation_failed,
    :gas_limit_exceeded
  ]

  @typedoc "The settlement lifecycle a requirements entry selects."
  @type payment_flow :: :escrow | :authorization

  @typedoc "When the post-resource finalize of an escrow route runs."
  @type capture_mode :: :sync | :deferred

  @typedoc "The kind of `extra.captureAuthorizer`."
  @type operator_type :: :delegated | :custom | :policy

  @typedoc "The escrow call a payload settles as."
  @type operation :: :authorize | :charge | :capture | :void | :refund

  @typedoc "A reason atom this scheme reports (see `reason_string/1`)."
  @type reason :: atom()

  @lifecycle_schema [
    salt_nonce: [
      type: :string,
      required: true,
      doc: "The client's `saltNonce` (32-byte `0x` hex) that reopens the salt binding."
    ],
    amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: "Atomic amount to capture or refund (required for those operations)."
    ],
    fee: [
      type: {:or, [:string, :non_neg_integer]},
      doc: """
      Submitted fee for `capture`: `feeAmount` (atomic units) on v1.1 or
      `feeBps` on v1.0. Defaults to the deployment's minimum
      (`amount * minFeeBps / 10000`, or `minFeeBps`).
      """
    ],
    fee_receiver: [
      type: :string,
      doc: "Submitted fee receiver for `capture`. Defaults to `paymentInfo.feeReceiver`."
    ],
    expected_capturable_amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: "The `capturableAmount` the authorizer expects to find (capture and refund)."
    ],
    expected_refundable_amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: "The `refundableAmount` the authorizer expects to find (capture and refund)."
    ],
    authorizer: [
      type: :any,
      required: true,
      doc: """
      The receiver authorizer's `X402.Signer`, required for explicit consent.
      """
    ],
    void_remainder: [
      type: :boolean,
      default: false,
      doc: """
      For `capture`: also sign a `Void` so the same settle releases the
      remaining hold (sync partial close-out). Requires `:authorizer`.
      """
    ]
  ]

  @charge_schema [
    amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: "Amount to charge, at most `requirements.amount` (the default)."
    ],
    fee: [
      type: {:or, [:string, :non_neg_integer]},
      doc: "Submitted fee (`feeAmount` on v1.1, `feeBps` on v1.0); defaults to the minimum."
    ],
    fee_receiver: [
      type: :string,
      doc: "Submitted fee receiver; defaults to `extra.feeRecipient`."
    ],
    authorizer: [
      type: :any,
      required: true,
      doc: "The receiver authorizer's `X402.Signer`, required for explicit consent."
    ]
  ]

  @deadline_schema [
    now: [type: :non_neg_integer],
    skew_seconds: [type: :non_neg_integer, default: @skew_seconds]
  ]

  # -- Requirements -----------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  The scheme identifier.

  ## Examples

      iex> X402.AuthCapture.scheme()
      "auth-capture"
  """
  @spec scheme() :: String.t()
  def scheme, do: @scheme

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  The clock-skew floor (seconds) the deadline checks apply.

  ## Examples

      iex> X402.AuthCapture.skew_seconds()
      6
  """
  @spec skew_seconds() :: pos_integer()
  def skew_seconds, do: @skew_seconds

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Resolves `extra.paymentFlow` (default `"escrow"`).

  The removed v1.0 `autoCapture: true` is rejected as unsupported.

  ## Examples

      iex> X402.AuthCapture.payment_flow(%{"extra" => %{}})
      {:ok, :escrow}

      iex> X402.AuthCapture.payment_flow(%{"extra" => %{"paymentFlow" => "authorization"}})
      {:ok, :authorization}

      iex> X402.AuthCapture.payment_flow(%{"extra" => %{"autoCapture" => true}})
      {:error, :unsupported_payment_flow}

      iex> X402.AuthCapture.payment_flow(%{"extra" => %{"paymentFlow" => "instant"}})
      {:error, :unsupported_payment_flow}
  """
  @spec payment_flow(map()) :: {:ok, payment_flow()} | {:error, :unsupported_payment_flow}
  def payment_flow(requirements) when is_map(requirements) do
    extra = extra(requirements)

    case {Utils.map_value(extra, {"autoCapture", :autoCapture}),
          Utils.map_value(extra, {"paymentFlow", :paymentFlow})} do
      {true, _flow} -> {:error, :unsupported_payment_flow}
      {_auto, nil} -> {:ok, :escrow}
      {_auto, "escrow"} -> {:ok, :escrow}
      {_auto, "authorization"} -> {:ok, :authorization}
      _other -> {:error, :unsupported_payment_flow}
    end
  end

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Resolves `extra.captureMode` (default `"sync"`), which is only meaningful
  under the escrow flow.

  ## Examples

      iex> X402.AuthCapture.capture_mode(%{"extra" => %{}})
      {:ok, :sync}

      iex> X402.AuthCapture.capture_mode(%{"extra" => %{"captureMode" => "deferred"}})
      {:ok, :deferred}

      iex> X402.AuthCapture.capture_mode(%{
      ...>   "extra" => %{"paymentFlow" => "authorization", "captureMode" => "sync"}
      ...> })
      {:error, :extra}
  """
  @spec capture_mode(map()) :: {:ok, capture_mode()} | {:error, :extra}
  def capture_mode(requirements) when is_map(requirements) do
    mode = Utils.map_value(extra(requirements), {"captureMode", :captureMode})

    case {payment_flow(requirements), mode} do
      {_flow, nil} -> {:ok, :sync}
      {{:ok, :escrow}, "sync"} -> {:ok, :sync}
      {{:ok, :escrow}, "deferred"} -> {:ok, :deferred}
      _other -> {:error, :extra}
    end
  end

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Resolves `extra.operatorType` (default `"delegated"`).

  ## Examples

      iex> X402.AuthCapture.operator_type(%{"extra" => %{}})
      {:ok, :delegated}

      iex> X402.AuthCapture.operator_type(%{"extra" => %{"operatorType" => "custom"}})
      {:ok, :custom}

      iex> X402.AuthCapture.operator_type(%{"extra" => %{"operatorType" => "dao"}})
      {:error, :unsupported_operator_type}
  """
  @spec operator_type(map()) :: {:ok, operator_type()} | {:error, :unsupported_operator_type}
  def operator_type(requirements) when is_map(requirements) do
    case Utils.map_value(extra(requirements), {"operatorType", :operatorType}) do
      nil -> {:ok, :delegated}
      "delegated" -> {:ok, :delegated}
      "custom" -> {:ok, :custom}
      "policy" -> {:ok, :policy}
      _other -> {:error, :unsupported_operator_type}
    end
  end

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Resolves `extra.assetTransferMethod` (default `"eip3009"`).

  ## Examples

      iex> X402.AuthCapture.asset_transfer_method(%{"extra" => %{}})
      {:ok, :eip3009}

      iex> X402.AuthCapture.asset_transfer_method(%{"extra" => %{"assetTransferMethod" => "permit2"}})
      {:ok, :permit2}

      iex> X402.AuthCapture.asset_transfer_method(%{"extra" => %{"assetTransferMethod" => "eip2612"}})
      {:error, :unsupported_asset_transfer_method}
  """
  @spec asset_transfer_method(map()) ::
          {:ok, :eip3009 | :permit2} | {:error, :unsupported_asset_transfer_method}
  def asset_transfer_method(requirements) when is_map(requirements) do
    case Utils.map_value(extra(requirements), {"assetTransferMethod", :assetTransferMethod}) do
      nil -> {:ok, :eip3009}
      "eip3009" -> {:ok, :eip3009}
      "permit2" -> {:ok, :permit2}
      _other -> {:error, :unsupported_asset_transfer_method}
    end
  end

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Whether the payload is a lifecycle payload (carries `payload.type`).

  ## Examples

      iex> X402.AuthCapture.lifecycle?(%{"payload" => %{"type" => "capture"}})
      true

      iex> X402.AuthCapture.lifecycle?(%{"payload" => %{"authorization" => %{}}})
      false
  """
  @spec lifecycle?(map()) :: boolean()
  def lifecycle?(payload) when is_map(payload),
    do: not is_nil(Utils.map_value(inner(payload), {"type", :type}))

  @doc since: "0.9.0"
  @doc group: :requirements
  @doc """
  Resolves the escrow operation a payload settles as.

  Client payloads settle as `:authorize` (escrow flow) or `:charge`
  (authorization flow); lifecycle payloads name their `payload.type`, with
  `capture` and `void` admitted only under the escrow flow.

  ## Examples

      iex> X402.AuthCapture.operation(%{"payload" => %{"authorization" => %{}}}, %{"extra" => %{}})
      {:ok, :authorize}

      iex> X402.AuthCapture.operation(
      ...>   %{"payload" => %{"authorization" => %{}}},
      ...>   %{"extra" => %{"paymentFlow" => "authorization"}}
      ...> )
      {:ok, :charge}

      iex> X402.AuthCapture.operation(%{"payload" => %{"type" => "refund"}}, %{"extra" => %{}})
      {:ok, :refund}

      iex> X402.AuthCapture.operation(
      ...>   %{"payload" => %{"type" => "capture"}},
      ...>   %{"extra" => %{"paymentFlow" => "authorization"}}
      ...> )
      {:error, :payload_type}

      iex> X402.AuthCapture.operation(%{"payload" => %{"type" => "settle"}}, %{"extra" => %{}})
      {:error, :payload_type}
  """
  @spec operation(map(), map()) ::
          {:ok, operation()} | {:error, :payload_type | :unsupported_payment_flow}
  def operation(payload, requirements) when is_map(payload) and is_map(requirements) do
    with {:ok, flow} <- payment_flow(requirements) do
      case {Utils.map_value(inner(payload), {"type", :type}), flow} do
        {nil, :escrow} -> {:ok, :authorize}
        {nil, :authorization} -> {:ok, :charge}
        {"capture", :escrow} -> {:ok, :capture}
        {"void", :escrow} -> {:ok, :void}
        {"refund", _flow} -> {:ok, :refund}
        _other -> {:error, :payload_type}
      end
    end
  end

  # -- Deadlines --------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :deadlines
  @doc """
  Checks the requirements' deadline ordering:
  `now + maxTimeoutSeconds <= captureDeadline <= refundDeadline` and
  `captureDeadline > now + skew`.

  ## Options

  * `:now` — Unix seconds (default: current time)
  * `:skew_seconds` — clock-skew floor (default `6`)

  ## Examples

      iex> requirements = %{
      ...>   "maxTimeoutSeconds" => 600,
      ...>   "extra" => %{"captureDeadline" => 2_000, "refundDeadline" => 3_000}
      ...> }
      iex> X402.AuthCapture.check_deadlines(requirements, now: 1_000)
      :ok

      iex> X402.AuthCapture.check_deadlines(
      ...>   %{"maxTimeoutSeconds" => 600, "extra" => %{"captureDeadline" => 3_000, "refundDeadline" => 2_000}},
      ...>   now: 1_000
      ...> )
      {:error, :deadline_ordering}

      iex> X402.AuthCapture.check_deadlines(
      ...>   %{"maxTimeoutSeconds" => 1_500, "extra" => %{"captureDeadline" => 2_000, "refundDeadline" => 3_000}},
      ...>   now: 1_000
      ...> )
      {:error, :deadline_ordering}

      iex> X402.AuthCapture.check_deadlines(
      ...>   %{"maxTimeoutSeconds" => 0, "extra" => %{"captureDeadline" => 1_005, "refundDeadline" => 3_000}},
      ...>   now: 1_000
      ...> )
      {:error, :capture_deadline_expired}
  """
  @spec check_deadlines(map(), keyword()) ::
          :ok
          | {:error,
             :deadline_ordering
             | :capture_deadline_expired
             | :extra
             | {:invalid_options, String.t()}}
  def check_deadlines(requirements, opts \\ []) when is_map(requirements) and is_list(opts) do
    extra = extra(requirements)

    with {:ok, opts} <- deadline_options(opts),
         now = opts[:now],
         skew = opts[:skew_seconds],
         {:ok, capture_deadline} <-
           integer(Utils.map_value(extra, {"captureDeadline", :captureDeadline})),
         {:ok, refund_deadline} <-
           integer(Utils.map_value(extra, {"refundDeadline", :refundDeadline})),
         {:ok, max_timeout} <-
           integer(Utils.map_value(requirements, {"maxTimeoutSeconds", :maxTimeoutSeconds})) do
      cond do
        refund_deadline < capture_deadline -> {:error, :deadline_ordering}
        now + max_timeout > capture_deadline -> {:error, :deadline_ordering}
        capture_deadline <= now + skew -> {:error, :capture_deadline_expired}
        true -> :ok
      end
    else
      :error -> {:error, :extra}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc since: "0.9.0"
  @doc group: :deadlines
  @doc """
  Checks a client authorization's time window against the capture deadline:
  `validAfter <= now`, `validBefore > now + skew`, and
  `validBefore <= captureDeadline`.

  `valid_after` is `nil` for Permit2 (which has no lower bound). The
  `:now` and `:skew_seconds` options must be non-negative integers;
  the skew is never lowered below six seconds.

  ## Examples

      iex> X402.AuthCapture.check_authorization_window("0", "1600", 2_000, now: 1_000)
      :ok

      iex> X402.AuthCapture.check_authorization_window("0", "1005", 2_000, now: 1_000)
      {:error, :authorization_expired}

      iex> X402.AuthCapture.check_authorization_window("0", "2500", 2_000, now: 1_000)
      {:error, :deadline_ordering}

      iex> X402.AuthCapture.check_authorization_window("1100", "1600", 2_000, now: 1_000)
      {:error, :authorization_not_yet_valid}
  """
  @spec check_authorization_window(term(), term(), term(), keyword()) ::
          :ok
          | {:error,
             :authorization_expired
             | :authorization_not_yet_valid
             | :deadline_ordering
             | :payload_format
             | {:invalid_options, String.t()}}
  def check_authorization_window(valid_after, valid_before, capture_deadline, opts \\ []) do
    with {:ok, opts} <- deadline_options(opts),
         now = opts[:now],
         skew = opts[:skew_seconds],
         {:ok, before} <- integer(valid_before),
         {:ok, after_} <- integer(if(is_nil(valid_after), do: 0, else: valid_after)),
         {:ok, deadline} <- integer(capture_deadline) do
      cond do
        before <= now + skew -> {:error, :authorization_expired}
        before > deadline -> {:error, :deadline_ordering}
        after_ > now -> {:error, :authorization_not_yet_valid}
        true -> :ok
      end
    else
      :error -> {:error, :payload_format}
      {:error, reason} -> {:error, reason}
    end
  end

  # -- Reasons ----------------------------------------------------------------

  @doc since: "0.9.0"
  @doc group: :reasons
  @doc """
  Every reason atom this scheme reports, standard ones first.
  """
  @spec reasons() :: [reason()]
  def reasons, do: @standard_reasons ++ @scheme_reasons

  @doc since: "0.9.0"
  @doc group: :reasons
  @doc """
  Converts a reason atom to its canonical wire string.

  Standard x402 reasons keep their name; everything else is namespaced
  `invalid_auth_capture_evm_*`.

  ## Examples

      iex> X402.AuthCapture.reason_string(:nonce_mismatch)
      "invalid_auth_capture_evm_nonce_mismatch"

      iex> X402.AuthCapture.reason_string(:invalid_network)
      "invalid_network"
  """
  @spec reason_string(reason()) :: String.t()
  def reason_string(reason) when reason in @standard_reasons, do: Atom.to_string(reason)

  def reason_string(reason) when is_atom(reason),
    do: "invalid_auth_capture_evm_" <> Atom.to_string(reason)

  # -- Lifecycle payload builders ---------------------------------------------

  @doc since: "0.9.0"
  @doc group: :lifecycle
  @doc """
  Builds a `capture` lifecycle payload (v2 envelope) for the facilitator.

  ## Options

  #{NimbleOptions.docs(@lifecycle_schema)}

  `:amount`, `:expected_capturable_amount`, and `:expected_refundable_amount`
  are required.
  """
  @spec capture_payload(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def capture_payload(requirements, payment_info, opts)
      when is_map(requirements) and is_map(payment_info) and is_list(opts) do
    with {:ok, opts} <-
           validate_lifecycle(opts, [
             :amount,
             :expected_capturable_amount,
             :expected_refundable_amount
           ]),
         {:ok, ctx} <- lifecycle_context(requirements, payment_info, opts[:salt_nonce]),
         :ok <- builder_operation(:capture, requirements),
         :ok <- validate_void_remainder(opts),
         {:ok, fee} <- default_fee(ctx, payment_info, opts[:amount], opts[:fee]),
         fee_receiver =
           opts[:fee_receiver] || Utils.map_value(payment_info, {"feeReceiver", :feeReceiver}),
         params = %{
           "paymentInfoHash" => ctx.payment_info_hash,
           "amount" => amount_string(opts[:amount]),
           EVM.fee_field(ctx.version) => amount_string(fee),
           "feeReceiver" => fee_receiver,
           "expectedCapturableAmount" => amount_string(opts[:expected_capturable_amount]),
           "expectedRefundableAmount" => amount_string(opts[:expected_refundable_amount])
         },
         {:ok, signature} <- maybe_sign(opts[:authorizer], :capture, params, ctx),
         {:ok, void_signature} <- maybe_void_signature(opts, ctx) do
      payload =
        %{"type" => "capture", "paymentInfo" => payment_info, "saltNonce" => opts[:salt_nonce]}
        |> Map.merge(Map.delete(params, "paymentInfoHash"))
        |> maybe_put("authorizerSignature", signature)
        |> maybe_put("voidAuthorizerSignature", void_signature)

      {:ok, envelope(requirements, payload)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :lifecycle
  @doc """
  Builds a `void` lifecycle payload (v2 envelope) for the facilitator.

  Accepts `:salt_nonce` and `:authorizer` from the lifecycle options.
  """
  @spec void_payload(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def void_payload(requirements, payment_info, opts)
      when is_map(requirements) and is_map(payment_info) and is_list(opts) do
    with {:ok, opts} <- validate_lifecycle(opts, []),
         {:ok, ctx} <- lifecycle_context(requirements, payment_info, opts[:salt_nonce]),
         :ok <- builder_operation(:void, requirements),
         params = %{"paymentInfoHash" => ctx.payment_info_hash},
         {:ok, signature} <- maybe_sign(opts[:authorizer], :void, params, ctx) do
      payload =
        %{"type" => "void", "paymentInfo" => payment_info, "saltNonce" => opts[:salt_nonce]}
        |> maybe_put("authorizerSignature", signature)

      {:ok, envelope(requirements, payload)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :lifecycle
  @doc """
  Builds a `refund` lifecycle payload (v2 envelope) for the facilitator.

  Requires `:salt_nonce`, `:amount`, `:expected_capturable_amount`, and
  `:expected_refundable_amount`; the token collector is always the
  deployment's operator refund collector and is not carried on the wire.
  """
  @spec refund_payload(map(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def refund_payload(requirements, payment_info, opts)
      when is_map(requirements) and is_map(payment_info) and is_list(opts) do
    with {:ok, opts} <-
           validate_lifecycle(opts, [
             :amount,
             :expected_capturable_amount,
             :expected_refundable_amount
           ]),
         {:ok, ctx} <- lifecycle_context(requirements, payment_info, opts[:salt_nonce]),
         :ok <- builder_operation(:refund, requirements),
         params = %{
           "paymentInfoHash" => ctx.payment_info_hash,
           "amount" => amount_string(opts[:amount]),
           "tokenCollector" => ctx.deployment.refund_collector,
           "expectedCapturableAmount" => amount_string(opts[:expected_capturable_amount]),
           "expectedRefundableAmount" => amount_string(opts[:expected_refundable_amount])
         },
         {:ok, signature} <- maybe_sign(opts[:authorizer], :refund, params, ctx) do
      payload =
        %{"type" => "refund", "paymentInfo" => payment_info, "saltNonce" => opts[:salt_nonce]}
        |> Map.merge(Map.drop(params, ["paymentInfoHash", "tokenCollector"]))
        |> maybe_put("authorizerSignature", signature)

      {:ok, envelope(requirements, payload)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :lifecycle
  @doc """
  Completes a client payment payload for a `charge` settle.

  Appends `amount`, the deployment's fee field, `feeReceiver`, and an
  explicit `authorizerSignature` over exactly those values, leaving the
  client's fields untouched. `envelope` is the v2 envelope whose
  `accepted` requirements select the deployment.

  ## Options

  #{NimbleOptions.docs(@charge_schema)}
  """
  @spec complete_charge(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def complete_charge(envelope, opts \\ []) when is_map(envelope) and is_list(opts) do
    requirements =
      case Utils.map_value(envelope, {"accepted", :accepted}) do
        %{} = requirements -> requirements
        _other -> %{}
      end

    payload = inner(envelope)

    with {:ok, opts} <- validate(opts, @charge_schema),
         :ok <- builder_operation(:charge, requirements),
         {:ok, method} <- asset_transfer_method(requirements),
         {:ok, payment_info} <- EVM.payment_info_from_payload(payload, requirements),
         {:ok, ctx} <-
           lifecycle_context(
             requirements,
             payment_info,
             Utils.map_value(payload, {"saltNonce", :saltNonce})
           ),
         amount = opts[:amount] || Utils.map_value(requirements, {"amount", :amount}),
         {:ok, fee} <- default_fee(ctx, payment_info, amount, opts[:fee]),
         {:ok, data_hash} <- collector_data_hash(payload, method),
         fee_receiver =
           opts[:fee_receiver] || Utils.map_value(payment_info, {"feeReceiver", :feeReceiver}),
         params = %{
           "paymentInfoHash" => ctx.payment_info_hash,
           "amount" => amount_string(amount),
           "tokenCollector" => collector(ctx.deployment, method),
           "collectorDataHash" => data_hash,
           EVM.fee_field(ctx.version) => amount_string(fee),
           "feeReceiver" => fee_receiver
         },
         {:ok, signature} <- maybe_sign(opts[:authorizer], :charge, params, ctx) do
      completed =
        payload
        |> Map.merge(Map.drop(params, ["paymentInfoHash", "tokenCollector", "collectorDataHash"]))
        |> maybe_put("authorizerSignature", signature)

      {:ok, Utils.map_put(envelope, {"payload", :payload}, completed)}
    end
  end

  @doc since: "0.9.0"
  @doc group: :lifecycle
  @doc """
  The token collector a deployment uses for an asset transfer method.

  ## Examples

      iex> deployment = X402.AuthCapture.EVM.deployment(:v1_1)
      iex> X402.AuthCapture.collector(deployment, :permit2)
      "0xD69831Aed5bfe262067ec4c751f4F830EcdD446e"
  """
  @spec collector(EVM.deployment(), :eip3009 | :permit2) :: String.t()
  def collector(deployment, :eip3009), do: deployment.eip3009_collector
  def collector(deployment, :permit2), do: deployment.permit2_collector

  # -- Internals --------------------------------------------------------------

  @spec extra(map()) :: map()
  defp extra(requirements) do
    case Utils.map_value(requirements, {"extra", :extra}) do
      %{} = extra -> extra
      _other -> %{}
    end
  end

  @spec inner(map()) :: map()
  defp inner(payload) do
    case Utils.map_value(payload, {"payload", :payload}) do
      %{} = inner -> inner
      _other -> payload
    end
  end

  @spec integer(term()) :: {:ok, integer()} | :error
  defp integer(value) do
    case EVM.parse_uint256(value) do
      {:ok, integer} -> {:ok, integer}
      {:error, _reason} -> :error
    end
  end

  @spec validate(keyword(), keyword()) :: {:ok, keyword()} | {:error, term()}
  defp validate(opts, schema) do
    case NimbleOptions.validate(opts, schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, error} -> {:error, {:invalid_options, Exception.message(error)}}
    end
  end

  @spec deadline_options(keyword()) :: {:ok, keyword()} | {:error, term()}
  defp deadline_options(opts) do
    with {:ok, validated} <- validate(opts, @deadline_schema) do
      {:ok,
       validated
       |> Keyword.put_new_lazy(:now, fn -> System.os_time(:second) end)
       |> Keyword.update!(:skew_seconds, &max(&1, @skew_seconds))}
    end
  end

  @spec validate_lifecycle(keyword(), [atom()]) :: {:ok, keyword()} | {:error, term()}
  defp validate_lifecycle(opts, required) do
    with {:ok, validated} <- validate(opts, @lifecycle_schema) do
      case Enum.find(required, &is_nil(validated[&1])) do
        nil -> {:ok, validated}
        key -> {:error, {:invalid_options, "required :#{key} option not found"}}
      end
    end
  end

  @spec lifecycle_context(map(), map(), term()) :: {:ok, map()} | {:error, term()}
  defp lifecycle_context(requirements, payment_info, salt_nonce) do
    with :ok <- Verify.validate_requirements(requirements),
         :ok <- EVM.match_payment_info(requirements, payment_info),
         :ok <- match_salt(requirements, payment_info, salt_nonce),
         {:ok, chain_id} <-
           EIP712.chain_id_from_caip2(Utils.map_value(requirements, {"network", :network})),
         {:ok, deployment} <- EVM.resolve_deployment(requirements),
         {:ok, hash} <- EVM.payment_info_hash(chain_id, deployment.escrow, payment_info) do
      {:ok,
       %{
         chain_id: chain_id,
         deployment: deployment,
         version: deployment.version,
         payment_info_hash: hash,
         payment_info: payment_info,
         receiver_authorizer:
           Utils.map_value(extra(requirements), {"receiverAuthorizer", :receiverAuthorizer}),
         domain:
           EVM.operator_domain(chain_id, Utils.map_value(payment_info, {"operator", :operator}))
       }}
    end
  end

  @spec match_salt(map(), map(), term()) :: :ok | {:error, term()}
  defp match_salt(requirements, info, salt_nonce) do
    with {:ok, salt} <-
           EVM.bound_salt(
             Utils.map_value(extra(requirements), {"receiverAuthorizer", :receiverAuthorizer}),
             Utils.map_value(extra(requirements), {"policy", :policy}),
             salt_nonce
           ),
         {:ok, actual} <- EVM.bytes32_hex(Utils.map_value(info, {"salt", :salt})),
         true <- salt == actual do
      :ok
    else
      false -> {:error, :salt_binding_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec builder_operation(EVM.operation(), map()) :: :ok | {:error, atom()}
  defp builder_operation(:charge, requirements) do
    case payment_flow(requirements) do
      {:ok, :authorization} -> :ok
      _other -> {:error, :payload_type}
    end
  end

  defp builder_operation(operation, requirements) do
    with {:ok, :delegated} <- operator_type(requirements),
         {:ok, ^operation} <-
           operation(%{"payload" => %{"type" => Atom.to_string(operation)}}, requirements) do
      :ok
    else
      {:ok, _other} -> {:error, :lifecycle_not_relayed}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec validate_void_remainder(keyword()) :: :ok | {:error, atom()}
  defp validate_void_remainder(opts) do
    with true <- opts[:void_remainder],
         {:ok, amount} <- integer(opts[:amount]),
         {:ok, capturable} <- integer(opts[:expected_capturable_amount]) do
      if amount < capturable, do: :ok, else: {:error, :void_remainder_full_capture}
    else
      false -> :ok
      _other -> {:error, :payload_format}
    end
  end

  @spec default_fee(map(), map(), term(), term()) :: {:ok, non_neg_integer()} | {:error, term()}
  defp default_fee(_ctx, _payment_info, _amount, fee) when not is_nil(fee) do
    case integer(fee) do
      {:ok, value} when value >= 0 -> {:ok, value}
      _other -> {:error, {:invalid_options, "fee must be a non-negative integer"}}
    end
  end

  defp default_fee(ctx, payment_info, amount, nil) do
    with {:ok, amount} <- integer_or(amount, :amount_mismatch),
         {:ok, min_bps} <-
           integer_or(Utils.map_value(payment_info, {"minFeeBps", :minFeeBps}), :extra) do
      case ctx.version do
        :v1_1 -> {:ok, EVM.fee_amount(amount, min_bps)}
        :v1_0 -> {:ok, min_bps}
      end
    end
  end

  @spec integer_or(term(), atom()) :: {:ok, integer()} | {:error, atom()}
  defp integer_or(value, reason) do
    case integer(value) do
      {:ok, integer} -> {:ok, integer}
      :error -> {:error, reason}
    end
  end

  @spec maybe_sign(term(), EVM.operation(), map(), map()) ::
          {:ok, String.t() | nil} | {:error, term()}
  defp maybe_sign(signer, operation, params, ctx) do
    with {:ok, address} <- Signer.address(signer),
         true <- EVM.nonzero_address?(ctx.receiver_authorizer),
         true <- String.downcase(address) == String.downcase(ctx.receiver_authorizer),
         :ok <- validate_intent(operation, params, ctx) do
      EVM.sign_consent(signer, operation, params, ctx.domain, ctx.version)
    else
      false -> {:error, :authorizer_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec validate_intent(EVM.operation(), map(), map()) :: :ok | {:error, term()}
  defp validate_intent(:void, _params, _ctx), do: :ok

  defp validate_intent(operation, params, ctx) do
    with {:ok, amount} <- integer_or(params["amount"], :amount_mismatch),
         {:ok, maximum} <-
           integer_or(
             Utils.map_value(ctx.payment_info, {"maxAmount", :maxAmount}),
             :amount_mismatch
           ),
         true <- amount > 0 and amount <= maximum,
         :ok <- validate_expected_balances(operation, params, maximum, amount) do
      validate_intent_fee(operation, params, ctx, amount)
    else
      false -> {:error, :amount_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec validate_expected_balances(EVM.operation(), map(), non_neg_integer(), non_neg_integer()) ::
          :ok | {:error, atom()}
  defp validate_expected_balances(:charge, _params, _maximum, _amount), do: :ok

  defp validate_expected_balances(operation, params, maximum, amount) do
    with {:ok, capturable} <- integer_or(params["expectedCapturableAmount"], :payload_format),
         {:ok, refundable} <- integer_or(params["expectedRefundableAmount"], :payload_format),
         true <- capturable + refundable <= maximum do
      available = if operation == :capture, do: capturable, else: refundable
      if amount <= available, do: :ok, else: {:error, :unexpected_payment_state}
    else
      false -> {:error, :unexpected_payment_state}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec validate_intent_fee(EVM.operation(), map(), map(), non_neg_integer()) ::
          :ok | {:error, term()}
  defp validate_intent_fee(:refund, _params, _ctx, _amount), do: :ok

  defp validate_intent_fee(_operation, params, ctx, amount) do
    with {:ok, fee} <- integer_or(params[EVM.fee_field(ctx.version)], :fee_bps_out_of_range),
         {:ok, min_bps} <-
           integer_or(Utils.map_value(ctx.payment_info, {"minFeeBps", :minFeeBps}), :extra),
         {:ok, max_bps} <-
           integer_or(Utils.map_value(ctx.payment_info, {"maxFeeBps", :maxFeeBps}), :extra) do
      EVM.check_fee(
        ctx.version,
        amount,
        fee,
        params["feeReceiver"],
        min_bps,
        max_bps,
        Utils.map_value(ctx.payment_info, {"feeReceiver", :feeReceiver})
      )
    end
  end

  @spec maybe_void_signature(keyword(), map()) :: {:ok, String.t() | nil} | {:error, term()}
  defp maybe_void_signature(opts, ctx) do
    case {opts[:void_remainder], opts[:authorizer]} do
      {false, _signer} ->
        {:ok, nil}

      {true, nil} ->
        {:error, {:invalid_options, ":void_remainder requires :authorizer"}}

      {true, signer} ->
        maybe_sign(signer, :void, %{"paymentInfoHash" => ctx.payment_info_hash}, ctx)
    end
  end

  @spec collector_data_hash(map(), :eip3009 | :permit2) :: {:ok, String.t()} | {:error, term()}
  defp collector_data_hash(payload, method) do
    with {:ok, keccak} <- EIP712.keccak_module(),
         "0x" <> hex_digits <- Utils.map_value(payload, {"signature", :signature}) || :missing,
         {:ok, bytes} <- Base.decode16(hex_digits, case: :mixed) do
      {:ok,
       "0x" <> Base.encode16(keccak.hash_256(EVM.collector_data(method, bytes)), case: :lower)}
    else
      :missing -> {:error, :payload_format}
      :error -> {:error, :payload_format}
      {:error, reason} -> {:error, reason}
      _other -> {:error, :payload_format}
    end
  end

  @spec amount_string(term()) :: String.t()
  defp amount_string(value) when is_integer(value), do: Integer.to_string(value)
  defp amount_string(value) when is_binary(value), do: value

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @spec envelope(map(), map()) :: map()
  defp envelope(requirements, payload),
    do: %{"x402Version" => @x402_version, "accepted" => requirements, "payload" => payload}
end
