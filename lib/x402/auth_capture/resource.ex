defmodule X402.AuthCapture.Resource do
  @moduledoc """
  Durable hold-before-handler orchestration for auth-capture escrow resources.

  `run/4` accepts only an initial escrow authorization. It retains PaymentInfo,
  saltNonce, a pre-signed void, and durable execution phases. A confirmed hold
  precedes the handler. The handler returns `{:ok, json_value, actual_amount}`
  or `{:error, reason}`. Results must be plain JSON values without custom
  encoders, at most 64 levels deep and one MiB of encoded JSON.
  Invalid results and exceptions retain uncertain execution; they never
  authorize running the handler again.

  Synchronous resources capture actual usage and confirm voiding the remainder
  before returning content. Deferred resources may return content after durable
  metering; the application must subsequently call `resume/2` to capture and
  void. A valid pre-signed void is retained before funding, including for
  zero-charge or explicitly failed handlers.

  `resume/3` is application-only recovery. It may continue funding or settlement,
  and can run a supplied handler only if the durable executing phase has never
  been entered. It cannot recover the value or metering of a crashed handler.
  Never expose this API as an unauthenticated client endpoint.

  Production requires the executor's shared durable store. There are no leases,
  TTL eviction, or automatic retries of uncertain handler execution. Applications
  must schedule recovery and monitor unresolved payment records. Authorization
  flow (terminal charge) and standalone refunds use `X402.AuthCapture.Engine`
  directly; this resource orchestrates escrow flow only.
  """

  alias X402.AuthCapture
  alias X402.AuthCapture.Engine
  alias X402.AuthCapture.EVM
  alias X402.AuthCapture.Output
  alias X402.AuthCapture.Store
  alias X402.Signer
  alias X402.Utils

  @enforce_keys [:engine, :authorizer, :mode, :max_records]
  defstruct [:engine, :authorizer, :mode, :max_records]

  @type t :: %__MODULE__{
          engine: Engine.t(),
          authorizer: Signer.t(),
          mode: :sync | :deferred,
          max_records: pos_integer()
        }
  @type handler :: (-> {:ok, term(), non_neg_integer()} | {:error, term()})
  @type result :: {:ok, term(), map()} | {:pending, String.t()} | {:error, term()}
  @options [
    engine: [type: {:custom, __MODULE__, :validate_engine, []}, required: true],
    authorizer: [type: :any, required: true],
    mode: [type: {:in, [:sync, :deferred]}, default: :sync],
    max_records: [type: :pos_integer, default: 1000]
  ]

  @doc since: "0.9.0"
  @doc "Builds an escrow resource with an explicit receiver-consent signer."
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    with {:ok, opts} <- NimbleOptions.validate(opts, @options),
         {:ok, address} <- Signer.address(opts[:authorizer]),
         true <- EVM.nonzero_address?(address) do
      {:ok, struct!(__MODULE__, opts)}
    else
      false -> {:error, :invalid_authorizer}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  @spec validate_engine(term()) :: {:ok, Engine.t()} | {:error, String.t()}
  def validate_engine(%Engine{} = engine), do: {:ok, engine}
  def validate_engine(_engine), do: {:error, "expected an auth-capture engine"}

  @doc since: "0.9.0"
  @doc "Confirms a hold, executes once, and durably meters before returning content."
  @spec run(t(), map(), map(), handler()) :: result()
  def run(resource, envelope, requirements, handler) when is_function(handler, 0) do
    case run_guarded(resource, envelope, requirements, handler) do
      {:not_admitted, reason} -> {:error, reason}
      result -> result
    end
  end

  @doc false
  @spec run_guarded(t(), map(), map(), handler()) :: result() | {:not_admitted, term()}
  def run_guarded(resource, envelope, requirements, handler) do
    case prepare_admission(resource, envelope, requirements) do
      {:ok, proof, void} ->
        # A failed admission write can already be durable. Only failures
        # before this boundary permit transport claim release.
        with {:ok, entry} <- admit(resource, proof, envelope, requirements, void),
             do: continue(resource, entry, handler, false)

      {:error, reason} ->
        {:not_admitted, reason}
    end
  end

  @spec prepare_admission(t(), map(), map()) :: {:ok, map(), map()} | {:error, term()}
  defp prepare_admission(resource, envelope, requirements) do
    with {:ok, proof} <- verify(resource, envelope, requirements),
         {:ok, void} <-
           AuthCapture.void_payload(requirements, proof.payment_info,
             authorizer: resource.authorizer,
             salt_nonce: salt_nonce(envelope)
           ),
         {:ok, _consent} <- Engine.verify_consent(resource.engine, void, requirements) do
      {:ok, proof, void}
    end
  catch
    _kind, _reason -> {:error, :consent_preparation_failed}
  end

  @doc since: "0.9.0"
  @doc "Read-only verification of an initial authorization under this resource's flow and mode."
  @spec verify(t(), map(), map()) :: {:ok, map()} | {:error, term()}
  def verify(resource, envelope, requirements) do
    with :ok <- route(resource, envelope, requirements),
         {:ok, id} <- Engine.identify(resource.engine, envelope, requirements),
         :ok <- available(resource, id),
         do: Engine.verify(resource.engine, envelope, requirements)
  end

  @spec available(t(), String.t()) :: :ok | {:error, term()}
  defp available(resource, id) do
    quota_key = {:auth_capture_resource_quota, resource.engine.network, resource.engine.address}

    with {:ok, quota} <- Store.fetch(store(resource), quota_key),
         :ok <- quota_available(quota, resource.max_records),
         {:ok, nil} <- Store.fetch(store(resource), key(resource, id)) do
      :ok
    else
      {:ok, _existing} -> {:error, :payment_already_admitted}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec quota_available(map() | nil, pos_integer()) :: :ok | {:error, term()}
  defp quota_available(nil, _limit), do: :ok

  defp quota_available(%{count: count}, limit)
       when is_integer(count) and count >= 0 and count < limit, do: :ok

  defp quota_available(_quota, _limit), do: {:error, :resource_capacity_exhausted}

  @doc since: "0.9.0"
  @doc """
  Resumes safe financial work, never uncertain handler execution.

  Supply a handler only when recovering funding that has not reached execution.
  Deferred, already-metered work needs no handler.
  """
  @spec resume(t(), String.t(), handler() | nil) :: result()
  def resume(resource, payment_info_hash, handler \\ nil) do
    case Store.fetch(store(resource), key(resource, payment_info_hash)) do
      {:ok, entry} when is_map(entry) -> continue(resource, entry, handler, true)
      {:ok, nil} -> {:error, :unknown_payment}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec admit(t(), map(), map(), map(), map()) :: {:ok, map()} | {:error, term()}
  defp admit(resource, proof, envelope, requirements, void) do
    entry = %{
      id: proof.payment_info_hash,
      phase: :funding,
      envelope: envelope,
      requirements: requirements,
      payment_info: proof.payment_info,
      salt_nonce: salt_nonce(envelope),
      maximum: proof.amount,
      void: void,
      mode: resource.mode,
      charged: nil,
      funding: nil,
      capture: nil,
      settlement: nil,
      failure: nil
    }

    record_key = key(resource, entry.id)
    quota_key = {:auth_capture_resource_quota, resource.engine.network, resource.engine.address}

    Store.transact_many(store(resource), [record_key, quota_key], fn values ->
      reserve_record(
        values[record_key],
        values[quota_key],
        record_key,
        quota_key,
        entry,
        resource.max_records
      )
    end)
  end

  @spec reserve_record(map() | nil, map() | nil, tuple(), tuple(), map(), pos_integer()) ::
          tuple()
  defp reserve_record(nil, nil, record_key, quota_key, entry, limit),
    do: reserve_record(nil, %{count: 0}, record_key, quota_key, entry, limit)

  defp reserve_record(nil, %{count: count}, record_key, quota_key, entry, limit)
       when is_integer(count) and count >= 0 and count < limit,
       do: {:commit, %{record_key => entry, quota_key => %{count: count + 1}}, entry}

  defp reserve_record(nil, _quota, _record_key, _quota_key, _entry, _limit),
    do: {:abort, :resource_capacity_exhausted}

  defp reserve_record(_existing, _quota, _record_key, _quota_key, _entry, _limit),
    do: {:abort, :payment_already_admitted}

  @spec continue(t(), map(), handler() | nil, boolean()) :: result()
  defp continue(resource, %{phase: :funding} = entry, handler, recovering) do
    case Engine.execute(resource.engine, entry.envelope, entry.requirements) do
      {:ok, %{status: :pending}} ->
        {:pending, entry.id}

      {:ok, %{status: :confirmed} = funding} ->
        with {:ok, funded} <- advance(resource, entry, :funded, %{funding: funding}) do
          continue(resource, funded, handler, recovering)
        end

      {:ok, %{status: :reverted} = funding} ->
        with {:ok, failed} <- advance(resource, entry, :funding_failed, %{funding: funding}) do
          continue(resource, failed, handler, recovering)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp continue(resource, %{phase: :funding_failed} = entry, _handler, _recovering) do
    with {:ok, _} <- Engine.acknowledge(resource.engine, entry.funding.id),
         do: {:error, :funding_reverted}
  end

  defp continue(_resource, %{phase: :funded} = entry, nil, _recovering),
    do: {:pending, entry.id}

  defp continue(resource, %{phase: :funded} = entry, handler, recovering) do
    with :ok <- Engine.verify_hold(resource.engine, entry.void, entry.requirements, entry.maximum),
         {:ok, _} <- Engine.acknowledge(resource.engine, entry.funding.id),
         {:ok, executing} <- advance(resource, entry, :executing, %{}) do
      execute_handler(resource, executing, handler, recovering)
    end
  end

  defp continue(_resource, %{phase: :executing}, _handler, _recovering),
    do: {:error, :execution_uncertain}

  defp continue(
         resource,
         %{phase: :metered, mode: :deferred, charged: amount, failure: nil} = entry,
         _handler,
         false
       )
       when amount > 0,
       do: completed_result(resource, entry, :deferred)

  defp continue(resource, %{phase: :metered, charged: 0} = entry, handler, recovering) do
    with {:ok, voiding} <- advance(resource, entry, :voiding, %{}) do
      continue(resource, voiding, handler, recovering)
    end
  end

  defp continue(resource, %{phase: :metered} = entry, handler, recovering) do
    with {:ok, capture} <-
           AuthCapture.capture_payload(entry.requirements, entry.payment_info,
             authorizer: resource.authorizer,
             salt_nonce: entry.salt_nonce,
             amount: entry.charged,
             expected_capturable_amount: entry.maximum,
             expected_refundable_amount: 0
           ),
         {:ok, capturing} <- advance(resource, entry, :capturing, %{capture: capture}) do
      continue(resource, capturing, handler, recovering)
    end
  end

  defp continue(resource, %{phase: :capturing} = entry, handler, recovering),
    do: settle(resource, entry, entry.capture, :captured, handler, recovering)

  defp continue(resource, %{phase: :voiding} = entry, handler, recovering),
    do: settle(resource, entry, entry.void, :voided, handler, recovering)

  defp continue(resource, %{phase: :captured} = entry, handler, recovering) do
    with {:ok, _} <- Engine.acknowledge(resource.engine, entry.settlement.id) do
      phase = if entry.charged < entry.maximum, do: :voiding, else: :complete

      with {:ok, next} <- advance(resource, entry, phase, %{}) do
        continue(resource, next, handler, recovering)
      end
    end
  end

  defp continue(resource, %{phase: :voided} = entry, handler, recovering) do
    with {:ok, _} <- Engine.acknowledge(resource.engine, entry.settlement.id),
         {:ok, complete} <- advance(resource, entry, :complete, %{}) do
      continue(resource, complete, handler, recovering)
    end
  end

  defp continue(resource, %{phase: :complete} = entry, _handler, _recovering),
    do: completed_result(resource, entry, :settled)

  defp continue(resource, %{phase: :settlement_failed} = entry, _handler, _recovering) do
    with {:ok, _} <- Engine.acknowledge(resource.engine, entry.settlement.id),
         do: {:error, :settlement_reverted}
  end

  @spec execute_handler(t(), map(), handler(), boolean()) :: result()
  defp execute_handler(resource, entry, handler, recovering) do
    case handler.() do
      {:ok, value, amount} when is_integer(amount) and amount >= 0 and amount <= entry.maximum ->
        meter(resource, entry, value, amount, nil, recovering)

      {:error, _reason} ->
        meter(resource, entry, nil, 0, :handler_failed, recovering)

      _invalid ->
        {:error, :invalid_handler_result}
    end
  catch
    _kind, _reason -> {:error, :execution_uncertain}
  end

  @spec meter(t(), map(), term(), non_neg_integer(), atom() | nil, boolean()) :: result()
  defp meter(resource, entry, value, amount, failure, recovering) do
    with {:ok, json} <- Output.encode(value),
         {:ok, metered} <- persist_metering(resource, entry, json, amount, failure) do
      continue(resource, metered, nil, recovering)
    else
      _error -> {:error, :metering_uncertain}
    end
  end

  @spec persist_metering(t(), map(), binary(), non_neg_integer(), atom() | nil) ::
          {:ok, map()} | {:error, term()}
  defp persist_metering(resource, entry, json, amount, failure) do
    record_key = key(resource, entry.id)
    output_key = {record_key, :output}

    Store.transact_many(store(resource), [record_key, output_key], fn values ->
      if values[record_key] == entry and is_nil(values[output_key]) do
        next = %{entry | phase: :metered, charged: amount, failure: failure}
        {:commit, %{record_key => next, output_key => %{json: json}}, next}
      else
        {:abort, :payment_state_changed}
      end
    end)
  end

  @spec settle(t(), map(), map(), atom(), handler() | nil, boolean()) :: result()
  defp settle(resource, entry, envelope, phase, handler, recovering) do
    case Engine.execute(resource.engine, envelope, entry.requirements) do
      {:ok, %{status: :pending}} ->
        {:pending, entry.id}

      {:ok, %{status: status} = result} ->
        phase = if status == :confirmed, do: phase, else: :settlement_failed

        with {:ok, next} <- advance(resource, entry, phase, %{settlement: result}) do
          continue(resource, next, handler, recovering)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec advance(t(), map(), atom(), map()) :: {:ok, map()} | {:error, term()}
  defp advance(resource, entry, phase, changes) do
    Store.transact(store(resource), key(resource, entry.id), fn
      ^entry ->
        next = entry |> Map.merge(changes) |> Map.put(:phase, phase)
        {:commit, next, next}

      _changed ->
        {:abort, :payment_state_changed}
    end)
  end

  @spec completed_result(t(), map(), :settled | :deferred) :: result()
  defp completed_result(_resource, %{failure: :handler_failed}, _status),
    do: {:error, :handler_failed}

  defp completed_result(resource, entry, status) do
    with {:ok, %{json: json}} <- Store.fetch(store(resource), {key(resource, entry.id), :output}),
         {:ok, value} <- Jason.decode(json) do
      {:ok, value,
       %{
         status: status,
         payment_info_hash: entry.id,
         charged_amount: entry.charged,
         funding: entry.funding,
         settlement: entry.settlement
       }}
    else
      _error -> {:error, :stored_output_unavailable}
    end
  end

  @spec route(t(), map(), map()) :: :ok | {:error, term()}
  defp route(resource, envelope, requirements) do
    with {:ok, :escrow} <- AuthCapture.payment_flow(requirements),
         {:ok, mode} <- AuthCapture.capture_mode(requirements),
         true <- mode == resource.mode,
         {:ok, :authorize} <- AuthCapture.operation(envelope, requirements) do
      :ok
    else
      _unsupported -> {:error, :unsupported_resource_flow}
    end
  end

  @spec salt_nonce(map()) :: term()
  defp salt_nonce(envelope),
    do: Utils.nested_map_value(envelope, [{"payload", :payload}, {"saltNonce", :saltNonce}])

  @spec store(t()) :: Store.t()
  defp store(resource), do: resource.engine.journal.store
  @spec key(t(), String.t()) :: tuple()
  defp key(resource, id), do: {:auth_capture_resource, resource.engine.network, id}
end
