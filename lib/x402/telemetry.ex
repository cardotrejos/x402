defmodule X402.Telemetry do
  @moduledoc """
  Telemetry event definitions and emission helpers for x402 operations.

  All events emitted by this library use the `[:x402, module, operation]` format
  and include `%{count: 1}` as measurements.

  Emitted events:

  - `[:x402, :payment_required, :encode]`
  - `[:x402, :payment_required, :decode]`
  - `[:x402, :payment_signature, :decode]`
  - `[:x402, :payment_signature, :validate]`
  - `[:x402, :payment_signature, :decode_and_validate]`
  - `[:x402, :payment_response, :encode]`
  - `[:x402, :payment_response, :decode]`
  - `[:x402, :extension_responses, :decode]`
  - `[:x402, :payment_identifier, :legacy]` — a deprecated `paymentIdentifier`
    format id was received (metadata `:source` is `:gate` or `:mcp`)
  - `[:x402, :siwx, :legacy]` — a deprecated `{message, signature}`
    `SIGN-IN-WITH-X` header was received (metadata `:source` is `:gate`)
  - `[:x402, :client, :select]`
  - `[:x402, :client, :sign]`
  - `[:x402, :client, :build]`
  - `[:x402, :client, :request]`
  - `[:x402, :client, :siwx]` — a payer client answered a Sign-In-With-X
    challenge (metadata `:transport`, `:chain_id`, and `:outcome` —
    `:authenticated` or `:payment_required` — or `:reason` on error).
    `:chain_id` is the selected signing chain, never `:auto`, and is `nil`
    on errors before chain selection. Direct `X402.Client.SIWX` calls
    default `:transport` to `nil`; HTTP/MCP drivers always identify it.
  - `[:x402, :rpc, :request]`
  - `[:x402, :verify, :evm]`
  - `[:x402, :verify, :svm]`
  - `[:x402, :facilitator_engine, :verify]`
  - `[:x402, :facilitator_engine, :settle]`

  Metadata always includes `:status` (`:ok` or `:error`) and may include
  additional operation-specific fields such as `:reason`, `:header`, or
  `:fields`.
  """

  @type module_name ::
          :payment_required
          | :payment_signature
          | :payment_response
          | :extension_responses
          | :payment_identifier
          | :siwx
          | :client
          | :rpc
          | :verify
          | :facilitator_engine
  @type operation ::
          :encode
          | :decode
          | :validate
          | :decode_and_validate
          | :select
          | :sign
          | :build
          | :request
          | :evm
          | :svm
          | :verify
          | :settle
          | :legacy
          | :siwx
  @type status :: :ok | :error

  @doc since: "0.1.0"
  @doc """
  Returns the telemetry event name for a module and operation.

  ## Examples

      iex> X402.Telemetry.event_name(:payment_required, :encode)
      [:x402, :payment_required, :encode]
  """
  @spec event_name(module_name(), operation()) :: [atom()]
  def event_name(module_name, operation), do: [:x402, module_name, operation]

  @doc since: "0.1.0"
  @doc """
  Emits an x402 telemetry event.

  ## Examples

      iex> X402.Telemetry.emit(:payment_required, :encode, :ok, %{header: "PAYMENT-REQUIRED"})
      :ok
  """
  @spec emit(module_name(), operation(), status(), map()) :: :ok
  def emit(module_name, operation, status, metadata \\ %{}) do
    final_metadata = Map.put(metadata, :status, status)
    :telemetry.execute(event_name(module_name, operation), %{count: 1}, final_metadata)
  end
end
