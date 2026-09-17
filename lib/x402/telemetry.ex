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
    `:authenticated` or `:payment_required` — or `:reason` on error)
  - `[:x402, :rpc, :request]`
  - `[:x402, :verify, :evm]`
  - `[:x402, :verify, :svm]`
  - `[:x402, :facilitator_engine, :verify]`
  - `[:x402, :facilitator_engine, :settle]`

  Metadata always includes `:status` (`:ok` or `:error`) and may include
  additional operation-specific fields such as `:reason`, `:header`, or
  `:fields`.

  Other modules emit events outside this helper — the payment gate
  (`[:x402, :plug, ...]`), the MCP transport (`[:x402, :mcp, ...]`), and
  the facilitator client (`:telemetry.span/3` events under
  `[:x402, :facilitator, operation]` plus `[:x402, :facilitator, :failover]`).
  `events/0` lists every event name the library can emit, and
  `X402.Telemetry.Metrics` / `X402.Telemetry.Stats` build on that list.
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

  @typedoc "A telemetry event name emitted by this library."
  @type event :: [atom(), ...]

  @emit_events [
    [:x402, :payment_required, :encode],
    [:x402, :payment_required, :decode],
    [:x402, :payment_signature, :decode],
    [:x402, :payment_signature, :validate],
    [:x402, :payment_signature, :decode_and_validate],
    [:x402, :payment_response, :encode],
    [:x402, :payment_response, :decode],
    [:x402, :extension_responses, :decode],
    [:x402, :payment_identifier, :legacy],
    [:x402, :siwx, :legacy],
    [:x402, :client, :select],
    [:x402, :client, :sign],
    [:x402, :client, :build],
    [:x402, :client, :request],
    [:x402, :client, :siwx],
    [:x402, :rpc, :request],
    [:x402, :verify, :evm],
    [:x402, :verify, :svm],
    [:x402, :facilitator_engine, :verify],
    [:x402, :facilitator_engine, :settle]
  ]

  @plug_events [
    [:x402, :plug, :pass_through],
    [:x402, :plug, :payment_required],
    [:x402, :plug, :payment_verified],
    [:x402, :plug, :payment_rejected],
    [:x402, :plug, :siwx_authenticated],
    [:x402, :plug, :rate_limited]
  ]

  @mcp_events [
    [:x402, :mcp, :payment_required],
    [:x402, :mcp, :payment_verified],
    [:x402, :mcp, :payment_rejected],
    [:x402, :mcp, :call]
  ]

  @facilitator_operations [:verify, :settle, :supported, :list_resources, :search_resources]

  @facilitator_span_events for operation <- @facilitator_operations,
                               suffix <- [:start, :stop, :exception],
                               do: [:x402, :facilitator, operation, suffix]

  @facilitator_events @facilitator_span_events ++ [[:x402, :facilitator, :failover]]

  @events @emit_events ++ @plug_events ++ @mcp_events ++ @facilitator_events

  @doc since: "0.9.0"
  @doc """
  Returns every telemetry event name this library can emit.

  Span operations (`X402.Facilitator` verify, settle, supported, discovery)
  are listed as their `:start`, `:stop`, and `:exception` events.

  ## Examples

      iex> [:x402, :plug, :rate_limited] in X402.Telemetry.events()
      true

      iex> [:x402, :facilitator, :settle, :stop] in X402.Telemetry.events()
      true
  """
  @spec events() :: [event()]
  def events, do: @events

  @doc since: "0.9.0"
  @doc """
  Returns the facilitator client operations instrumented with `:telemetry.span/3`.

  ## Examples

      iex> X402.Telemetry.facilitator_operations()
      [:verify, :settle, :supported, :list_resources, :search_resources]
  """
  @spec facilitator_operations() :: [atom()]
  def facilitator_operations, do: @facilitator_operations

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
