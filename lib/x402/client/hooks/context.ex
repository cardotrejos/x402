defmodule X402.Client.Hooks.Context do
  @moduledoc """
  Context passed between `X402.Client.Hooks` callbacks.

  * `:payment_required` — the decoded `PaymentRequired` map the payment is
    built for, or `nil` when `X402.Client.build_payment/3` was given a bare
    requirements map.
  * `:requirements` — the selected `accepts` entry. `before_payment/2` may
    replace it; the replacement is what gets signed.
  * `:opts` — the validated build options.
  * `:payload` — the assembled `PaymentPayload`, set for `after_payment/2`,
    which may replace it.
  * `:error` — the failure reason, set for `on_payment_failure/2`, which may
    replace it.
  """

  @enforce_keys [:requirements]
  defstruct payment_required: nil, requirements: %{}, opts: [], payload: nil, error: nil

  @type t :: %__MODULE__{
          payment_required: map() | nil,
          requirements: map(),
          opts: keyword(),
          payload: map() | nil,
          error: term() | nil
        }

  @doc since: "0.9.0"
  @doc """
  Builds a new client hook context.

  ## Examples

      iex> requirements = %{"scheme" => "exact", "network" => "eip155:8453"}
      iex> context = X402.Client.Hooks.Context.new(%{"accepts" => [requirements]}, requirements, [])
      iex> context.requirements["scheme"]
      "exact"
      iex> {context.payload, context.error}
      {nil, nil}
  """
  @spec new(map() | nil, map(), keyword()) :: t()
  def new(payment_required, requirements, opts)
      when (is_map(payment_required) or is_nil(payment_required)) and is_map(requirements) and
             is_list(opts) do
    %__MODULE__{payment_required: payment_required, requirements: requirements, opts: opts}
  end
end
