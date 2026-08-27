defmodule X402.Scheme.UptoEVM do
  @moduledoc """
  Built-in `X402.Scheme` for `upto` payments on EVM (`eip155:*`) networks.

  Server-side only in this release: `c:X402.Scheme.validate_payload/3`
  validates that the payment value the client signed does not exceed the
  advertised maximum (the requirements' `amount`, with `maxPrice` and
  `maxAmountRequired` fallbacks), recognizing the Permit2
  (`permit2Authorization.permitted.amount`), `maxAmount`, `value`, and
  EIP-3009 `authorization.value` payload shapes. Failures are
  `{:error, {:invalid_upto_payment, reason}}` — see `t:validation_error/0`.

  Pre-checks reuse the shared EIP-3009 authorization checks
  (`X402.Scheme.EVM.authorization_precheck/3` — payTo binding and validity
  window) without the exact-amount equality: for `upto`, the signed value
  is a ceiling, not the settled amount.

  `c:X402.Scheme.sign/3` is intentionally not implemented — `X402.Client`
  cannot yet sign `upto` payments, so `upto` requirements return
  `{:error, {:unsupported_kind, "upto", network}}` from
  `X402.Client.build_payment/3`.
  """

  @behaviour X402.Scheme

  alias X402.Scheme.EVM
  alias X402.Utils

  @typedoc "Reasons an `upto` payment fails ceiling validation."
  @type validation_error ::
          :missing_max_price
          | :missing_payment_value
          | :invalid_max_price
          | :invalid_payment_value
          | :payment_value_exceeds_max_price

  @doc since: "0.6.0"
  @doc """
  Returns `"upto"`.

  ## Examples

      iex> X402.Scheme.UptoEVM.scheme()
      "upto"
  """
  @impl X402.Scheme
  @spec scheme() :: String.t()
  def scheme, do: "upto"

  @doc since: "0.6.0"
  @doc """
  Returns `["eip155:*"]` — every EVM network.

  ## Examples

      iex> X402.Scheme.UptoEVM.networks()
      ["eip155:*"]
  """
  @impl X402.Scheme
  @spec networks() :: [String.t()]
  def networks, do: ["eip155:*"]

  @doc since: "0.6.0"
  @doc """
  Validates that the signed payment value stays within the ceiling.

  ## Examples

      iex> X402.Scheme.UptoEVM.validate_payload(
      ...>   %{"payload" => %{"value" => "9000"}},
      ...>   %{"amount" => "10000"},
      ...>   []
      ...> )
      :ok

      iex> X402.Scheme.UptoEVM.validate_payload(
      ...>   %{"payload" => %{"value" => "10001"}},
      ...>   %{"amount" => "10000"},
      ...>   []
      ...> )
      {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
  """
  @impl X402.Scheme
  @spec validate_payload(map(), map(), keyword()) ::
          :ok | {:error, {:invalid_upto_payment, validation_error()}}
  def validate_payload(payload, requirements, _opts) do
    with {:ok, max_price} <- extract_max_price(payload, requirements),
         {:ok, payment_value} <- extract_payment_value(payload) do
      ensure_not_exceeds(payment_value, max_price)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Runs `X402.Scheme.EVM.authorization_precheck/3` without exact-amount
  equality — for `upto`, the signed value is a ceiling.
  """
  @impl X402.Scheme
  @spec precheck(map(), map(), keyword()) ::
          :ok | {:error, {:precheck_failed, EVM.precheck_failure()}}
  def precheck(payload, requirements, _opts) do
    EVM.authorization_precheck(payload, requirements, enforce_exact_amount: false)
  end

  @spec extract_max_price(map(), map()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:invalid_upto_payment, :missing_max_price | :invalid_max_price}}
  defp extract_max_price(payload, requirements) do
    value =
      Utils.first_present([
        Utils.map_value(requirements, {"amount", :amount}),
        Utils.map_value(requirements, {"maxPrice", :maxPrice}),
        Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired}),
        Utils.nested_map_value(payload, [{"accepted", :accepted}, {"amount", :amount}]),
        Utils.map_value(payload, {"maxPrice", :maxPrice}),
        Utils.map_value(payload, {"maxAmountRequired", :maxAmountRequired})
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_max_price}}

      max_price ->
        case Utils.parse_decimal(max_price) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_max_price}}
        end
    end
  end

  @spec extract_payment_value(map()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:invalid_upto_payment, :missing_payment_value | :invalid_payment_value}}
  defp extract_payment_value(payload) do
    value =
      Utils.first_present([
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"maxAmount", :maxAmount}]),
        Utils.map_value(payload, {"maxAmount", :maxAmount}),
        Utils.map_value(payload, {"value", :value}),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"value", :value}]),
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"authorization", :authorization},
          {"value", :value}
        ]),
        Utils.nested_map_value(payload, [{"authorization", :authorization}, {"value", :value}])
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_payment_value}}

      payment_value ->
        case Utils.parse_decimal(payment_value) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_payment_value}}
        end
    end
  end

  @spec ensure_not_exceeds(
          {non_neg_integer(), non_neg_integer()},
          {non_neg_integer(), non_neg_integer()}
        ) :: :ok | {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
  defp ensure_not_exceeds(payment_value, max_price) do
    case Utils.compare_decimal(payment_value, max_price) do
      :gt -> {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
      _comparison -> :ok
    end
  end
end
