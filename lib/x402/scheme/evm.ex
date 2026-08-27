defmodule X402.Scheme.EVM do
  @moduledoc """
  Shared local pre-checks for EVM authorization-style scheme payloads.

  Used by the built-in `X402.Scheme.ExactEVM` and `X402.Scheme.UptoEVM`
  schemes to implement `c:X402.Scheme.precheck/3`, and reusable by
  third-party EVM scheme modules whose payloads carry an EIP-3009-style
  `payload.authorization` object.

  The checks mirror the first checks every reference facilitator performs
  (payTo equality, exact amount equality, time window), so junk traffic is
  rejected without paying a facilitator verify call. Payloads without a
  `payload.authorization` map — other payload shapes, Permit2 — are skipped
  entirely, as is any individual absent field: the facilitator remains the
  authority, these checks only fail fast on certain mismatch.
  """

  alias X402.Utils

  # Mirrors the 6-second buffer the reference facilitators apply to
  # validBefore so a payment does not expire mid-settlement.
  @time_buffer_seconds 6

  @typedoc "Reasons an authorization pre-check fails."
  @type precheck_failure ::
          :pay_to_mismatch
          | :amount_mismatch
          | :invalid_authorization_value
          | :authorization_not_yet_valid
          | :authorization_expired
          | :invalid_authorization_timing

  @doc since: "0.6.0"
  @doc """
  Returns the settlement buffer applied to `validBefore`, in seconds.

  ## Examples

      iex> X402.Scheme.EVM.time_buffer_seconds()
      6
  """
  @spec time_buffer_seconds() :: pos_integer()
  def time_buffer_seconds, do: @time_buffer_seconds

  @doc since: "0.6.0"
  @doc """
  Runs cheap local checks on an EIP-3009-style `payload.authorization`.

  Checks, in order: the authorization's `to` must equal the requirements'
  `payTo` (case-insensitive for hex addresses); with `enforce_exact_amount:
  true` the authorization's `value` must equal the requirements' `amount`;
  and the `validAfter`/`validBefore` window must cover now (with a
  #{@time_buffer_seconds}s settlement buffer on `validBefore`). Payloads
  without a `payload.authorization` map pass with `:ok`, as does any
  individual absent field.

  ## Options

  * `:enforce_exact_amount` (default `false`) — require `authorization.value`
    to equal the requirements' `amount` exactly. Use for `exact`-style
    schemes; for ceiling schemes such as `upto`, the signed value is a
    maximum, not the settled amount.

  ## Examples

      iex> X402.Scheme.EVM.authorization_precheck(%{"payload" => %{}}, %{})
      :ok

      iex> payload = %{
      ...>   "payload" => %{"authorization" => %{"to" => "0xAb", "value" => "10"}}
      ...> }
      iex> requirements = %{"payTo" => "0xab", "amount" => "10"}
      iex> X402.Scheme.EVM.authorization_precheck(payload, requirements,
      ...>   enforce_exact_amount: true
      ...> )
      :ok

      iex> payload = %{
      ...>   "payload" => %{"authorization" => %{"to" => "0xother", "value" => "10"}}
      ...> }
      iex> X402.Scheme.EVM.authorization_precheck(payload, %{"payTo" => "0xab"})
      {:error, {:precheck_failed, :pay_to_mismatch}}
  """
  @spec authorization_precheck(map(), map(), keyword()) ::
          :ok | {:error, {:precheck_failed, precheck_failure()}}
  def authorization_precheck(payload, requirements, opts \\ [])
      when is_map(payload) and is_map(requirements) and is_list(opts) do
    case authorization(payload) do
      nil ->
        :ok

      authorization ->
        with :ok <- precheck_pay_to(authorization, requirements),
             :ok <-
               precheck_exact_amount(
                 Keyword.get(opts, :enforce_exact_amount, false),
                 authorization,
                 requirements
               ) do
          precheck_timing(authorization)
        end
    end
  end

  @spec authorization(map()) :: map() | nil
  defp authorization(payload) do
    case Utils.nested_map_value(payload, [
           {"payload", :payload},
           {"authorization", :authorization}
         ]) do
      authorization when is_map(authorization) -> authorization
      _other -> nil
    end
  end

  @spec precheck_pay_to(map(), map()) ::
          :ok | {:error, {:precheck_failed, :pay_to_mismatch}}
  defp precheck_pay_to(authorization, requirements) do
    to = Utils.map_value(authorization, {"to", :to})
    pay_to = Utils.map_value(requirements, {"payTo", :payTo})

    case is_binary(to) and is_binary(pay_to) do
      true ->
        case same_address?(to, pay_to) do
          true -> :ok
          false -> {:error, {:precheck_failed, :pay_to_mismatch}}
        end

      false ->
        :ok
    end
  end

  @spec same_address?(String.t(), String.t()) :: boolean()
  defp same_address?(left, right) do
    case hex_address?(left) and hex_address?(right) do
      true -> String.downcase(left) == String.downcase(right)
      false -> left == right
    end
  end

  @spec hex_address?(String.t()) :: boolean()
  defp hex_address?(<<"0x", rest::binary>>) when rest != "",
    do: Regex.match?(~r/^[0-9a-fA-F]+$/, rest)

  defp hex_address?(_address), do: false

  @spec precheck_exact_amount(boolean(), map(), map()) ::
          :ok | {:error, {:precheck_failed, :amount_mismatch | :invalid_authorization_value}}
  defp precheck_exact_amount(false, _authorization, _requirements), do: :ok

  defp precheck_exact_amount(true, authorization, requirements) do
    value = Utils.map_value(authorization, {"value", :value})
    amount = Utils.map_value(requirements, {"amount", :amount})

    case not is_nil(value) and not is_nil(amount) do
      true -> compare_exact_amount(value, amount)
      false -> :ok
    end
  end

  @spec compare_exact_amount(term(), term()) ::
          :ok | {:error, {:precheck_failed, :amount_mismatch | :invalid_authorization_value}}
  defp compare_exact_amount(value, amount) do
    with {:ok, parsed_value} <- parse_precheck_amount(value),
         {:ok, parsed_amount} <- parse_precheck_amount(amount) do
      case Utils.compare_decimal(parsed_value, parsed_amount) do
        :eq -> :ok
        _other -> {:error, {:precheck_failed, :amount_mismatch}}
      end
    end
  end

  @spec parse_precheck_amount(term()) ::
          {:ok, {non_neg_integer(), non_neg_integer()}}
          | {:error, {:precheck_failed, :invalid_authorization_value}}
  defp parse_precheck_amount(value) do
    case Utils.parse_decimal(value) do
      {:ok, parsed} -> {:ok, parsed}
      :error -> {:error, {:precheck_failed, :invalid_authorization_value}}
    end
  end

  @spec precheck_timing(map()) ::
          :ok
          | {:error,
             {:precheck_failed,
              :authorization_not_yet_valid
              | :authorization_expired
              | :invalid_authorization_timing}}
  defp precheck_timing(authorization) do
    now = System.system_time(:second)

    with {:ok, valid_after} <-
           optional_unix_time(Utils.map_value(authorization, {"validAfter", :validAfter})),
         {:ok, valid_before} <-
           optional_unix_time(Utils.map_value(authorization, {"validBefore", :validBefore})) do
      cond do
        is_integer(valid_after) and valid_after > now ->
          {:error, {:precheck_failed, :authorization_not_yet_valid}}

        is_integer(valid_before) and valid_before < now + @time_buffer_seconds ->
          {:error, {:precheck_failed, :authorization_expired}}

        true ->
          :ok
      end
    end
  end

  @spec optional_unix_time(term()) ::
          {:ok, integer() | nil} | {:error, {:precheck_failed, :invalid_authorization_timing}}
  defp optional_unix_time(nil), do: {:ok, nil}
  defp optional_unix_time(value) when is_integer(value), do: {:ok, value}

  defp optional_unix_time(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} -> {:ok, parsed}
      _other -> {:error, {:precheck_failed, :invalid_authorization_timing}}
    end
  end

  defp optional_unix_time(_value),
    do: {:error, {:precheck_failed, :invalid_authorization_timing}}
end
