defmodule X402.Extensions.SIWX.Storage do
  @moduledoc """
  Behaviour for storing SIWX access records.

  Storage adapters persist wallet access grants keyed by `{address, resource}`.
  """

  use X402.Behaviour, callbacks: [get: 2, put: 4, delete: 2]

  @typedoc "Stored access record for a wallet/resource pair."
  @type access_record :: %{
          required(:payment_proof) => term(),
          required(:expires_at_ms) => non_neg_integer()
        }

  @doc """
  Fetches an access record by wallet address and resource identifier.
  """
  @callback get(address :: String.t(), resource :: String.t()) ::
              {:ok, access_record()} | {:error, :not_found}

  @doc """
  Stores an access record for a wallet/resource pair with a TTL in milliseconds.
  """
  @callback put(
              address :: String.t(),
              resource :: String.t(),
              payment_proof :: term(),
              ttl_ms :: non_neg_integer()
            ) :: :ok | {:error, term()}

  @doc """
  Deletes an access record by wallet address and resource identifier.
  """
  @callback delete(address :: String.t(), resource :: String.t()) :: :ok

  @doc since: "0.3.0"
  @doc """
  Validates that a value is a module implementing `X402.Extensions.SIWX.Storage`.

  This function is intended for `NimbleOptions` custom validation.
  """
  @spec validate_module(term()) :: :ok | {:error, String.t()}
  def validate_module(module),
    do: X402.Behaviour.validate_implementation(module, __MODULE__, @required_callbacks)
end
