defmodule X402.AuthCapture.Transport do
  @moduledoc false

  alias X402.AuthCapture
  alias X402.AuthCapture.EVM
  alias X402.AuthCapture.Resource
  alias X402.Utils

  @doc false
  @spec validate_resource(term()) :: {:ok, Resource.t() | nil} | {:error, String.t()}
  def validate_resource(nil), do: {:ok, nil}
  def validate_resource(%Resource{} = resource), do: {:ok, resource}
  def validate_resource(_resource), do: {:error, "expected an auth-capture resource"}

  @doc false
  @spec replay_key(term(), map()) :: {:ok, String.t()} | :error
  def replay_key(payload, requirements) when is_map(payload) do
    with {:ok, method} <- AuthCapture.asset_transfer_method(requirements),
         %{} = authorization <- authorization(payload, method),
         from when is_binary(from) <- Utils.map_value(authorization, {"from", :from}),
         true <- EVM.nonzero_address?(from),
         {:ok, nonce} <- nonce(Utils.map_value(authorization, {"nonce", :nonce}), method) do
      identity =
        {requirements["network"], method, String.downcase(requirements["asset"]),
         String.downcase(from), nonce}

      {:ok,
       "auth-capture:" <>
         Base.encode16(
           :crypto.hash(
             :sha256,
             :erlang.term_to_binary(identity, [:deterministic])
           ),
           case: :lower
         )}
    else
      _invalid -> :error
    end
  end

  def replay_key(_payload, _requirements), do: :error

  @spec authorization(map(), :eip3009 | :permit2) :: term()
  defp authorization(payload, :eip3009),
    do: Utils.map_value(payload, {"authorization", :authorization})

  defp authorization(payload, :permit2),
    do: Utils.map_value(payload, {"permit2Authorization", :permit2Authorization})

  @spec nonce(term(), :eip3009 | :permit2) :: {:ok, term()} | :error
  defp nonce("0x" <> hex, :eip3009) when byte_size(hex) == 64,
    do: Base.decode16(hex, case: :mixed)

  defp nonce(value, :permit2) do
    case EVM.parse_uint256(value) do
      {:ok, nonce} -> {:ok, nonce}
      _invalid -> :error
    end
  end

  defp nonce(_value, _method), do: :error

  @doc false
  @spec verify(Resource.t() | nil, map(), map()) :: {:ok, map()} | {:error, term()}
  def verify(nil, _envelope, _requirements), do: {:error, :auth_capture_resource_required}

  def verify(resource, envelope, requirements) do
    case Resource.verify(resource, envelope, requirements) do
      {:ok, proof} ->
        {:ok, %{status: 200, body: %{"isValid" => true, "payer" => proof.payer}}}

      {:error, {:invalid, reason}} ->
        {:error, {:verification_failed, X402.AuthCapture.reason_string(reason)}}

      {:error, reason} ->
        {:error, {:local_verification_error, reason}}
    end
  end

  @doc false
  @spec response(map(), map()) :: map()
  def response(receipt, requirements) do
    settlement = receipt.settlement || receipt.funding

    %{
      "success" => true,
      "transaction" => settlement.transaction,
      "network" => requirements["network"],
      "payer" => receipt.funding.payer,
      "amount" => Integer.to_string(receipt.charged_amount),
      "paymentInfoHash" => receipt.payment_info_hash,
      "settlementStatus" => Atom.to_string(receipt.status),
      "fundingTransaction" => receipt.funding.transaction
    }
  end
end
