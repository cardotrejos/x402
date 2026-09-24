defmodule X402.AuthCapture.Receipt do
  @moduledoc """
  Strict auth-capture receipt identity and escrow-event checks.

  Expected events come from the execution layer's full verification result,
  not a request-provided assertion. Successful receipts must contain exactly
  one matching event from the configured escrow, with canonical ABI data and
  matching transaction/block provenance. Reverted receipts must have no logs.

  This pure check does not establish chain identity, canonical inclusion, or
  finality. The execution layer must check those against its trusted RPC before
  recording a final journal outcome. Contract addresses are deployment
  configuration, not independent runtime-code authenticity proofs.
  """

  alias X402.AuthCapture
  alias X402.AuthCapture.EVM
  alias X402.EIP712
  alias X402.RPC
  alias X402.Verify.AuthCaptureEVM

  @type event :: %{address: String.t(), topics: [String.t()], data: String.t()}
  @type identity :: %{hash: String.t(), from: String.t(), to: String.t()}
  @type inclusion :: %{
          outcome: :confirmed | :reverted,
          block_hash: String.t(),
          block_number: non_neg_integer(),
          transaction_index: non_neg_integer()
        }

  @doc since: "0.9.0"
  @doc """
  Builds the exact escrow event for a fully verified operation.

  `:primary` selects the original operation. `:void_remainder` selects the
  separately submitted void leg after a partial capture and uses the remaining
  capturable balance, not the captured amount.

  ## Examples

      iex> X402.AuthCapture.Receipt.expected_event(%{})
      {:error, :invalid_verification}
  """
  @spec expected_event(AuthCaptureEVM.verification(), :primary | :void_remainder) ::
          {:ok, event()} | {:error, term()}
  def expected_event(verification, leg \\ :primary)

  def expected_event(%{level: :full, deployment: deployment} = proof, leg) do
    with {:ok, operation, amount} <- operation(proof, leg),
         {:ok, data} <- event_data(operation, amount, proof),
         {:ok, hash} <-
           EVM.payment_info_hash(proof.chain_id, deployment.escrow, proof.payment_info) do
      {:ok,
       %{
         address: String.downcase(deployment.escrow),
         topics: [topic(operation, deployment.version), hash],
         data: hex(data)
       }}
    end
  end

  def expected_event(_verification, _leg), do: {:error, :invalid_verification}

  @doc since: "0.9.0"
  @doc """
  Checks receipt identity, status and event data, returning unfinalized inclusion.

  `identity` must come from the frozen transaction. A successful result still
  needs canonical-block and confirmation-depth checks by the execution layer.

  ## Examples

      iex> X402.AuthCapture.Receipt.check(nil, %{}, %{})
      {:error, :invalid_receipt}
  """
  @spec check(term(), identity(), event()) :: {:ok, inclusion()} | {:error, atom()}
  def check(receipt, identity, event) when is_map(receipt) and is_map(identity) do
    with true <- same_hex?(receipt["transactionHash"], identity[:hash], 32),
         true <- same_hex?(receipt["from"], identity[:from], 20),
         true <- same_hex?(receipt["to"], identity[:to], 20),
         {:ok, block_hash} <- canonical_hex(receipt["blockHash"], 32),
         {:ok, block_number} <- RPC.decode_quantity(receipt["blockNumber"]),
         {:ok, index} <- RPC.decode_quantity(receipt["transactionIndex"]),
         {:ok, outcome} <- outcome(receipt, event) do
      {:ok,
       %{
         outcome: outcome,
         block_hash: block_hash,
         block_number: block_number,
         transaction_index: index
       }}
    else
      _invalid -> {:error, :invalid_receipt}
    end
  end

  def check(_receipt, _identity, _event), do: {:error, :invalid_receipt}

  @spec operation(map(), atom()) :: {:ok, atom(), non_neg_integer()} | {:error, atom()}
  defp operation(%{operation: :void, payment_state: state}, :primary),
    do: {:ok, :void, state.capturable_amount}

  defp operation(%{operation: operation, amount: amount}, :primary)
       when operation in [:authorize, :charge, :capture, :refund],
       do: {:ok, operation, amount}

  defp operation(
         %{operation: :capture, amount: amount, payment_state: state, void_calldata: calldata},
         :void_remainder
       )
       when is_binary(calldata) do
    if state.capturable_amount > amount,
      do: {:ok, :void, state.capturable_amount - amount},
      else: {:error, :invalid_void_remainder}
  end

  defp operation(_proof, _leg), do: {:error, :invalid_verification}

  @spec event_data(atom(), non_neg_integer(), map()) :: {:ok, binary()} | {:error, term()}
  defp event_data(:void, amount, _proof), do: EIP712.encode_uint256(amount)

  defp event_data(:refund, amount, proof) do
    with {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, collector} <- EIP712.encode_address(proof.deployment.refund_collector) do
      {:ok, amount_word <> collector}
    end
  end

  defp event_data(:capture, amount, proof), do: fee_words(amount, proof)

  defp event_data(operation, amount, proof) when operation in [:authorize, :charge] do
    with {:ok, info} <- EVM.encode_payment_info(proof.payment_info),
         {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, collector} <-
           EIP712.encode_address(AuthCapture.collector(proof.deployment, proof.method)),
         {:ok, fee} <- collect_fee(operation, proof) do
      {:ok, info <> amount_word <> collector <> fee}
    end
  end

  @spec collect_fee(atom(), map()) :: {:ok, binary()} | {:error, term()}
  defp collect_fee(:authorize, _proof), do: {:ok, <<>>}

  defp collect_fee(:charge, proof) do
    with {:ok, <<_amount::binary-size(32), fee::binary>>} <- fee_words(proof.amount, proof),
         do: {:ok, fee}
  end

  @spec fee_words(non_neg_integer(), map()) :: {:ok, binary()} | {:error, term()}
  defp fee_words(amount, proof) do
    with {:ok, amount_word} <- EIP712.encode_uint256(amount),
         {:ok, fee} <- EIP712.encode_uint256(proof.fee),
         {:ok, receiver} <- EIP712.encode_address(proof.fee_receiver) do
      {:ok, amount_word <> fee <> receiver}
    end
  end

  @spec topic(atom(), :v1_0 | :v1_1) :: String.t()
  defp topic(:authorize, _version), do: EVM.event_topic(:authorized)
  defp topic(:charge, :v1_0), do: EVM.event_topic(:charged_v1_0)
  defp topic(:charge, :v1_1), do: EVM.event_topic(:charged_v1_1)
  defp topic(:capture, :v1_0), do: EVM.event_topic(:captured_v1_0)
  defp topic(:capture, :v1_1), do: EVM.event_topic(:captured_v1_1)
  defp topic(:void, _version), do: EVM.event_topic(:voided)
  defp topic(:refund, _version), do: EVM.event_topic(:refunded)

  @spec outcome(map(), event()) :: {:ok, :confirmed | :reverted} | :error
  defp outcome(%{"status" => "0x0", "logs" => []}, _event), do: {:ok, :reverted}

  defp outcome(%{"status" => "0x1", "logs" => logs} = receipt, event)
       when is_list(logs) and length(logs) <= 4096 do
    case Enum.filter(logs, &event_identity?(&1, event)) do
      [log] ->
        if valid_log?(log, receipt, event), do: {:ok, :confirmed}, else: :error

      _other ->
        :error
    end
  end

  defp outcome(_receipt, _event), do: :error

  @spec event_identity?(term(), event()) :: boolean()
  defp event_identity?(%{"address" => address, "topics" => [signature, hash]}, event) do
    [expected_signature, expected_hash] = event.topics

    same_hex?(address, event.address, 20) and
      same_hex?(signature, expected_signature, 32) and same_hex?(hash, expected_hash, 32)
  end

  defp event_identity?(_log, _event), do: false

  @spec valid_log?(map(), map(), event()) :: boolean()
  defp valid_log?(log, receipt, event) do
    log["removed"] == false and
      same_hex?(log["data"], event.data, div(byte_size(event.data) - 2, 2)) and
      same_hex?(log["transactionHash"], receipt["transactionHash"], 32) and
      same_hex?(log["blockHash"], receipt["blockHash"], 32) and
      log["blockNumber"] == receipt["blockNumber"] and
      log["transactionIndex"] == receipt["transactionIndex"] and
      match?({:ok, _}, RPC.decode_quantity(log["logIndex"]))
  end

  @spec same_hex?(term(), term(), pos_integer()) :: boolean()
  defp same_hex?(left, right, size) do
    with {:ok, value} <- canonical_hex(left, size),
         {:ok, ^value} <- canonical_hex(right, size) do
      true
    else
      _invalid -> false
    end
  end

  @spec canonical_hex(term(), pos_integer()) :: {:ok, String.t()} | :error
  defp canonical_hex("0x" <> hex, size) when byte_size(hex) == size * 2 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, _bytes} -> {:ok, "0x" <> String.downcase(hex)}
      :error -> :error
    end
  end

  defp canonical_hex(_value, _size), do: :error

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)
end
