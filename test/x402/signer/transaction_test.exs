defmodule X402.Signer.TransactionTest do
  use ExUnit.Case, async: true

  alias X402.EIP3009
  alias X402.Signer
  alias X402.Signer.LocalKey
  alias X402.Transaction

  @fixture File.read!(Path.expand("../../fixtures/auth_capture_transaction.json", __DIR__))
           |> Jason.decode!()

  defmodule ExternalSigner do
    @moduledoc false
    @behaviour Signer
    defstruct [:owner, :result]

    @impl Signer
    def address(_signer), do: {:error, :unused}

    @impl Signer
    def sign_transaction(signer, digest, transaction) do
      send(signer.owner, {:transaction_signature, digest, transaction})
      signer.result
    end
  end

  defmodule TypedDataOnly do
    @moduledoc false
    @behaviour Signer
    defstruct [:owner]

    @impl Signer
    def address(_signer), do: {:error, :unused}

    @impl Signer
    def sign_eip712(signer, _digest, _typed_data) do
      send(signer.owner, :wrong_callback)
      {:error, :unexpected}
    end
  end

  test "local transaction signing matches independent ethers bytes" do
    {:ok, signer} = LocalKey.new(<<1::256>>)
    transaction = transaction()
    assert {:ok, digest} = Transaction.digest(transaction)
    assert hex(digest) == @fixture["digest"]
    assert {:ok, signature} = Signer.sign_transaction(signer, transaction)
    assert hex(signature) == @fixture["signature"]
    assert EIP3009.recover_signer(digest, signature) == {:ok, @fixture["address"]}
    assert {:ok, raw} = Transaction.encode_signed(transaction, signature)
    assert hex(raw) == @fixture["raw"]
  end

  test "remote callbacks receive the exact transaction, not fake typed data" do
    signature = bytes(@fixture["signature"])
    <<compact::binary-size(64), v>> = signature
    signer = %ExternalSigner{owner: self(), result: {:ok, compact <> <<v - 27>>}}
    transaction = transaction()
    assert Signer.sign_transaction(signer, transaction) == {:ok, signature}
    assert_received {:transaction_signature, digest, ^transaction}
    assert hex(digest) == @fixture["digest"]
  end

  test "unsupported, invalid and denied requests never use typed-data fallback" do
    assert Signer.sign_transaction(%TypedDataOnly{owner: self()}, transaction()) ==
             {:error, :unsupported_signer}

    refute_received :wrong_callback
    assert Signer.sign_transaction(:bad, transaction()) == {:error, :invalid_signer}
    assert Signer.sign_transaction(%ExternalSigner{}, %{}) == {:error, :invalid_signer}
    signer = %ExternalSigner{owner: self(), result: {:ok, <<1, 2, 3>>}}

    assert Signer.sign_transaction(signer, %{transaction() | nonce: -1}) ==
             {:error, :invalid_transaction}

    refute_received {:transaction_signature, _, _}
    assert Signer.sign_transaction(signer, transaction()) == {:error, :invalid_signature_format}

    assert Signer.sign_transaction(%{signer | result: {:error, :denied}}, transaction()) ==
             {:error, :denied}
  end

  test "direct local callbacks reject mismatched or invalid transaction digests" do
    {:ok, signer} = LocalKey.new(<<1::256>>)

    assert LocalKey.sign_transaction(signer, <<0::256>>, transaction()) ==
             {:error, :invalid_digest}

    assert LocalKey.sign_transaction(signer, <<0::256>>, %{transaction() | nonce: -1}) ==
             {:error, :invalid_transaction}
  end

  @spec transaction() :: Transaction.t()
  defp transaction do
    tx = @fixture["transaction"]

    %Transaction{
      chain_id: tx["chainId"],
      nonce: tx["nonce"],
      max_priority_fee_per_gas: tx["maxPriorityFeePerGas"],
      max_fee_per_gas: tx["maxFeePerGas"],
      gas_limit: tx["gasLimit"],
      to: tx["to"],
      data: bytes(tx["data"]),
      value: tx["value"]
    }
  end

  @spec bytes(String.t()) :: binary()
  defp bytes("0x" <> value), do: Base.decode16!(value, case: :mixed)

  @spec hex(binary()) :: String.t()
  defp hex(value), do: "0x" <> Base.encode16(value, case: :lower)
end
