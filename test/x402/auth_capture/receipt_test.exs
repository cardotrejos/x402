defmodule X402.AuthCapture.ReceiptTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture.Receipt

  alias X402.AuthCapture.EVM
  alias X402.AuthCapture.Receipt
  alias X402.TestAuthCapture, as: Fixture

  @events File.read!(Path.expand("../../fixtures/auth_capture_events.json", __DIR__))
          |> Jason.decode!()
  @hash "0x" <> String.duplicate("ab", 32)
  @block "0x" <> String.duplicate("cd", 32)

  test "all deployment, method and salt variants match independent ethers event ABI" do
    for vector <- Fixture.fixture()["vectors"],
        operation <- [:authorize, :charge, :capture, :void, :refund] do
      expected = event(vector, operation)
      assert Receipt.expected_event(proof(vector, operation)) == {:ok, expected}
      identity = identity(vector)
      receipt = receipt(expected, identity)

      assert {:ok,
              %{outcome: :confirmed, block_hash: @block, block_number: 16, transaction_index: 0}} =
               Receipt.check(receipt, identity, expected)
    end
  end

  test "capture remainder uses the post-capture balance" do
    vector = Fixture.vector()

    proof = %{
      proof(vector, :capture)
      | payment_state: %{capturable_amount: 1_000_000},
        void_calldata: <<1>>
    }

    assert Receipt.expected_event(proof, :void_remainder) == {:ok, event(vector, :void)}

    assert Receipt.expected_event(%{proof | amount: 1_000_000}, :void_remainder) ==
             {:error, :invalid_void_remainder}

    assert Receipt.expected_event(%{proof | void_calldata: nil}, :void_remainder) ==
             {:error, :invalid_verification}

    assert Receipt.expected_event(%{proof | level: :signature}) == {:error, :invalid_verification}
    assert Receipt.expected_event(proof, :other) == {:error, :invalid_verification}
  end

  test "reverted receipts must have no logs and still bind transaction identity" do
    vector = Fixture.vector()
    expected = event(vector, :authorize)
    identity = identity(vector)
    valid = %{receipt(expected, identity) | "status" => "0x0", "logs" => []}
    assert {:ok, %{outcome: :reverted}} = Receipt.check(valid, identity, expected)

    assert Receipt.check(%{valid | "transactionHash" => @block}, identity, expected) ==
             {:error, :invalid_receipt}

    assert Receipt.check(%{receipt(expected, identity) | "status" => "0x0"}, identity, expected) ==
             {:error, :invalid_receipt}
  end

  test "wrong receipt identities, quantities and statuses are rejected" do
    vector = Fixture.vector()
    expected = event(vector, :capture)
    identity = identity(vector)
    receipt = receipt(expected, identity)

    for {key, value} <- [
          {"transactionHash", @block},
          {"from", expected.address},
          {"to", identity.from},
          {"blockHash", "0xno"},
          {"blockNumber", "0x00"},
          {"blockNumber", "0x-1"},
          {"blockNumber", "0x" <> String.duplicate("a", 65)},
          {"transactionIndex", nil},
          {"status", "0x2"},
          {"logs", nil},
          {"logs", []}
        ] do
      assert Receipt.check(Map.put(receipt, key, value), identity, expected) ==
               {:error, :invalid_receipt}
    end
  end

  test "event provenance, exact ABI and uniqueness are mandatory" do
    vector = Fixture.vector()
    expected = event(vector, :authorize)
    identity = identity(vector)
    receipt = receipt(expected, identity)
    [log] = receipt["logs"]

    for {key, value} <- [
          {"address", identity.from},
          {"topics", []},
          {"topics", expected.topics ++ [@hash]},
          {"topics", [@hash, @hash]},
          {"data", expected.data <> "00"},
          {"data", "0xzz"},
          {"removed", true},
          {"removed", nil},
          {"transactionHash", @block},
          {"blockHash", @hash},
          {"blockNumber", "0x11"},
          {"transactionIndex", "0x1"},
          {"logIndex", "0x01"}
        ] do
      assert Receipt.check(%{receipt | "logs" => [Map.put(log, key, value)]}, identity, expected) ==
               {:error, :invalid_receipt}
    end

    assert Receipt.check(%{receipt | "logs" => [log, log]}, identity, expected) ==
             {:error, :invalid_receipt}

    assert Receipt.check(%{receipt | "logs" => List.duplicate(log, 4097)}, identity, expected) ==
             {:error, :invalid_receipt}

    assert {:ok, _} = Receipt.check(%{receipt | "logs" => [%{}, log]}, identity, expected)
  end

  @spec proof(map(), atom()) :: map()
  defp proof(vector, operation) do
    deployment = EVM.deployment(String.to_existing_atom(vector["deployment"]["version"]))

    %{
      level: :full,
      operation: operation,
      chain_id: 8453,
      deployment: deployment,
      payment_info: vector["info"],
      method: String.to_existing_atom(vector["method"]),
      amount: amount(operation),
      fee: if(deployment.version == :v1_1, do: 7500, else: 100),
      fee_receiver: vector["info"]["feeReceiver"],
      payment_state: %{capturable_amount: 250_000},
      void_calldata: nil
    }
  end

  @spec amount(atom()) :: non_neg_integer()
  defp amount(:authorize), do: 1_000_000
  defp amount(:refund), do: 250_000
  defp amount(:void), do: 0
  defp amount(_operation), do: 750_000

  @spec event(map(), atom()) :: Receipt.event()
  defp event(vector, operation) do
    fixture = Enum.find(@events["vectors"], &(&1["id"] == vector["id"]))
    event = fixture["events"][Atom.to_string(operation)]

    %{
      address: String.downcase(vector["deployment"]["escrow"]),
      topics: event["topics"],
      data: event["data"]
    }
  end

  @spec identity(map()) :: Receipt.identity()
  defp identity(vector),
    do: %{hash: @hash, from: vector["info"]["operator"], to: vector["deployment"]["escrow"]}

  @spec receipt(Receipt.event(), Receipt.identity()) :: map()
  defp receipt(event, identity) do
    log = %{
      "address" => event.address,
      "topics" => event.topics,
      "data" => event.data,
      "transactionHash" => identity.hash,
      "blockHash" => @block,
      "blockNumber" => "0x10",
      "transactionIndex" => "0x0",
      "logIndex" => "0x0",
      "removed" => false
    }

    %{
      "transactionHash" => identity.hash,
      "from" => identity.from,
      "to" => identity.to,
      "blockHash" => @block,
      "blockNumber" => "0x10",
      "transactionIndex" => "0x0",
      "status" => "0x1",
      "logs" => [log]
    }
  end
end
