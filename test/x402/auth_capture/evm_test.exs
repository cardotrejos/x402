defmodule X402.AuthCapture.EVMTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture.EVM

  alias X402.AuthCapture.EVM
  alias X402.EIP712
  alias X402.Permit2
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCapture.RecordingSigner

  for vector <- Fixture.fixture()["vectors"] do
    @vector vector
    test "independent hashes, signatures and ABI for #{vector["id"]}" do
      vector = @vector
      info = vector["info"]
      version = String.to_existing_atom(vector["deployment"]["version"])
      deployment = EVM.deployment(version)
      requirements = vector["requirements"]

      assert {:ok, encoded} = EVM.encode_payment_info(info)
      assert Fixture.hex(encoded) == vector["encoded_info"]

      assert EVM.payment_info_hash(8453, deployment.escrow, info) ==
               {:ok, vector["payment_info_hash"]}

      assert EVM.signature_nonce(8453, deployment.escrow, info) ==
               {:ok, vector["signature_nonce"]}

      if vector["bound"] do
        assert EVM.bound_salt(Fixture.fixture()["authorizer"], nil, vector["salt_nonce"]) ==
                 {:ok, info["salt"]}
      end

      {method, authorization, domain} =
        case vector["method"] do
          "eip3009" ->
            {:ok, domain} = EIP712.domain(requirements)
            {:eip3009, vector["payload"]["authorization"], domain}

          "permit2" ->
            {:ok, domain} = Permit2.domain(requirements)
            {:permit2, vector["payload"]["permit2Authorization"], domain}
        end

      digest_result =
        case method do
          :eip3009 -> EVM.receive_authorization_digest(domain, authorization)
          :permit2 -> EVM.permit_transfer_digest(domain, authorization)
        end

      assert {:ok, digest} = digest_result
      assert Fixture.hex(digest) == vector["digest"]

      collector_data = Fixture.bytes(vector["collector_data"])

      collector =
        Map.fetch!(deployment, String.to_existing_atom(vector["method"] <> "_collector"))

      fee = if version == :v1_1, do: "7500", else: "100"

      calls = %{
        "authorize" => EVM.authorize_calldata(info, "1000000", collector, collector_data),
        "charge" =>
          EVM.charge_calldata(
            version,
            info,
            "750000",
            collector,
            collector_data,
            fee,
            info["feeReceiver"]
          ),
        "capture" => EVM.capture_calldata(version, info, "750000", fee, info["feeReceiver"]),
        "void" => EVM.void_calldata(info),
        "reclaim" => EVM.reclaim_calldata(info),
        "refund" => EVM.refund_calldata(info, "250000", deployment.refund_collector),
        "payment_state" => EVM.payment_state_calldata(vector["payment_info_hash"])
      }

      for {operation, result} <- calls do
        assert {:ok, encoded} = result
        assert Fixture.hex(encoded) == vector["calldata"][operation]
      end

      {:ok, inner} = LocalKey.new(<<2::256>>)
      signer = %RecordingSigner{inner: inner, owner: self()}
      domain = EVM.operator_domain(8453, info["operator"])

      for {operation, consent} <- vector["consents"] do
        operation = String.to_existing_atom(operation)
        assert {:ok, digest} = EVM.consent_digest(operation, consent["params"], domain, version)
        assert Fixture.hex(digest) == consent["digest"]

        assert EVM.sign_consent(signer, operation, consent["params"], domain, version) ==
                 {:ok, consent["signature"]}

        assert_received {:signed, ^digest, typed_data}

        assert Fixture.normalize_typed_data(typed_data) ==
                 Fixture.normalize_typed_data(consent["typed_data"])

        assert EVM.recover_consent(
                 operation,
                 consent["params"],
                 domain,
                 version,
                 Fixture.bytes(consent["signature"])
               ) ==
                 {:ok, Fixture.fixture()["authorizer"]}
      end
    end
  end

  test "payment state accepts only canonical bool and uint120 ABI words" do
    assert EVM.decode_payment_state(Fixture.vector()["state"]) ==
             {:ok, %{collected?: true, capturable_amount: 250_000, refundable_amount: 750_000}}

    for {collected, capturable, refundable} <- [
          {2, 0, 0},
          {1, Integer.pow(2, 120), 0},
          {1, 0, Integer.pow(2, 120)}
        ] do
      invalid = Fixture.hex(<<collected::256, capturable::256, refundable::256>>)
      assert EVM.decode_payment_state(invalid) == {:error, :invalid_payment_state}
    end

    for invalid <- [Fixture.vector()["state"] <> "00", "0x00", "0xzz", nil, %{}] do
      assert EVM.decode_payment_state(invalid) == {:error, :invalid_payment_state}
    end
  end

  test "payment identity rejects chain ids outside uint256 instead of truncating" do
    vector = Fixture.vector()

    for chain_id <- [-1, Integer.pow(2, 256)] do
      assert EVM.payment_info_hash(chain_id, vector["deployment"]["escrow"], vector["info"]) ==
               {:error, :invalid_amount}
    end
  end

  test "deployment resolution honors direct extra maps and rejects malformed selectors" do
    deployment = EVM.deployment(:v1_0)

    assert EVM.resolve_deployment(%{"authCaptureEscrow" => deployment.escrow}) ==
             {:ok, deployment}

    assert EVM.resolve_deployment(%{"authCaptureEscrow" => "bad"}) == {:error, :invalid_escrow}
    assert EVM.resolve_deployment(%{"extra" => false}) == {:error, :invalid_escrow}
  end

  test "malformed authorization and salt values return tagged failures" do
    vector = Fixture.vector()

    for salt <- [nil, false, 0, [], %{}] do
      payload = Map.put(vector["payload"], "salt", salt)

      assert EVM.payment_info_from_payload(payload, vector["requirements"]) ==
               {:error, :payload_format}
    end

    for alternative <- ["permit2Authorization", :permit2Authorization] do
      payload = Map.put(vector["payload"], alternative, nil)

      assert EVM.payment_info_from_payload(payload, vector["requirements"]) ==
               {:error, :payload_format}
    end

    {:ok, domain} = Permit2.domain(vector["requirements"])

    for value <- [nil, false, [], "bad"] do
      assert {:error, _} = EVM.permit_transfer_digest(domain, %{"permitted" => value})
    end
  end

  test "every PaymentInfo field is bounded and required" do
    info = Fixture.vector()["info"]

    for field <- Map.keys(info) do
      assert EVM.encode_payment_info(Map.delete(info, field)) ==
               {:error, {:invalid_payment_info, field}}
    end

    for {field, bits} <- [
          {"maxAmount", 120},
          {"preApprovalExpiry", 48},
          {"authorizationExpiry", 48},
          {"refundExpiry", 48},
          {"minFeeBps", 16},
          {"maxFeeBps", 16}
        ] do
      assert {:ok, _} = EVM.encode_payment_info(Map.put(info, field, Integer.pow(2, bits) - 1))

      assert EVM.encode_payment_info(Map.put(info, field, Integer.pow(2, bits))) ==
               {:error, {:invalid_payment_info, field}}
    end
  end
end
