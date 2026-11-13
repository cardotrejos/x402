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

  test "deployment resolution rejects a non-string escrow selector" do
    assert EVM.resolve_deployment(%{"authCaptureEscrow" => 123}) == {:error, :invalid_escrow}

    assert EVM.resolve_deployment(%{"extra" => %{"authCaptureEscrow" => ["0x1"]}}) ==
             {:error, :invalid_escrow}
  end

  test "the PaymentInfo and salt-binding type strings pin their field lists" do
    assert "PaymentInfo(" <> fields = EVM.payment_info_type()
    assert String.ends_with?(fields, "uint256 salt)")
    assert Enum.count_until(String.split(fields, ","), 13) == 12
    assert String.starts_with?(fields, "address operator,address payer,address receiver,")

    assert EVM.salt_binding_type() ==
             "x402AuthCaptureSaltBinding(address receiverAuthorizer,address policy,uint256 saltNonce)"
  end

  test "bytes32 spelling accepts decimal strings and rejects other terms" do
    assert EVM.bytes32_hex("255") ==
             {:ok, "0x00000000000000000000000000000000000000000000000000000000000000ff"}

    assert EVM.bytes32_hex("0xzz") == {:error, :invalid_bytes32}
    assert EVM.bytes32_hex("-1") == {:error, :invalid_bytes32}

    for invalid <- [nil, -1, 1.5, :atom, %{}, Integer.pow(2, 256)] do
      assert EVM.bytes32_hex(invalid) == {:error, :invalid_bytes32}
    end
  end

  test "Permit2 digests surface the first malformed field" do
    vector = Fixture.vector("v1_1_bound_permit2")
    {:ok, domain} = Permit2.domain(vector["requirements"])
    authorization = vector["payload"]["permit2Authorization"]

    assert {:ok, _digest} = EVM.permit_transfer_digest(domain, authorization)

    for {path, value} <- [
          {["permitted", "token"], "0x1"},
          {["permitted", "amount"], "-1"},
          {["spender"], "bad"},
          {["nonce"], "x"},
          {["deadline"], %{}}
        ] do
      assert {:error, reason} =
               EVM.permit_transfer_digest(domain, put_in(authorization, path, value))

      assert reason in [:invalid_address, :invalid_amount]
    end
  end

  test "custom error table is the single source for revert classification" do
    errors = EVM.custom_errors()
    assert map_size(errors) == 21

    for {selector, {name, reason}} <- errors do
      assert byte_size(selector) == 4
      data = Fixture.hex(selector <> <<0::256>>)

      assert EVM.classify_revert(%{code: 3, message: "execution reverted", data: data}) == reason
      assert EVM.classify_revert(%{code: 3, message: "reverted: #{name}(1)", data: nil}) == reason
    end

    assert EVM.custom_errors()[<<0xAD, 0x7C, 0x14, 0x5A>>] ==
             {"PaymentAlreadyCollected", :payment_already_collected}
  end

  test "revert classification ignores unmapped selectors and malformed data or messages" do
    for data <- ["0xdeadbeef", "0xab", "0xzz", "0x", "nope", nil, 7] do
      assert EVM.classify_revert(%{code: 3, message: "execution reverted", data: data}) == nil
    end

    for message <- [nil, 7, %{}, ["AfterRefundExpiry"]] do
      assert EVM.classify_revert(%{code: 3, message: message, data: nil}) == nil
    end

    assert EVM.classify_revert(%{}) == nil

    assert EVM.classify_revert(%{
             message: "reverted: AfterRefundExpiry(1, 2)",
             data: "0xdeadbeef"
           }) == :refund_deadline_expired
  end

  test "payment info reconstruction accepts the full envelope as well as the inner payload" do
    vector = Fixture.vector()

    assert {:ok, from_envelope} =
             EVM.payment_info_from_payload(Fixture.envelope(vector), vector["requirements"])

    assert {:ok, from_inner} =
             EVM.payment_info_from_payload(vector["payload"], vector["requirements"])

    assert from_envelope == from_inner
    assert EVM.encode_payment_info(from_envelope) == EVM.encode_payment_info(vector["info"])
  end

  test "authorizer consent and calldata name the field that is missing" do
    vector = Fixture.vector()
    domain = EVM.operator_domain(8453, vector["info"]["operator"])
    hash = vector["payment_info_hash"]

    assert EVM.consent_digest(:void, %{}, domain, :v1_1) ==
             {:error, {:missing_field, "paymentInfoHash"}}

    assert EVM.consent_digest(:refund, %{"paymentInfoHash" => hash}, domain, :v1_1) ==
             {:error, {:missing_field, "amount"}}

    assert EVM.consent_digest(
             :capture,
             %{"paymentInfoHash" => hash, "amount" => "1"},
             domain,
             :v1_0
           ) == {:error, {:missing_field, "fee"}}

    assert EVM.consent_digest(
             :charge,
             %{
               "paymentInfoHash" => hash,
               "amount" => "1",
               "tokenCollector" => EVM.deployment(:v1_1).eip3009_collector,
               "collectorDataHash" => hash
             },
             domain,
             :v1_1
           ) == {:error, {:missing_field, "fee"}}

    info = vector["info"]

    assert EVM.capture_calldata(:v1_1, info, "1", nil, info["feeReceiver"]) ==
             {:error, {:missing_field, "fee"}}

    assert EVM.charge_calldata(
             :v1_0,
             info,
             "1",
             EVM.deployment(:v1_0).eip3009_collector,
             <<>>,
             nil,
             info["feeReceiver"]
           ) == {:error, {:missing_field, "fee"}}
  end

  test "a signed fee receiver never matches a missing submitted receiver" do
    signed = "0x2222222222222222222222222222222222222222"

    assert EVM.check_fee(:v1_1, 750_000, 0, nil, 0, 0, signed) == {:error, :fee_receiver}
    assert EVM.check_fee(:v1_1, 750_000, 0, 7, 0, 0, signed) == {:error, :fee_receiver}
    assert EVM.check_fee(:v1_1, 750_000, 0, signed, 0, 0, signed) == :ok

    assert EVM.check_fee(:v1_1, 750_000, 0, String.upcase(signed), 0, 0, signed) == :ok
  end

  test "client authorization typed data matches the independent JSON for both transfer methods" do
    for vector <- Fixture.fixture()["vectors"] do
      requirements = vector["requirements"]

      {method, authorization, domain} =
        case vector["method"] do
          "eip3009" ->
            {:ok, domain} = EIP712.domain(requirements)
            {:eip3009, vector["payload"]["authorization"], domain}

          "permit2" ->
            {:ok, domain} = Permit2.domain(requirements)
            {:permit2, vector["payload"]["permit2Authorization"], domain}
        end

      typed_data = EVM.authorization_typed_data(method, domain, authorization)

      assert Fixture.normalize_typed_data(typed_data) ==
               Fixture.normalize_typed_data(vector["typed_data"])
    end
  end
end
