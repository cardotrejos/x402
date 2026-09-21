defmodule X402.AuthCaptureTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture

  alias X402.AuthCapture
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCapture.RecordingSigner
  alias X402.Verify.AuthCaptureEVM, as: Verify

  test "deadline options cannot lower the protocol skew floor" do
    assert AuthCapture.check_authorization_window(nil, 1005, 2000, now: 1000, skew_seconds: 0) ==
             {:error, :authorization_expired}

    assert AuthCapture.check_authorization_window(false, 1600, 2000, now: 1000) ==
             {:error, :payload_format}

    assert {:error, {:invalid_options, _}} =
             AuthCapture.check_authorization_window(nil, 1600, 2000, now: -1)

    assert {:error, {:invalid_options, _}} = AuthCapture.check_deadlines(%{}, unknown: true)
  end

  test "lifecycle builders reproduce independent authorizer signatures" do
    {:ok, signer} = LocalKey.new(<<2::256>>)

    for id <- ["v1_1_bound_eip3009", "v1_0_bound_permit2"] do
      vector = Fixture.vector(id)
      common = [salt_nonce: vector["salt_nonce"], authorizer: signer]

      assert {:ok, capture} =
               AuthCapture.capture_payload(
                 vector["requirements"],
                 vector["info"],
                 common ++
                   [
                     amount: "750000",
                     expected_capturable_amount: "1000000",
                     expected_refundable_amount: "0"
                   ]
               )

      assert capture == Fixture.lifecycle(vector, "capture")

      assert {:ok, void} =
               AuthCapture.void_payload(vector["requirements"], vector["info"], common)

      assert void == Fixture.lifecycle(vector, "void")

      assert {:ok, refund} =
               AuthCapture.refund_payload(
                 vector["requirements"],
                 vector["info"],
                 common ++
                   [
                     amount: "250000",
                     expected_capturable_amount: "250000",
                     expected_refundable_amount: "750000"
                   ]
               )

      assert refund == Fixture.lifecycle(vector, "refund")
    end
  end

  test "charge builder hashes the exact collector data for both funding methods" do
    {:ok, signer} = LocalKey.new(<<2::256>>)

    for id <- [
          "v1_1_bound_eip3009",
          "v1_0_bound_eip3009",
          "v1_1_bound_permit2",
          "v1_0_bound_permit2"
        ] do
      vector = Fixture.vector(id)
      expected = Fixture.charge(vector)
      raw = %{expected | "payload" => vector["payload"]}

      assert {:ok, completed} =
               AuthCapture.complete_charge(raw, authorizer: signer, amount: "750000")

      assert completed == expected

      assert {:ok, _} =
               Verify.verify(completed, completed["accepted"],
                 level: :signature,
                 now: Fixture.fixture()["now"],
                 settlement: true
               )
    end
  end

  test "builders require explicit receiver consent" do
    vector = Fixture.vector()

    assert {:error, _} =
             AuthCapture.void_payload(vector["requirements"], vector["info"],
               salt_nonce: vector["salt_nonce"]
             )

    raw = %{Fixture.charge(vector) | "payload" => vector["payload"]}
    assert {:error, _} = AuthCapture.complete_charge(raw)
  end

  test "invalid lifecycle intent is rejected before requesting any signature" do
    vector = Fixture.vector()
    {:ok, inner} = LocalKey.new(<<2::256>>)
    signer = %RecordingSigner{inner: inner, owner: self()}

    opts = [
      salt_nonce: vector["salt_nonce"],
      authorizer: signer,
      amount: "750000",
      expected_capturable_amount: "1000000",
      expected_refundable_amount: "0"
    ]

    for invalid <- [
          [amount: "1000001"],
          [fee: "50000"],
          [salt_nonce: "0x00"],
          [expected_capturable_amount: "700000"],
          [expected_refundable_amount: "1000001"],
          [amount: "1000000", void_remainder: true]
        ] do
      assert {:error, _} =
               AuthCapture.capture_payload(
                 vector["requirements"],
                 vector["info"],
                 Keyword.merge(opts, invalid)
               )

      refute_received {:signed, _, _}
    end

    altered = Map.put(vector["info"], "receiver", vector["info"]["operator"])
    assert {:error, _} = AuthCapture.capture_payload(vector["requirements"], altered, opts)
    refute_received {:signed, _, _}

    {:ok, wrong} = LocalKey.new(<<1::256>>)

    assert {:error, _} =
             AuthCapture.capture_payload(
               vector["requirements"],
               vector["info"],
               Keyword.put(opts, :authorizer, %RecordingSigner{inner: wrong, owner: self()})
             )

    refute_received {:signed, _, _}
  end
end
