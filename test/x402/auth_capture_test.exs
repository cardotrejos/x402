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

  test "the policy operator type and atom-keyed extras resolve" do
    assert AuthCapture.operator_type(%{"extra" => %{"operatorType" => "policy"}}) ==
             {:ok, :policy}

    assert AuthCapture.operator_type(%{"extra" => %{operatorType: "delegated"}}) ==
             {:ok, :delegated}
  end

  describe "deadline checks" do
    test "requirements without both deadlines are an extra error" do
      requirements = %{
        "maxTimeoutSeconds" => 600,
        "extra" => %{"captureDeadline" => 2_000}
      }

      assert AuthCapture.check_deadlines(requirements, now: 1_000) == {:error, :extra}
      assert AuthCapture.check_deadlines(%{}, now: 1_000) == {:error, :extra}
    end

    test "the current time is the default clock" do
      far = System.os_time(:second) + 1_000_000

      future = %{
        "maxTimeoutSeconds" => 60,
        "extra" => %{"captureDeadline" => far, "refundDeadline" => far + 1}
      }

      assert AuthCapture.check_deadlines(future) == :ok

      past = %{
        "maxTimeoutSeconds" => 0,
        "extra" => %{"captureDeadline" => 1, "refundDeadline" => 2}
      }

      assert AuthCapture.check_deadlines(past) == {:error, :deadline_ordering}
    end
  end

  test "reasons lists the standard reasons first and maps every one to a wire string" do
    reasons = AuthCapture.reasons()

    assert :payload_format in reasons
    assert :gas_limit_exceeded in reasons
    assert Enum.uniq(reasons) == reasons

    standard = [
      :invalid_network,
      :invalid_x402_version,
      :unsupported_scheme,
      :settlement_pending,
      :unexpected_settle_error,
      :insufficient_funds
    ]

    assert Enum.take(reasons, 6) == standard

    for reason <- reasons do
      wire = AuthCapture.reason_string(reason)

      if reason in standard,
        do: assert(wire == Atom.to_string(reason)),
        else: assert(wire == "invalid_auth_capture_evm_" <> Atom.to_string(reason))
    end
  end

  describe "lifecycle builder failures" do
    setup do
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

      %{vector: vector, signer: signer, opts: opts}
    end

    test "required lifecycle options are named when absent", ctx do
      for key <- [:amount, :expected_capturable_amount, :expected_refundable_amount] do
        assert AuthCapture.capture_payload(
                 ctx.vector["requirements"],
                 ctx.vector["info"],
                 Keyword.delete(ctx.opts, key)
               ) == {:error, {:invalid_options, "required :#{key} option not found"}}
      end

      refute_received {:signed, _, _}
    end

    test "a different salt nonce does not reopen the salt binding", ctx do
      opts = Keyword.put(ctx.opts, :salt_nonce, Fixture.hex(<<1::256>>))

      assert AuthCapture.capture_payload(ctx.vector["requirements"], ctx.vector["info"], opts) ==
               {:error, :salt_binding_mismatch}

      assert AuthCapture.void_payload(ctx.vector["requirements"], ctx.vector["info"], opts) ==
               {:error, :salt_binding_mismatch}

      refute_received {:signed, _, _}
    end

    test "the authorization flow has no relayed capture", ctx do
      requirements = Fixture.charge(ctx.vector)["accepted"]

      assert AuthCapture.capture_payload(requirements, ctx.vector["info"], ctx.opts) ==
               {:error, :payload_type}

      refute_received {:signed, _, _}
    end

    test "only the delegated operator type relays lifecycle payloads", ctx do
      requirements =
        ctx.vector["requirements"]
        |> put_in(["extra", "operatorType"], "custom")
        |> put_in(["extra", "captureMode"], "deferred")

      assert AuthCapture.capture_payload(requirements, ctx.vector["info"], ctx.opts) ==
               {:error, :lifecycle_not_relayed}

      assert AuthCapture.void_payload(requirements, ctx.vector["info"], ctx.opts) ==
               {:error, :lifecycle_not_relayed}

      refute_received {:signed, _, _}
    end

    test "a void remainder needs integer amounts", ctx do
      opts = Keyword.merge(ctx.opts, amount: "abc", void_remainder: true)

      assert AuthCapture.capture_payload(ctx.vector["requirements"], ctx.vector["info"], opts) ==
               {:error, :payload_format}

      refute_received {:signed, _, _}
    end

    test "a submitted fee must be a non-negative integer", ctx do
      for fee <- ["abc", "-1"] do
        assert AuthCapture.capture_payload(
                 ctx.vector["requirements"],
                 ctx.vector["info"],
                 Keyword.put(ctx.opts, :fee, fee)
               ) == {:error, {:invalid_options, "fee must be a non-negative integer"}}
      end

      refute_received {:signed, _, _}
    end

    test "the default fee needs a readable amount", ctx do
      assert AuthCapture.capture_payload(
               ctx.vector["requirements"],
               ctx.vector["info"],
               Keyword.put(ctx.opts, :amount, "abc")
             ) == {:error, :amount_mismatch}

      refute_received {:signed, _, _}
    end

    test "expected balances must be readable before any signature", ctx do
      for key <- [:expected_capturable_amount, :expected_refundable_amount] do
        assert AuthCapture.capture_payload(
                 ctx.vector["requirements"],
                 ctx.vector["info"],
                 Keyword.put(ctx.opts, key, "abc")
               ) == {:error, :payload_format}
      end

      refute_received {:signed, _, _}
    end

    test "a void remainder adds the void signature to the capture", ctx do
      assert {:ok, capture} =
               AuthCapture.capture_payload(
                 ctx.vector["requirements"],
                 ctx.vector["info"],
                 Keyword.put(ctx.opts, :void_remainder, true)
               )

      void = Fixture.lifecycle(ctx.vector, "void")["payload"]["authorizerSignature"]
      assert capture["payload"]["voidAuthorizerSignature"] == void

      assert capture["payload"]["authorizerSignature"] ==
               Fixture.lifecycle(ctx.vector, "capture")["payload"]["authorizerSignature"]

      assert_received {:signed, _, %{"primaryType" => "Capture"}}
      assert_received {:signed, _, %{"primaryType" => "Void"}}
    end

    test "a charge needs an authorization-flow envelope", ctx do
      raw = %{Fixture.charge(ctx.vector) | "payload" => ctx.vector["payload"]}

      assert AuthCapture.complete_charge(Fixture.envelope(ctx.vector), authorizer: ctx.signer) ==
               {:error, :payload_type}

      assert AuthCapture.complete_charge(
               %{"payload" => ctx.vector["payload"]},
               authorizer: ctx.signer
             ) == {:error, :payload_type}

      refute_received {:signed, _, _}
      assert {:ok, _} = AuthCapture.complete_charge(raw, authorizer: ctx.signer)
      assert_received {:signed, _, %{"primaryType" => "Charge"}}
    end

    test "a charge hashes the collector data only from a hex client signature", ctx do
      charge = Fixture.charge(ctx.vector)

      for payload <- [
            Map.delete(ctx.vector["payload"], "signature"),
            Map.put(ctx.vector["payload"], "signature", nil),
            Map.put(ctx.vector["payload"], "signature", "0xzz"),
            Map.put(ctx.vector["payload"], "signature", "e2e4"),
            Map.put(ctx.vector["payload"], "signature", 12)
          ] do
        assert AuthCapture.complete_charge(%{charge | "payload" => payload},
                 authorizer: ctx.signer
               ) == {:error, :payload_format}
      end

      refute_received {:signed, _, _}
    end
  end
end
