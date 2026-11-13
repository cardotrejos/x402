defmodule X402.Scheme.AuthCaptureEVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.AuthCaptureEVM

  alias X402.AuthCapture.EVM
  alias X402.Scheme.AuthCaptureEVM, as: Scheme
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCapture.RecordingSigner
  alias X402.Verify.AuthCaptureEVM, as: Verify

  test "invalid requirements are refused before signing" do
    vector = Fixture.vector()
    {:ok, inner} = LocalKey.new(<<1::256>>)
    signer = %RecordingSigner{inner: inner, owner: self()}

    for requirements <- [
          put_in(vector["requirements"], ["extra", "captureDeadline"], Fixture.fixture()["now"]),
          put_in(vector["requirements"], ["extra", "maxFeeBps"], 10_001),
          put_in(vector["requirements"], ["extra", "policy"], vector["info"]["payer"]),
          put_in(vector["requirements"], ["extra", "operatorType"], "policy"),
          Map.put(vector["requirements"], "amount", "0"),
          Map.put(vector["requirements"], "amount", Integer.to_string(Integer.pow(2, 120))),
          Map.put(vector["requirements"], "maxTimeoutSeconds", 0),
          Map.put(vector["requirements"], "asset", "bad"),
          Map.put(vector["requirements"], "scheme", "exact")
        ] do
      assert {:error, _} = Scheme.sign(requirements, signer, now: Fixture.fixture()["now"])
      refute_received {:signed, _, _}
    end
  end

  for vector <- Fixture.fixture()["vectors"] do
    @vector vector
    test "client and verifier agree with ethers for #{vector["id"]}" do
      vector = @vector
      {:ok, inner} = LocalKey.new(<<1::256>>)
      signer = %RecordingSigner{inner: inner, owner: self()}

      opts = [
        now: Fixture.fixture()["now"],
        salt: vector["info"]["salt"],
        salt_nonce: vector["salt_nonce"]
      ]

      assert {:ok, payload} = Scheme.sign(vector["requirements"], signer, opts)
      assert payload == vector["payload"]
      assert_received {:signed, digest, typed_data}
      assert Fixture.hex(digest) == vector["digest"]

      assert Fixture.normalize_typed_data(typed_data) ==
               Fixture.normalize_typed_data(vector["typed_data"])

      assert {:ok, verification} =
               Verify.verify(Fixture.envelope(vector), vector["requirements"],
                 level: :signature,
                 now: Fixture.fixture()["now"]
               )

      assert verification.payment_info_hash == vector["payment_info_hash"]
      assert Fixture.hex(verification.calldata) == vector["calldata"]["authorize"]
    end
  end

  describe "validate_options/1" do
    test "accepts the declared signing options" do
      assert Scheme.validate_options(now: 1_800_000_000) == {:ok, [now: 1_800_000_000]}
      assert Scheme.validate_options([]) == {:ok, []}
    end

    test "rejects unknown options and non-list values" do
      assert {:error, message} = Scheme.validate_options(bogus: 1)
      assert message =~ "unknown options"

      assert Scheme.validate_options(:bad) == {:error, "expected auth-capture signing options"}
      assert Scheme.validate_options(nil) == {:error, "expected auth-capture signing options"}
    end
  end

  describe "signable?/1" do
    test "accepts fixture requirements and refuses values that are not requirements maps" do
      assert Scheme.signable?(Fixture.vector()["requirements"])
      refute Scheme.signable?(nil)
      refute Scheme.signable?("auth-capture")
    end
  end

  describe "sign/3 options" do
    test "reports invalid signing options before touching the signer" do
      {:ok, inner} = LocalKey.new(<<1::256>>)
      signer = %RecordingSigner{inner: inner, owner: self()}

      assert {:error, {:invalid_options, message}} =
               Scheme.sign(Fixture.vector()["requirements"], signer, bogus: true)

      assert message =~ "unknown options"
      refute_received {:signed, _, _}
    end
  end

  describe "validate_payload/3 and precheck/3" do
    test "accept the fixture payload for every vector" do
      for vector <- Fixture.fixture()["vectors"] do
        envelope = Fixture.envelope(vector)
        assert Scheme.validate_payload(envelope, vector["requirements"], []) == :ok

        assert Scheme.precheck(envelope, vector["requirements"], now: Fixture.fixture()["now"]) ==
                 :ok
      end
    end

    test "report structural failures with the verifier's reason" do
      vector = Fixture.vector()
      envelope = put_in(Fixture.envelope(vector), ["payload", "authorization", "to"], "0x1234")

      assert Scheme.precheck(envelope, vector["requirements"], now: Fixture.fixture()["now"]) ==
               {:error, {:invalid_auth_capture_payment, :payload_format}}

      mismatched =
        put_in(
          Fixture.envelope(vector),
          ["payload", "authorization", "to"],
          "0x" <> String.duplicate("12", 20)
        )

      assert Scheme.precheck(mismatched, vector["requirements"], now: Fixture.fixture()["now"]) ==
               {:error, {:invalid_auth_capture_payment, :token_collector_mismatch}}

      assert Scheme.validate_payload(envelope, vector["requirements"], []) ==
               {:error, {:invalid_auth_capture_payment, :payload_format}}
    end

    test "pass non-reason verifier errors through unchanged" do
      vector = Fixture.vector()

      assert {:error, {:invalid_auth_capture_payment, {:invalid_options, message}}} =
               Scheme.precheck(Fixture.envelope(vector), vector["requirements"], now: "soon")

      assert message =~ ":now"
    end
  end

  describe "reclaim_transaction/2" do
    test "builds the payer's reclaim call against the deployment escrow" do
      for id <- ["v1_1_bound_eip3009", "v1_0_unbound_permit2"] do
        vector = Fixture.vector(id)
        {:ok, deployment} = EVM.resolve_deployment(vector["requirements"])
        {:ok, encoded} = EVM.encode_payment_info(vector["info"])

        assert {:ok, transaction} =
                 Scheme.reclaim_transaction(Fixture.envelope(vector), vector["requirements"])

        assert transaction == %{
                 to: deployment.escrow,
                 data: Fixture.hex(EVM.selector(:reclaim) <> encoded),
                 value: 0
               }

        assert {:ok, ^transaction} =
                 Scheme.reclaim_transaction(vector["payload"], vector["requirements"])
      end
    end

    test "refuses payloads and requirements that cannot reconstruct the payment" do
      vector = Fixture.vector()
      envelope = Fixture.envelope(vector)

      without_salt = update_in(envelope, ["payload"], &Map.delete(&1, "salt"))

      assert Scheme.reclaim_transaction(without_salt, vector["requirements"]) ==
               {:error, :payload_format}

      assert Scheme.reclaim_transaction(
               envelope,
               put_in(
                 vector["requirements"],
                 ["extra", "authCaptureEscrow"],
                 "0x" <> String.duplicate("11", 20)
               )
             ) ==
               {:error, :invalid_escrow}

      assert Scheme.reclaim_transaction(envelope, %{"extra" => %{}}) ==
               {:error, {:missing_field, "captureAuthorizer"}}
    end
  end
end
