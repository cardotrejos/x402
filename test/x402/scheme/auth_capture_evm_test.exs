defmodule X402.Scheme.AuthCaptureEVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.AuthCaptureEVM

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
end
