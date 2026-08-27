defmodule X402.TestPaymentsTest do
  use ExUnit.Case, async: true

  alias ExKeccak
  alias ExSecp256k1
  alias X402.TestPayments

  @domain %{
    name: "USDC",
    version: "2",
    chain_id: 84_532,
    verifying_contract: "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
  }

  @receiver "0x2222222222222222222222222222222222222222"

  describe "config/0 and config/1" do
    test "applies facilitator-agnostic defaults" do
      config = TestPayments.config()

      assert config.network == "eip155:84532"
      assert config.contract == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
      assert config.amount == "10000"
      assert config.resource == "https://x402.org/smoke-test"
      assert config.max_timeout == 300
      assert config.token_name == "USDC"
      assert config.token_version == "2"
      assert config.settle? == false
      assert config.payer_key == nil
      assert config.receiver == nil
    end

    test "applies keyword overrides on top of the defaults" do
      config = TestPayments.config(receiver: @receiver, max_timeout: 60, settle?: true)

      assert config.receiver == @receiver
      assert config.max_timeout == 60
      assert config.settle? == true
      assert config.network == "eip155:84532"
      assert config.amount == "10000"
    end
  end

  describe "from_env/1" do
    test "reads X402_* values and decodes the payer key" do
      config =
        TestPayments.from_env(fn name ->
          %{
            "X402_PAYER_KEY" => "0x" <> Base.encode16(:crypto.strong_rand_bytes(32)),
            "X402_NETWORK" => "eip155:8453",
            "X402_CONTRACT" => "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "X402_RESOURCE" => "https://example.test/api",
            "X402_MAX_TIMEOUT" => "60",
            "X402_TOKEN_NAME" => "USDC",
            "X402_TOKEN_VERSION" => "2",
            "X402_SETTLE" => "1"
          }[name]
        end)

      assert byte_size(config.payer_key) == 32
      assert byte_size(config.receiver_key) == 32
      assert config.network == "eip155:8453"
      assert config.contract == "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
      assert config.resource == "https://example.test/api"
      assert config.max_timeout == 60
      assert config.token_name == "USDC"
      assert config.token_version == "2"
      assert config.settle? == true
    end

    test "applies defaults for unset variables" do
      config = TestPayments.from_env(fn _name -> nil end)

      assert config.payer_key == nil
      assert config.receiver_key == nil
      assert config.network == "eip155:84532"
      assert config.max_timeout == 300
      assert config.settle? == false
      assert config.receiver == nil
    end

    test "ignores a payer key that is not valid 32-byte hex" do
      config = TestPayments.from_env(fn _name -> "not-a-key" end)
      assert config.payer_key == nil
    end
  end

  describe "requirements/1" do
    test "builds the v2 requirements map with the configured receiver" do
      config = TestPayments.config(receiver: @receiver)
      requirements = TestPayments.requirements(config)

      assert requirements == %{
               "scheme" => "exact",
               "network" => "eip155:84532",
               "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
               "amount" => "10000",
               "payTo" => @receiver,
               "maxTimeoutSeconds" => 300,
               "extra" => %{"name" => "USDC", "version" => "2"}
             }
    end

    test "uses the burner wallet as payTo, never the payer or zero address" do
      payer_key = :crypto.strong_rand_bytes(32)
      config = TestPayments.config(payer_key: payer_key, receiver_key: TestPayments.burner_key())
      pay_to = TestPayments.requirements(config)["payTo"]

      assert pay_to == TestPayments.derive_address(config.receiver_key)
      assert pay_to != TestPayments.derive_address(payer_key)
      assert pay_to != TestPayments.zero_address()
    end

    test "falls back to the zero address when no receiver is available" do
      config = TestPayments.config()

      assert TestPayments.requirements(config)["payTo"] == TestPayments.zero_address()
    end
  end

  describe "payload/2" do
    test "builds a v2 payload with a signed authorization" do
      config = TestPayments.config(receiver: @receiver)
      signer_key = :crypto.strong_rand_bytes(32)
      payload = TestPayments.payload(config, signer_key)

      assert payload["x402Version"] == 2
      assert payload["accepted"] == TestPayments.requirements(config)

      authorization = payload["payload"]["authorization"]
      assert authorization["from"] == TestPayments.derive_address(signer_key)
      assert authorization["to"] == @receiver
      assert authorization["value"] == "10000"
      assert String.match?(authorization["nonce"], ~r/^0x[0-9a-f]{64}$/)

      valid_after = String.to_integer(authorization["validAfter"])
      valid_before = String.to_integer(authorization["validBefore"])
      now = System.os_time(:second)
      assert valid_after <= now
      # `now` is sampled after the payload was built, so a second may have
      # ticked between the two readings — allow it (was a CI flake).
      assert_in_delta valid_before, now + config.max_timeout, 1

      signature = payload["payload"]["signature"]
      assert String.starts_with?(signature, "0x")
      assert byte_size(String.trim_leading(signature, "0x")) == 130

      assert payload["resource"] == %{"url" => config.resource, "mimeType" => "application/json"}
    end

    test "defaults payTo to the burner wallet, never the payer or zero address" do
      payer_key = :crypto.strong_rand_bytes(32)
      config = TestPayments.config(payer_key: payer_key, receiver_key: TestPayments.burner_key())
      payload = TestPayments.payload(config, payer_key)
      to = payload["payload"]["authorization"]["to"]

      assert to == TestPayments.derive_address(config.receiver_key)
      assert to != TestPayments.derive_address(payer_key)
      assert to != TestPayments.zero_address()
    end
  end

  describe "auth_payload/1" do
    test "signs with a throwaway key and targets the zero address" do
      config = TestPayments.config()
      payload = TestPayments.auth_payload(config)

      assert payload["payload"]["authorization"]["to"] == TestPayments.zero_address()
      assert payload["payload"]["signature"] != nil
    end

    test "keeps a configured receiver" do
      config = TestPayments.config(receiver: @receiver)
      payload = TestPayments.auth_payload(config)

      assert payload["payload"]["authorization"]["to"] == @receiver
    end
  end

  describe "EIP-712 signing" do
    test "derive_address/1 returns a lowercase 0x-prefixed EVM address" do
      address = TestPayments.derive_address(:crypto.strong_rand_bytes(32))
      assert String.match?(address, ~r/^0x[0-9a-f]{40}$/)
    end

    test "a signed authorization recovers to the signer address" do
      signer_key = :crypto.strong_rand_bytes(32)
      from = TestPayments.derive_address(signer_key)

      authorization = %{
        from: from,
        to: @receiver,
        value: "1",
        valid_after: "0",
        valid_before: "9999999999",
        nonce: TestPayments.random_nonce()
      }

      signature =
        TestPayments.sign_transfer_with_authorization(signer_key, @domain, authorization)

      assert String.starts_with?(signature, "0x")

      hex = String.trim_leading(signature, "0x")
      <<signature_bytes::binary-size(65)>> = Base.decode16!(String.upcase(hex))
      <<compact::binary-size(64), v::unsigned-integer-size(8)>> = signature_bytes
      assert v in [27, 28]

      digest = TestPayments.eip712_digest(@domain, authorization)
      {:ok, public_key} = ExSecp256k1.recover_compact(digest, compact, v - 27)

      assert TestPayments.public_key_to_address(public_key) == from
    end

    test "eip712_digest is keccak256 of 0x1901 || domain || struct" do
      authorization = %{
        from: "0x1111111111111111111111111111111111111111",
        to: @receiver,
        value: "1",
        valid_after: "0",
        valid_before: "1",
        nonce: "0x" <> String.duplicate("00", 32)
      }

      digest = TestPayments.eip712_digest(@domain, authorization)
      assert byte_size(digest) == 32
      assert digest == TestPayments.eip712_digest(@domain, authorization)
    end
  end

  describe "encoding helpers" do
    test "encode_address/1 produces a left-padded 32-byte word" do
      encoded = TestPayments.encode_address("0x1111111111111111111111111111111111111111")
      assert byte_size(encoded) == 32
      assert <<0::unsigned-big-integer-size(96), address::binary-size(20)>> = encoded
      assert Base.encode16(address, case: :lower) == String.duplicate("1", 40)
    end

    test "encode_uint256/1 accepts integers and decimal strings" do
      assert TestPayments.encode_uint256(0) == <<0::unsigned-big-integer-size(256)>>
      assert TestPayments.encode_uint256("1") == TestPayments.encode_uint256(1)
      assert byte_size(TestPayments.encode_uint256("123456789")) == 32
    end

    test "encode_bytes32/1 decodes 0x hex" do
      nonce = TestPayments.random_nonce()
      assert byte_size(TestPayments.encode_bytes32(nonce)) == 32
    end

    test "chain_id_from_caip2/1 extracts the chain id" do
      assert TestPayments.chain_id_from_caip2("eip155:84532") == 84_532
      assert TestPayments.chain_id_from_caip2("eip155:1") == 1
    end
  end
end
