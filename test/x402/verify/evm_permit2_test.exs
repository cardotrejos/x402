defmodule X402.Verify.EVMPermit2Test do
  # Permit2 flows (exact with assetTransferMethod "permit2", and upto) of
  # X402.Verify.EVM. The EIP-3009 flow lives in X402.Verify.EVMTest.
  use ExUnit.Case, async: false

  alias X402.EIP3009
  alias X402.ERC6492
  alias X402.Permit2
  alias X402.Signer.LocalKey
  alias X402.Verify.EVM

  import X402.TestHelpers

  @payer_key "0x" <> String.duplicate("11", 32)
  @payer "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @facilitator "0x1563915e194d8cfba1943570603f7606a3115508"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @network "eip155:84532"
  @exact_proxy "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
  @upto_proxy "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"
  @permit2 "0x000000000022D473030F116dDEE9F6B43aC78BA3"

  setup [:setup_bypass, :setup_finch]

  # -- Fixtures ---------------------------------------------------------------

  defp exact_requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => "10000",
        "asset" => @asset,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 600,
        "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
      },
      overrides
    )
  end

  defp upto_requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "upto",
        "network" => @network,
        "amount" => "10000",
        "asset" => @asset,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 600,
        "extra" => %{"name" => "USDC", "version" => "2", "facilitatorAddress" => @facilitator}
      },
      overrides
    )
  end

  defp payer_signer do
    {:ok, signer} = LocalKey.new(@payer_key)
    signer
  end

  defp signed_payload(%{"scheme" => "upto"} = requirements) do
    {:ok, scheme_payload} = Permit2.sign_upto(requirements, payer_signer())
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp signed_payload(requirements) do
    {:ok, scheme_payload} = Permit2.sign_exact(requirements, payer_signer())
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp stub_rpc(%{bypass: bypass, finch: finch}, overrides \\ %{}) do
    X402.TestRPCStub.stub_rpc(bypass, finch, overrides)
  end

  defp full(payload, requirements, rpc, opts \\ []) do
    EVM.verify(payload, requirements, [level: :full, rpc: rpc] ++ opts)
  end

  defp resign(payload, requirements) do
    authorization = payload["payload"]["permit2Authorization"]
    {:ok, domain} = Permit2.domain(requirements)
    {:ok, signature} = Permit2.sign_authorization(payer_signer(), domain, authorization)
    put_in(payload, ["payload", "signature"], signature)
  end

  defp selector(signature), do: binary_part(ExKeccak.hash_256(signature), 0, 4)

  # -- Structural -------------------------------------------------------------

  describe "level :structural (exact permit2)" do
    test "accepts a well-formed payload and reports the kind" do
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{payer: @payer, kind: :permit2_exact, level: :structural, signature_type: nil}} =
               EVM.verify(payload, requirements, level: :structural)
    end

    test "rejects the reference facilitator's structural reasons in order" do
      requirements = exact_requirements()
      payload = signed_payload(requirements)
      path = ["payload", "permit2Authorization"]
      now = System.system_time(:second)

      assert EVM.verify(put_in(payload, ["accepted", "scheme"], "upto"), requirements,
               level: :structural
             ) == {:error, {:invalid, :scheme_mismatch}}

      assert EVM.verify(put_in(payload, ["accepted", "network"], "eip155:1"), requirements,
               level: :structural
             ) == {:error, {:invalid, :network_mismatch}}

      assert EVM.verify(put_in(payload, path ++ ["spender"], @upto_proxy), requirements,
               level: :structural
             ) == {:error, {:invalid, :invalid_permit2_spender}}

      assert EVM.verify(put_in(payload, path ++ ["witness", "to"], @facilitator), requirements,
               level: :structural
             ) == {:error, {:invalid, :permit2_recipient_mismatch}}

      assert EVM.verify(
               put_in(payload, path ++ ["deadline"], Integer.to_string(now + 2)),
               requirements,
               level: :structural
             ) == {:error, {:invalid, :permit2_deadline_expired}}

      assert EVM.verify(
               put_in(payload, path ++ ["witness", "validAfter"], Integer.to_string(now + 600)),
               requirements,
               level: :structural
             ) == {:error, {:invalid, :permit2_not_yet_valid}}

      assert EVM.verify(put_in(payload, path ++ ["permitted", "amount"], "9999"), requirements,
               level: :structural
             ) == {:error, {:invalid, :permit2_amount_mismatch}}

      assert EVM.verify(
               put_in(payload, path ++ ["permitted", "token"], @facilitator),
               requirements,
               level: :structural
             ) == {:error, {:invalid, :permit2_token_mismatch}}
    end

    test "rejects malformed authorizations, assets, networks, and signatures" do
      requirements = exact_requirements()
      payload = signed_payload(requirements)
      path = ["payload", "permit2Authorization"]

      for broken <- [
            put_in(payload, path, "nope"),
            put_in(payload, path ++ ["permitted"], "nope"),
            put_in(payload, path ++ ["witness"], nil),
            put_in(payload, path ++ ["from"], "0x123"),
            put_in(payload, path ++ ["witness", "to"], "till"),
            put_in(payload, path ++ ["permitted", "token"], "0xnope"),
            put_in(payload, path ++ ["deadline"], "soon"),
            put_in(payload, path ++ ["nonce"], "-1")
          ] do
        assert EVM.verify(broken, requirements, level: :structural) ==
                 {:error, {:invalid, :invalid_authorization}}
      end

      assert EVM.verify(payload, exact_requirements(%{"asset" => "0x123"}), level: :structural) ==
               {:error, {:invalid, :invalid_requirements}}

      solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
      solana_requirements = exact_requirements(%{"network" => solana})
      solana_payload = put_in(payload, ["accepted", "network"], solana)

      assert EVM.verify(solana_payload, solana_requirements, level: :structural) ==
               {:error, {:invalid, :unsupported_network}}

      assert EVM.verify(put_in(payload, ["payload", "signature"], "0x"), requirements,
               level: :structural
             ) == {:error, {:invalid, :invalid_signature}}
    end
  end

  describe "level :structural (upto)" do
    test "accepts amounts at or below the permitted ceiling" do
      requirements = upto_requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{kind: :permit2_upto}} = EVM.verify(payload, requirements, level: :structural)

      assert {:ok, %{kind: :permit2_upto}} =
               EVM.verify(payload, upto_requirements(%{"amount" => "1"}), level: :structural)

      assert EVM.verify(payload, upto_requirements(%{"amount" => "10001"}), level: :structural) ==
               {:error, {:invalid, :settlement_exceeds_amount}}
    end

    test "uses the upto reason family and binds the facilitator" do
      requirements = upto_requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(put_in(payload, ["accepted", "scheme"], "exact"), requirements,
               level: :structural
             ) == {:error, {:invalid, :upto_scheme_mismatch}}

      assert EVM.verify(put_in(payload, ["accepted", "network"], "eip155:1"), requirements,
               level: :structural
             ) == {:error, {:invalid, :upto_network_mismatch}}

      assert EVM.verify(
               put_in(payload, ["payload", "permit2Authorization", "spender"], @exact_proxy),
               requirements,
               level: :structural
             ) == {:error, {:invalid, :invalid_permit2_spender}}

      other_facilitator = upto_requirements(%{"extra" => %{"facilitatorAddress" => @pay_to}})

      assert EVM.verify(payload, other_facilitator, level: :structural) ==
               {:error, {:invalid, :upto_facilitator_mismatch}}

      no_facilitator = upto_requirements(%{"extra" => %{}})

      assert EVM.verify(payload, no_facilitator, level: :structural) ==
               {:error, {:invalid, :upto_facilitator_mismatch}}
    end
  end

  # -- Signature --------------------------------------------------------------

  describe "level :signature" do
    test "recovers the payer over the Permit2 digest for both flows" do
      for requirements <- [exact_requirements(), upto_requirements()] do
        payload = signed_payload(requirements)

        assert {:ok, %{payer: @payer, level: :signature, signature_type: :eoa}} =
                 EVM.verify(payload, requirements, level: :signature)
      end
    end

    test "rejects tampered authorizations with the Permit2 signature reason" do
      requirements = exact_requirements()
      payload = signed_payload(requirements)
      tampered = put_in(payload, ["payload", "permit2Authorization", "nonce"], "42")

      assert EVM.verify(tampered, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_permit2_signature}}
    end

    test "cannot prove smart-wallet signatures without RPC" do
      requirements = exact_requirements()
      payload = signed_payload(requirements)
      "0x" <> inner_hex = payload["payload"]["signature"]

      {:ok, wrapped} =
        ERC6492.wrap(@pay_to, <<0xDE, 0xAD>>, Base.decode16!(inner_hex, case: :mixed))

      wrapped_payload =
        put_in(payload, ["payload", "signature"], "0x" <> Base.encode16(wrapped, case: :lower))

      assert EVM.verify(wrapped_payload, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_permit2_signature}}
    end
  end

  # -- Full -------------------------------------------------------------------

  describe "level :full" do
    test "simulates the exact proxy's settle from the payer", context do
      rpc = stub_rpc(context)
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{payer: @payer, kind: :permit2_exact, level: :full, signature_type: :eoa}} =
               full(payload, requirements, rpc)

      assert_received {:rpc, "eth_getCode", [@exact_proxy, "latest"]}

      assert_received {:rpc, "eth_call",
                       [
                         %{"to" => @exact_proxy, "from" => @payer, "data" => "0x13cd3b53" <> _},
                         "latest"
                       ]}
    end

    test "simulates the upto proxy's settle as the witness facilitator", context do
      rpc = stub_rpc(context)
      requirements = upto_requirements(%{"amount" => "5000"})
      payload = signed_payload(upto_requirements())

      assert {:ok, %{kind: :permit2_upto, level: :full}} = full(payload, requirements, rpc)

      assert_received {:rpc, "eth_call",
                       [
                         %{
                           "to" => @upto_proxy,
                           "from" => @facilitator,
                           "data" => "0xff11e7b4" <> data
                         },
                         "latest"
                       ]}

      # The settle amount is the requirements' amount, not the ceiling.
      {:ok, calldata} =
        Permit2.upto_settle_calldata(
          payload["payload"]["permit2Authorization"],
          "5000",
          Base.decode16!(String.slice(payload["payload"]["signature"], 2..-1//1), case: :mixed)
        )

      assert "0xff11e7b4" <> data == "0x" <> Base.encode16(calldata, case: :lower)
    end

    test "rejects a missing proxy, insufficient balance, and missing allowance", context do
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      rpc = stub_rpc(context, %{code: %{String.downcase(@asset) => "0x6001"}})

      assert full(payload, requirements, rpc) ==
               {:error, {:invalid, :permit2_proxy_not_deployed}}

      rpc = stub_rpc(context, %{balance: 9_999})

      assert full(payload, requirements, rpc) ==
               {:error, {:invalid, :permit2_insufficient_balance}}

      rpc = stub_rpc(context, %{allowance: 0, simulate: {:revert, "TRANSFER_FROM_FAILED"}})

      assert full(payload, requirements, rpc) ==
               {:error, {:invalid, :permit2_allowance_required}}
    end

    test "diagnoses an unexplained settle revert", context do
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      rpc = stub_rpc(context, %{simulate: {:revert, "something odd"}})

      assert full(payload, requirements, rpc) ==
               {:error, {:invalid, :permit2_simulation_failed}}

      rpc = stub_rpc(context, %{simulate: {:revert, "something odd"}, permit2_probe: :empty})

      assert full(payload, requirements, rpc) ==
               {:error, {:invalid, :permit2_proxy_not_deployed}}
    end

    test "maps Permit2 and proxy custom errors from selectors and messages", context do
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      cases = [
        {{:revert_data, selector("InvalidNonce()")}, :permit2_invalid_nonce},
        {{:revert_data, selector("PaymentTooEarly()")}, :permit2_payment_too_early},
        {{:revert_data, selector("SignatureExpired(uint256)")}, :invalid_permit2_signature},
        {{:revert_data, selector("InvalidSigner()")}, :invalid_permit2_signature},
        {{:revert_data, selector("InvalidAmount(uint256)")}, :permit2_invalid_amount},
        {{:revert_data, selector("InvalidDestination()")}, :permit2_invalid_destination},
        {{:revert_data, selector("InvalidOwner()")}, :permit2_invalid_owner},
        {{:revert_data, selector("Permit2612AmountMismatch()")}, :permit2_2612_amount_mismatch},
        {{:revert_data, selector("AmountExceedsPermitted()")}, :upto_amount_exceeds_permitted},
        {{:revert_data, selector("UnauthorizedFacilitator()")}, :upto_unauthorized_facilitator},
        {{:revert, "InvalidNonce()"}, :permit2_invalid_nonce},
        {{:revert, "Too early"}, :permit2_payment_too_early}
      ]

      for {simulate, expected} <- cases do
        rpc = stub_rpc(context, %{simulate: simulate})

        assert full(payload, requirements, rpc) == {:error, {:invalid, expected}},
               inspect(simulate)
      end
    end

    test "rejects a signature that does not recover to the payer", context do
      rpc = stub_rpc(context)
      requirements = exact_requirements()
      payload = signed_payload(requirements)
      forged = put_in(payload, ["payload", "permit2Authorization", "deadline"], "9999999999")

      assert full(forged, requirements, rpc) == {:error, {:invalid, :invalid_permit2_signature}}
    end

    test "validates deployed smart wallets via ERC-1271 against the proxy settle", context do
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      # The payer holds code: the stub answers isValidSignature only when
      # the test routes 0x1626ba7e; TestRPCStub has no handler, so drive it
      # through the counterfactual multicall path instead.
      "0x" <> inner_hex = payload["payload"]["signature"]
      inner = Base.decode16!(inner_hex, case: :mixed)
      {:ok, wrapped} = ERC6492.wrap(@pay_to, <<0xDE, 0xAD>>, inner)

      wrapped_payload =
        put_in(payload, ["payload", "signature"], "0x" <> Base.encode16(wrapped, case: :lower))

      rpc = stub_rpc(context)

      assert full(wrapped_payload, requirements, rpc) ==
               {:error, {:invalid, :eip6492_factory_not_allowed}}

      rpc = stub_rpc(context)

      assert {:ok, %{signature_type: :erc6492_counterfactual}} =
               full(wrapped_payload, requirements, rpc, eip6492_allowed_factories: [@pay_to])

      assert_received {:rpc, "eth_call", [%{"data" => "0x82ad56cb" <> _}, "latest"]}

      # A failing settle leg inside the multicall is classified like a direct revert.
      rpc =
        stub_rpc(context, %{
          multicall: [{true, <<>>}, {false, selector("AmountExceedsPermitted()")}]
        })

      assert full(wrapped_payload, requirements, rpc, eip6492_allowed_factories: [@pay_to]) ==
               {:error, {:invalid, :upto_amount_exceeds_permitted}}
    end

    test "re-signed authorizations verify after the deadline is refreshed", context do
      rpc = stub_rpc(context)
      requirements = exact_requirements()
      payload = signed_payload(requirements)

      refreshed =
        payload
        |> put_in(["payload", "permit2Authorization", "deadline"], "9999999999")
        |> resign(requirements)

      assert {:ok, %{kind: :permit2_exact}} = full(refreshed, requirements, rpc)
    end
  end

  # -- Reason strings and selectors -------------------------------------------

  describe "reason_string/1" do
    test "maps Permit2 reasons onto the reference facilitator strings" do
      assert EVM.reason_string(:invalid_permit2_spender) == "invalid_permit2_spender"

      assert EVM.reason_string(:permit2_recipient_mismatch) ==
               "invalid_permit2_recipient_mismatch"

      assert EVM.reason_string(:invalid_permit2_signature) == "invalid_permit2_signature"
      assert EVM.reason_string(:permit2_allowance_required) == "permit2_allowance_required"
      assert EVM.reason_string(:upto_scheme_mismatch) == "invalid_upto_evm_scheme"
      assert EVM.reason_string(:upto_network_mismatch) == "invalid_upto_evm_network_mismatch"

      assert EVM.reason_string(:settlement_exceeds_amount) ==
               "invalid_upto_evm_payload_settlement_exceeds_amount"

      assert EVM.reason_string(:upto_facilitator_mismatch) == "upto_facilitator_mismatch"
    end
  end

  describe "classify_permit2_revert/1" do
    test "prefers the selector, falls back to the message, and translates shared reasons" do
      assert EVM.classify_permit2_revert(%{
               code: 3,
               message: "execution reverted",
               data: "0x" <> Base.encode16(selector("InvalidSignature()"), case: :lower)
             }) == :invalid_permit2_signature

      assert EVM.classify_permit2_revert(%{
               code: 3,
               message: "InvalidSignatureLength()",
               data: nil
             }) ==
               :invalid_permit2_signature

      assert EVM.classify_permit2_revert(%{code: 3, message: "boom", data: "0xzz"}) == nil
      assert EVM.classify_permit2_revert(%{code: 3, message: nil, data: nil}) == nil
    end
  end

  test "hardcoded ABI selectors match keccak256 of their signatures" do
    assert selector("allowance(address,address)") == <<0xDD, 0x62, 0xED, 0x3E>>
    assert selector("PERMIT2()") == <<0x6A, 0xFD, 0xD8, 0x50>>

    assert selector("settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)") ==
             <<0x13, 0xCD, 0x3B, 0x53>>

    assert selector(
             "settle(((address,uint256),uint256,uint256),uint256,address,(address,address,uint256),bytes)"
           ) == <<0xFF, 0x11, 0xE7, 0xB4>>

    assert selector("InvalidContractSignature()") == <<0xB0, 0x66, 0x9C, 0xBC>>
    assert selector("InvalidSignatureLength()") == <<0x4B, 0xE6, 0x32, 0x1B>>
    assert selector("InvalidSignature()") == <<0x8B, 0xAA, 0x57, 0x9F>>
    assert selector("Permit2612AmountMismatch()") == <<0x05, 0x0C, 0xDA, 0x49>>
  end

  test "verification recovers the payer over the canonical Permit2 domain" do
    requirements = exact_requirements()
    payload = signed_payload(requirements)

    {:ok, domain} = Permit2.domain(requirements)
    assert domain.verifying_contract == @permit2

    {:ok, digest} = Permit2.digest(domain, payload["payload"]["permit2Authorization"])
    assert EIP3009.recover_signer(digest, payload["payload"]["signature"]) == {:ok, @payer}
  end
end
