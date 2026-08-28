defmodule X402.Facilitator.EngineTest do
  use ExUnit.Case, async: false

  alias X402.EIP3009
  alias X402.ERC6492
  alias X402.Facilitator.Engine
  alias X402.Facilitator.PendingSettlementStore
  alias X402.RPC
  alias X402.Signer.LocalKey
  alias X402.TestRLPDecoder

  import X402.TestHelpers

  # Payer key (the paying client) and facilitator key (the fee payer).
  @payer_key "0x" <> String.duplicate("11", 32)
  @payer "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @facilitator_key "0x" <> String.duplicate("22", 32)
  @facilitator_address "0x1563915e194d8cfba1943570603f7606a3115508"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @asset_bytes Base.decode16!("036CbD53842c5426634e7929541eC2318f3dCF7e", case: :mixed)
  @network "eip155:84532"
  @tx_hash "0x" <> String.duplicate("cd", 32)
  @factory "0x3333333333333333333333333333333333333333"
  @factory_bytes :binary.copy(<<0x33>>, 20)
  @factory_calldata <<0xDE, 0xAD>>

  setup [:setup_bypass, :setup_finch]

  # -- Fixtures ---------------------------------------------------------------

  defp requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => "10000",
        "asset" => @asset,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 600,
        "extra" => %{"name" => "USDC", "version" => "2"}
      },
      overrides
    )
  end

  defp payer_signer do
    {:ok, signer} = LocalKey.new(@payer_key)
    signer
  end

  defp facilitator_signer do
    {:ok, signer} = LocalKey.new(@facilitator_key)
    signer
  end

  defp signed_payload(requirements) do
    {:ok, scheme_payload} = EIP3009.sign(requirements, payer_signer())
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp engine(context, overrides \\ []) do
    rpc = stub_rpc(context, Keyword.get(overrides, :stub, %{}))

    {:ok, engine} =
      [
        rpc: rpc,
        signer: facilitator_signer(),
        networks: [@network],
        receipt_timeout_ms: 500,
        receipt_interval_ms: 10
      ]
      |> Keyword.merge(Keyword.delete(overrides, :stub))
      |> Engine.new()

    engine
  end

  defp stub_rpc(%{bypass: bypass, finch: finch}, overrides) do
    X402.TestRPCStub.stub_rpc(bypass, finch, overrides)
  end

  # Wraps the payload's real EOA signature in an ERC-6492 wrapper; the payer
  # stays undeployed, so the engine classifies it as counterfactual.
  defp counterfactual_payload(payload, factory) do
    "0x" <> inner_hex = payload["payload"]["signature"]
    inner = Base.decode16!(inner_hex, case: :mixed)
    {:ok, wrapped} = ERC6492.wrap(factory, @factory_calldata, inner)

    wrapped_payload =
      put_in(payload, ["payload", "signature"], "0x" <> Base.encode16(wrapped, case: :lower))

    {wrapped_payload, inner}
  end

  defp pending_store(name, opts \\ []) do
    start_supervised!({X402.Facilitator.PendingSettlementStore.ETS, [name: name] ++ opts})
    {X402.Facilitator.PendingSettlementStore.ETS, name}
  end

  defp pending_key(payload) do
    "0x" <> signature_hex = payload["payload"]["signature"]
    bytes = Base.decode16!(signature_hex, case: :mixed)
    Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  # -- new/1 ------------------------------------------------------------------

  describe "new/1" do
    test "requires eip155 CAIP-2 networks", %{finch: finch} do
      {:ok, rpc} = RPC.new(rpc_url: "https://sepolia.base.org", finch: finch)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Engine.new(rpc: rpc, signer: facilitator_signer(), networks: [])

      assert {:error, %NimbleOptions.ValidationError{}} =
               Engine.new(rpc: rpc, signer: facilitator_signer(), networks: ["solana:mainnet"])
    end

    test "requires a struct implementing X402.Signer", %{finch: finch} do
      {:ok, rpc} = RPC.new(rpc_url: "https://sepolia.base.org", finch: finch)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Engine.new(rpc: rpc, signer: :not_a_signer, networks: [@network])
    end

    test "requires an X402.RPC configuration" do
      assert {:error, %NimbleOptions.ValidationError{}} =
               Engine.new(rpc: :nope, signer: facilitator_signer(), networks: [@network])
    end

    test "rejects structs that do not implement X402.Signer", %{finch: finch} do
      {:ok, rpc} = RPC.new(rpc_url: "https://sepolia.base.org", finch: finch)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Engine.new(rpc: rpc, signer: %URI{}, networks: [@network])
    end
  end

  # -- supported/1 ------------------------------------------------------------

  describe "supported/1" do
    test "derives kinds and signers from the configuration", context do
      engine = engine(context, networks: [@network, "eip155:8453"])

      assert Engine.supported(engine) == %{
               "kinds" => [
                 %{"x402Version" => 2, "scheme" => "exact", "network" => @network},
                 %{"x402Version" => 2, "scheme" => "exact", "network" => "eip155:8453"}
               ],
               "extensions" => [],
               "signers" => %{"eip155:*" => [@facilitator_address]}
             }
    end
  end

  # -- verify/3 ---------------------------------------------------------------

  describe "verify/3" do
    test "returns the valid wire response for a good payment", context do
      engine = engine(context)
      requirements = requirements()

      assert {:ok, %{"isValid" => true, "payer" => @payer}} =
               Engine.verify(engine, signed_payload(requirements), requirements)

      assert_received {:rpc, "eth_chainId", []}
      assert_received {:rpc, "eth_call", _params}
    end

    test "returns the canonical invalidReason string for a rejected payment", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = requirements(%{"amount" => "20000"})

      assert Engine.verify(engine, payload, tampered) ==
               {:ok,
                %{
                  "isValid" => false,
                  "invalidReason" => "invalid_exact_evm_payload_authorization_value_mismatch",
                  "payer" => @payer
                }}
    end

    test "rejects unsupported schemes, networks, and versions without RPC calls", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{"isValid" => false, "invalidReason" => "unsupported_scheme"}} =
               Engine.verify(engine, payload, requirements(%{"scheme" => "upto"}))

      assert {:ok, %{"isValid" => false, "invalidReason" => "invalid_network"}} =
               Engine.verify(engine, payload, requirements(%{"network" => "eip155:1"}))

      assert {:ok, %{"isValid" => false, "invalidReason" => "invalid_x402_version"}} =
               Engine.verify(engine, Map.put(payload, "x402Version", 1), requirements)

      refute_received {:rpc, _method, _params}
    end

    test "returns an infrastructure error when the RPC is unreachable", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      Bypass.down(context.bypass)

      assert {:error, {:rpc_error, _reason}} = Engine.verify(engine, payload, requirements)
    end

    test "simulate: false still proves counterfactual payments via the atomic simulation",
         context do
      engine = engine(context, simulate: false, eip6492_allowed_factories: [@factory])
      requirements = requirements()
      {payload, _inner} = counterfactual_payload(signed_payload(requirements), @factory)

      # verify predicts settle: settle's re-verify keeps the counterfactual
      # proof even with simulation off, so verify must accept (not reject as
      # undeployed_smart_wallet) the same payment.
      assert {:ok, %{"isValid" => true, "payer" => @payer}} =
               Engine.verify(engine, payload, requirements)

      # The atomic Multicall3 deploy-and-transfer proof ran — the only
      # possible signature check for a counterfactual wallet.
      assert_received {:rpc, "eth_call", [%{"data" => "0x82ad56cb" <> _rest}, _block]}
    end

    test "simulate: false keeps the transfer simulation off for EOA payments", context do
      engine = engine(context, simulate: false, eip6492_allowed_factories: [@factory])
      requirements = requirements()

      assert {:ok, %{"isValid" => true, "payer" => @payer}} =
               Engine.verify(engine, signed_payload(requirements), requirements)

      # No transferWithAuthorization eth_call (either variant) and no
      # Multicall3 call — only counterfactuals keep their proof.
      refute_received {:rpc, "eth_call", [%{"data" => "0xe3ee160e" <> _vrs}, _block]}
      refute_received {:rpc, "eth_call", [%{"data" => "0xcf092995" <> _bytes}, _block2]}
      refute_received {:rpc, "eth_call", [%{"data" => "0x82ad56cb" <> _agg}, _block3]}
    end
  end

  # -- settle/3 ---------------------------------------------------------------

  describe "settle/3 with a nonce manager" do
    test "assigns distinct consecutive nonces with a single node fetch", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        engine(context,
          nonce_manager: manager,
          stub: %{receipts: [%{"status" => "0x1"}, %{"status" => "0x1"}]}
        )

      requirements = requirements()

      assert {:ok, %{"success" => true}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert {:ok, %{"success" => true}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      # The pending nonce was read from the node exactly once …
      assert_received {:rpc, "eth_getTransactionCount", _params}
      refute_received {:rpc, "eth_getTransactionCount", _params2}

      # … and the two broadcast transactions carry consecutive nonces.
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_1]}
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_2]}

      [nonce_1, nonce_2] =
        for raw_hex <- [raw_hex_1, raw_hex_2] do
          raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
          [_chain_id, nonce | _rest] = X402.TestRLPDecoder.decode_eip1559(raw)
          :binary.decode_unsigned(nonce)
        end

      assert nonce_2 == nonce_1 + 1
    end

    test "a rejected broadcast rolls the tail nonce back for the next settle", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        engine(context,
          nonce_manager: manager,
          stub: %{
            send_raw: {:error, %{"code" => -32_000, "message" => "rejected"}},
            receipts: [%{"status" => "0x1"}]
          }
        )

      requirements = requirements()

      assert {:ok, %{"success" => false, "errorReason" => "unexpected_settle_error"}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert {:ok, %{"success" => false}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      # One node fetch; the rejected broadcast released its nonce, so the
      # second settle reused it (no gap, no reissue race).
      assert_received {:rpc, "eth_getTransactionCount", _params}
      refute_received {:rpc, "eth_getTransactionCount", _params2}

      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_1]}
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_2]}

      [nonce_1, nonce_2] =
        for raw_hex <- [raw_hex_1, raw_hex_2] do
          raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
          [_chain_id, nonce | _rest] = TestRLPDecoder.decode_eip1559(raw)
          :binary.decode_unsigned(nonce)
        end

      assert nonce_2 == nonce_1
    end

    test "gas estimates above the ceiling refuse to settle", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        engine(context,
          nonce_manager: manager,
          max_gas_limit: 100_000,
          stub: %{estimate_gas: {:ok, 3_000_000}}
        )

      requirements = requirements()

      assert {:ok, %{"success" => false, "errorReason" => "settle_gas_limit_exceeded"}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      # The fee payer never broadcast against the gas-burning contract.
      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end
  end

  describe "settle/3" do
    test "broadcasts the exact signed EIP-1559 transaction and confirms it", context do
      engine = engine(context, stub: %{receipts: [nil, %{"status" => "0x1"}]})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => true,
                "transaction" => @tx_hash,
                "network" => @network,
                "payer" => @payer
              }} == Engine.settle(engine, payload, requirements)

      # Re-verify ran (preflight batch) before any transaction work.
      assert_received {:rpc, "eth_chainId", []}
      assert_received {:rpc, "eth_estimateGas", [call]}
      assert call["from"] == @facilitator_address
      assert call["to"] == @asset

      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex]}
      raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)

      assert [
               chain_id,
               nonce,
               max_priority,
               max_fee,
               gas_limit,
               to,
               value,
               data,
               [],
               y_parity,
               r,
               s
             ] = TestRLPDecoder.decode_eip1559(raw)

      assert :binary.decode_unsigned(chain_id) == 84_532
      assert :binary.decode_unsigned(nonce) == 5
      assert :binary.decode_unsigned(max_priority) == 1_000_000
      # maxFeePerGas = 2 * next base fee (120) + priority.
      assert :binary.decode_unsigned(max_fee) == 1_000_240
      # 20% margin over the 60_000 estimate.
      assert :binary.decode_unsigned(gas_limit) == 72_000
      assert to == @asset_bytes
      assert value == ""

      # The calldata is exactly the shared EIP-3009 builder's output for the
      # signed authorization.
      authorization = payload["payload"]["authorization"]
      "0x" <> signature_hex = payload["payload"]["signature"]
      signature_bytes = Base.decode16!(signature_hex, case: :mixed)
      assert {:ok, data} == EIP3009.transfer_calldata(authorization, signature_bytes, :eoa)

      # Recovery proof: the broadcast transaction was signed by the
      # facilitator key.
      rebuilt_digest =
        ExKeccak.hash_256(
          <<0x02>> <>
            X402.RLP.encode([
              chain_id,
              nonce,
              max_priority,
              max_fee,
              gas_limit,
              to,
              value,
              data,
              []
            ])
        )

      recovery_signature =
        pad_word(r) <> pad_word(s) <> <<:binary.decode_unsigned(pad_word(y_parity)) + 27>>

      assert EIP3009.recover_signer(rebuilt_digest, recovery_signature) ==
               {:ok, @facilitator_address}
    end

    test "falls back to eth_gasPrice when EIP-1559 fee APIs are unavailable", context do
      engine = engine(context, stub: %{max_priority_fee: :error})
      requirements = requirements()

      assert {:ok, %{"success" => true}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert_received {:rpc, "eth_gasPrice", []}
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex]}

      raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
      [_chain, _nonce, max_priority, max_fee | _rest] = TestRLPDecoder.decode_eip1559(raw)

      assert :binary.decode_unsigned(max_priority) == 2_000_000
      assert :binary.decode_unsigned(max_fee) == 4_000_000
    end

    test "re-verify rejects before any transaction is built", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = requirements(%{"amount" => "20000"})

      assert Engine.settle(engine, payload, tampered) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "invalid_exact_evm_payload_authorization_value_mismatch",
                  "transaction" => "",
                  "network" => @network,
                  "payer" => @payer
                }}

      refute_received {:rpc, "eth_sendRawTransaction", _params}
      refute_received {:rpc, "eth_estimateGas", _params}
    end

    test "fee-payer safety: a tampered asset fails signature re-verification", context do
      other_asset = "0x4444444444444444444444444444444444444444"

      engine =
        engine(context,
          stub: %{
            code: %{
              String.downcase(@asset) => "0x6001",
              String.downcase(other_asset) => "0x6001"
            }
          }
        )

      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = requirements(%{"asset" => other_asset})

      assert {:ok, %{"success" => false, "errorReason" => "invalid_exact_evm_signature"}} =
               Engine.settle(engine, payload, tampered)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "fee-payer safety: counterfactual ERC-6492 payments are refused", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      "0x" <> inner_hex = payload["payload"]["signature"]
      inner = Base.decode16!(inner_hex, case: :mixed)
      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xDE, 0xAD>>, inner)

      wrapped_payload =
        put_in(
          payload,
          ["payload", "signature"],
          "0x" <> Base.encode16(wrapped, case: :lower)
        )

      assert {:ok, %{"success" => false, "errorReason" => "eip6492_factory_not_allowed"}} =
               Engine.settle(engine, wrapped_payload, requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a reverted transaction returns the failed wire response", context do
      engine = engine(context, stub: %{receipts: [%{"status" => "0x0"}]})
      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_evm_transaction_failed",
                "transaction" => @tx_hash
              }} = Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a receipt that never arrives returns settlement_pending with the hash", context do
      engine =
        engine(context,
          stub: %{receipts: []},
          receipt_timeout_ms: 50,
          receipt_interval_ms: 10
        )

      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => @tx_hash,
                "network" => @network
              }} = Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a node rejection of the broadcast returns unexpected_settle_error", context do
      engine =
        engine(context,
          stub: %{send_raw: {:error, %{"code" => -32_000, "message" => "nonce too low"}}}
        )

      requirements = requirements()

      assert {:ok, %{"success" => false, "errorReason" => "unexpected_settle_error"}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "an eth_estimateGas revert is a protocol-level rejection", context do
      engine =
        engine(context,
          stub: %{estimate_gas: {:error, %{"code" => 3, "message" => "execution reverted"}}}
        )

      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_evm_transaction_simulation_failed"
              }} = Engine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "an estimateGas revert for a consumed authorization reports nonce_already_used",
         context do
      engine =
        engine(context,
          stub: %{
            estimate_gas:
              {:error,
               %{
                 "code" => 3,
                 "message" => "execution reverted: FiatTokenV2: authorization is used or canceled"
               }}
          }
        )

      requirements = requirements()

      # A retry of a payment whose transaction already confirmed (pending
      # entry expired or consumed by a concurrent retry) passes re-verify and
      # dies at estimateGas with the token's revert text — the canonical
      # nonce_already_used tells the client the payment already went through,
      # where simulation_failed would invite a double payment.
      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_evm_nonce_already_used"
              }} = Engine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a transport failure on broadcast returns settlement_pending with the local hash",
         context do
      engine = engine(context, stub: %{send_raw: :http_error})
      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => transaction_hash
              }} = Engine.settle(engine, signed_payload(requirements), requirements)

      # The hash is computed locally: keccak-256 of the raw transaction that
      # was on the wire when the transport failed.
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex]}
      raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
      assert transaction_hash == "0x" <> Base.encode16(ExKeccak.hash_256(raw), case: :lower)
    end

    test "a transport failure on broadcast consumes the nonce (may have landed)", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      # Both broadcasts fail at the transport layer — ambiguous, the node may
      # have accepted them, so each nonce must be consumed rather than left
      # in flight (a stuck in-flight nonce could never drain to re-fetch).
      engine = engine(context, nonce_manager: manager, stub: %{send_raw: :http_error})
      requirements = requirements()

      assert {:ok, %{"errorReason" => "settlement_pending"}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert {:ok, %{"errorReason" => "settlement_pending"}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      # One node fetch, and consecutive nonces: the first ambiguous broadcast
      # consumed its nonce instead of stalling the counter behind a gap.
      assert_received {:rpc, "eth_getTransactionCount", _params}
      refute_received {:rpc, "eth_getTransactionCount", _params2}

      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_1]}
      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex_2]}

      [nonce_1, nonce_2] =
        for raw_hex <- [raw_hex_1, raw_hex_2] do
          raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
          [_chain_id, nonce | _rest] = TestRLPDecoder.decode_eip1559(raw)
          :binary.decode_unsigned(nonce)
        end

      assert nonce_2 == nonce_1 + 1
    end

    test "a non-binary broadcast result is an infrastructure error", context do
      engine = engine(context, stub: %{send_raw: {:ok, 42}})
      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_response, 42}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "an unreachable RPC is an infrastructure error", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      Bypass.down(context.bypass)

      assert {:error, {:rpc_error, _reason}} = Engine.settle(engine, payload, requirements)
    end

    test "an empty fee history falls back to eth_gasPrice", context do
      engine = engine(context, stub: %{fee_history: {:ok, []}})
      requirements = requirements()

      assert {:ok, %{"success" => true}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert_received {:rpc, "eth_gasPrice", []}
    end

    test "simulate_in_settle runs the eth_call simulation during re-verify", context do
      engine = engine(context, simulate_in_settle: true, stub: %{simulate: {:revert, "nope"}})
      requirements = requirements()

      assert {:ok, %{"success" => false}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end
  end

  # -- ERC-6492 counterfactual settlement ---------------------------------------

  describe "settle/3 — ERC-6492 counterfactual" do
    test "deploys the wallet then transfers, on consecutive nonces", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        engine(context,
          nonce_manager: manager,
          eip6492_allowed_factories: [@factory],
          stub: %{receipts: [%{"status" => "0x1"}, %{"status" => "0x1"}]}
        )

      requirements = requirements()
      {payload, inner} = counterfactual_payload(signed_payload(requirements), @factory)

      assert {:ok, %{"success" => true, "transaction" => @tx_hash, "payer" => @payer}} =
               Engine.settle(engine, payload, requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [deploy_hex]}
      assert_received {:rpc, "eth_sendRawTransaction", [transfer_hex]}
      refute_received {:rpc, "eth_sendRawTransaction", _params}

      [deploy, transfer] =
        for raw_hex <- [deploy_hex, transfer_hex] do
          raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
          TestRLPDecoder.decode_eip1559(raw)
        end

      # First broadcast: the wrapper's factory calldata toward the factory.
      [_chain, deploy_nonce, _priority, _fee, _gas, deploy_to, deploy_value, deploy_data | _] =
        deploy

      assert deploy_to == @factory_bytes
      assert deploy_value == ""
      assert deploy_data == @factory_calldata

      # Second broadcast: the bytes-variant transfer with the inner signature.
      [_chain2, transfer_nonce, _priority2, _fee2, _gas2, transfer_to, _value2, transfer_data | _] =
        transfer

      assert transfer_to == @asset_bytes

      authorization = payload["payload"]["authorization"]

      assert {:ok, transfer_data} ==
               EIP3009.transfer_calldata(authorization, inner, :erc6492_counterfactual)

      assert :binary.decode_unsigned(transfer_nonce) ==
               :binary.decode_unsigned(deploy_nonce) + 1
    end

    test "an unlisted factory is rejected at verify and at settle without broadcasting",
         context do
      engine =
        engine(context,
          eip6492_allowed_factories: ["0x5555555555555555555555555555555555555555"]
        )

      requirements = requirements()
      {payload, _inner} = counterfactual_payload(signed_payload(requirements), @factory)

      assert {:ok, %{"isValid" => false, "invalidReason" => "eip6492_factory_not_allowed"}} =
               Engine.verify(engine, payload, requirements)

      assert {:ok, %{"success" => false, "errorReason" => "eip6492_factory_not_allowed"}} =
               Engine.settle(engine, payload, requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a reverted deployment fails without broadcasting the transfer", context do
      engine =
        engine(context,
          eip6492_allowed_factories: [@factory],
          stub: %{receipts: [%{"status" => "0x0"}]}
        )

      requirements = requirements()
      {payload, _inner} = counterfactual_payload(signed_payload(requirements), @factory)

      assert {:ok, %{"success" => false, "errorReason" => "smart_wallet_deployment_failed"}} =
               Engine.settle(engine, payload, requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [_deploy_hex]}
      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a deployment estimateGas revert keeps the deployment failure reason", context do
      engine =
        engine(context,
          eip6492_allowed_factories: [@factory],
          stub: %{
            estimate_gas:
              {:error, %{"code" => 3, "message" => "execution reverted: authorization is used"}}
          }
        )

      requirements = requirements()
      {payload, _inner} = counterfactual_payload(signed_payload(requirements), @factory)

      # Revert-text classification applies only to the transfer's estimate —
      # the factory deployment keeps its own fixed reason.
      assert {:ok, %{"success" => false, "errorReason" => "smart_wallet_deployment_failed"}} =
               Engine.settle(engine, payload, requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a deployment estimate above the deploy ceiling refuses to settle", context do
      engine =
        engine(context,
          eip6492_allowed_factories: [@factory],
          max_deploy_gas_limit: 100_000,
          stub: %{estimate_gas: {:ok, 3_000_000}}
        )

      requirements = requirements()
      {payload, _inner} = counterfactual_payload(signed_payload(requirements), @factory)

      assert {:ok, %{"success" => false, "errorReason" => "settle_gas_limit_exceeded"}} =
               Engine.settle(engine, payload, requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a wallet deployed since verification skips the deployment", context do
      engine =
        engine(context,
          eip6492_allowed_factories: [@factory],
          stub: %{
            code: %{
              String.downcase(@asset) => "0x6001",
              # Undeployed during the re-verify's preflight, deployed by the
              # time the engine re-checks before broadcasting.
              @payer => ["0x", "0x6001"]
            }
          }
        )

      requirements = requirements()
      {payload, inner} = counterfactual_payload(signed_payload(requirements), @factory)

      assert {:ok, %{"success" => true, "transaction" => @tx_hash}} =
               Engine.settle(engine, payload, requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex]}
      refute_received {:rpc, "eth_sendRawTransaction", _params}

      raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)

      [_chain, _nonce, _priority, _fee, _gas, to, _value, data | _] =
        TestRLPDecoder.decode_eip1559(raw)

      assert to == @asset_bytes

      authorization = payload["payload"]["authorization"]

      assert {:ok, data} ==
               EIP3009.transfer_calldata(authorization, inner, :erc6492_counterfactual)
    end
  end

  # -- Transfer-event verification ----------------------------------------------

  describe "settle/3 Transfer-event verification" do
    test "a mismatched Transfer event is a terminal failure", context do
      engine =
        engine(context,
          stub: %{
            receipts: [
              %{"status" => "0x1", "logs" => [X402.TestRPCStub.transfer_log(%{value: 999})]}
            ]
          }
        )

      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_evm_transfer_event_mismatch",
                "transaction" => @tx_hash
              }} = Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a receipt without the Transfer log is a terminal failure", context do
      engine = engine(context, stub: %{receipts: [%{"status" => "0x1", "logs" => []}]})
      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_evm_transfer_event_mismatch",
                "transaction" => @tx_hash
              }} = Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "unreadable logs return settlement_pending", context do
      engine = engine(context, stub: %{receipts: [%{"status" => "0x1", "logs" => ["junk"]}]})
      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => @tx_hash
              }} = Engine.settle(engine, signed_payload(requirements), requirements)
    end
  end

  # -- Pending-settlement reconciliation ----------------------------------------

  describe "settle/3 with a pending-settlement store" do
    test "a receipt timeout records the pending entry and a retry reconciles it", context do
      store = pending_store(__MODULE__.TimeoutStore)
      {:ok, queue} = Agent.start_link(fn -> [] end)

      engine =
        engine(context,
          pending_settlement_store: store,
          receipt_timeout_ms: 50,
          receipt_interval_ms: 10,
          stub: %{receipt_queue: queue}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => @tx_hash
              }} = Engine.settle(engine, payload, requirements)

      assert {:hit,
              %{transaction: @tx_hash, provenance: :node_acknowledged, raw_transaction: nil}} =
               PendingSettlementStore.get(store, pending_key(payload))

      # Consume the first attempt's broadcast so the retries can prove they
      # add none.
      assert_received {:rpc, "eth_sendRawTransaction", [_raw_hex]}
      assert_received {:rpc, "eth_estimateGas", [_call]}

      # A retry that still cannot confirm re-records the entry and stays
      # pending.
      assert {:ok, %{"errorReason" => "settlement_pending"}} =
               Engine.settle(engine, payload, requirements)

      assert {:hit, %{transaction: @tx_hash}} =
               PendingSettlementStore.get(store, pending_key(payload))

      Agent.update(queue, fn _empty -> [%{"status" => "0x1"}] end)

      assert {:ok, %{"success" => true, "transaction" => @tx_hash}} =
               Engine.settle(engine, payload, requirements)

      # The retries reconciled: no re-verify, no second broadcast, and the
      # confirmed entry stays deleted.
      refute_received {:rpc, "eth_sendRawTransaction", _params}
      refute_received {:rpc, "eth_estimateGas", _params2}
      assert PendingSettlementStore.get(store, pending_key(payload)) == :miss
    end

    test "a transport failure records a local-hash entry that a retry re-awaits", context do
      store = pending_store(__MODULE__.TransportStore)
      {:ok, queue} = Agent.start_link(fn -> [] end)

      engine =
        engine(context,
          pending_settlement_store: store,
          stub: %{send_raw: :http_error, receipt_queue: queue}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => local_hash
              }} = Engine.settle(engine, payload, requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [raw_hex]}
      raw = Base.decode16!(String.trim_leading(raw_hex, "0x"), case: :mixed)
      assert local_hash == "0x" <> Base.encode16(ExKeccak.hash_256(raw), case: :lower)

      assert {:hit, %{transaction: ^local_hash, provenance: :local_hash, raw_transaction: ^raw}} =
               PendingSettlementStore.get(store, pending_key(payload))

      # The retry re-awaits the recorded hash — it never rebroadcasts the
      # stored raw bytes.
      Agent.update(queue, fn _empty -> [%{"status" => "0x1"}] end)

      assert {:ok, %{"success" => true, "transaction" => ^local_hash}} =
               Engine.settle(engine, payload, requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
      assert_received {:rpc, "eth_getTransactionReceipt", [^local_hash]}
    end

    test "a failed pending-store write downgrades to a terminal failure", context do
      store = pending_store(__MODULE__.FullStore, max_size: 1)

      :ok =
        PendingSettlementStore.put(store, "occupied", %{
          transaction: "0x00",
          provenance: :node_acknowledged,
          raw_transaction: nil
        })

      engine =
        engine(context,
          pending_settlement_store: store,
          receipt_timeout_ms: 50,
          receipt_interval_ms: 10,
          stub: %{receipts: []}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok,
                  %{
                    "success" => false,
                    "errorReason" => "invalid_exact_evm_transaction_failed",
                    "transaction" => @tx_hash
                  }} = Engine.settle(engine, payload, requirements)
        end)

      assert log =~ "failed to persist for retry"
    end

    test "reconcile validates the Transfer event against the signed authorization, not the retry's requirements",
         context do
      store = pending_store(__MODULE__.DriftStore)
      {:ok, queue} = Agent.start_link(fn -> [] end)

      engine =
        engine(context,
          pending_settlement_store: store,
          receipt_timeout_ms: 50,
          receipt_interval_ms: 10,
          stub: %{receipt_queue: queue}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{"errorReason" => "settlement_pending", "transaction" => @tx_hash}} =
               Engine.settle(engine, payload, requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [_raw_hex]}

      # The transaction confirms on chain with the real
      # Transfer(payer, payTo, 10000) log.
      Agent.update(queue, fn _empty -> [%{"status" => "0x1"}] end)

      # Retry with the identical payload but drifted requirements (e.g. the
      # resource server re-derived them after a price change). The reconcile
      # path runs without re-verification, so the expected event must come
      # from the signature-bound authorization: the completed settlement is
      # reported as success, not as a transfer-event mismatch.
      drifted = requirements(%{"amount" => "12000"})

      assert {:ok, %{"success" => true, "transaction" => @tx_hash}} =
               Engine.settle(engine, payload, drifted)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
      assert PendingSettlementStore.get(store, pending_key(payload)) == :miss
    end

    test "an unavailable store falls through to a normal broadcast instead of crashing",
         context do
      # The configured store name was never started: every adapter call
      # exits (:noproc) inside GenServer.call.
      store = {X402.Facilitator.PendingSettlementStore.ETS, __MODULE__.NeverStartedStore}

      engine = engine(context, pending_settlement_store: store)
      requirements = requirements()

      assert {:ok, %{"success" => true, "transaction" => @tx_hash}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      assert_received {:rpc, "eth_sendRawTransaction", [_raw_hex]}
    end

    test "a pending write against a dead store downgrades to a terminal failure with the hash",
         context do
      store = {X402.Facilitator.PendingSettlementStore.ETS, __MODULE__.DeadStore}

      engine =
        engine(context,
          pending_settlement_store: store,
          receipt_timeout_ms: 50,
          receipt_interval_ms: 10,
          stub: %{receipts: []}
        )

      requirements = requirements()

      # The broadcast happened; the store exit on put must not crash the
      # settle — the terminal response keeps the transaction hash for
      # manual reconciliation.
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok,
                  %{
                    "success" => false,
                    "errorReason" => "invalid_exact_evm_transaction_failed",
                    "transaction" => @tx_hash
                  }} = Engine.settle(engine, signed_payload(requirements), requirements)
        end)

      assert log =~ "failed to persist for retry"
    end
  end

  # -- Hooks ------------------------------------------------------------------

  defmodule HaltHooks do
    @behaviour X402.Hooks

    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def before_verify(_context, _metadata), do: {:halt, "blocked_by_policy"}
    def before_settle(_context, _metadata), do: {:halt, :not_verified}
  end

  defmodule RecoverHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default

    def on_verify_failure(_context, _metadata),
      do: {:recover, %{"isValid" => true, "payer" => "0xrecovered"}}

    def on_settle_failure(_context, _metadata),
      do: {:recover, %{"success" => true, "transaction" => "0xrecovered"}}
  end

  defmodule ReplaceResultHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def after_verify(context, _metadata),
      do: {:cont, %{context | result: Map.put(context.result, "note", "audited")}}
  end

  defmodule RaisingHooks do
    @behaviour X402.Hooks

    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def before_verify(_context, _metadata), do: raise("hook boom")
  end

  defmodule InvalidReturnHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def after_verify(_context, _metadata), do: :nonsense
  end

  defmodule NilResultHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def after_verify(context, _metadata), do: {:cont, %{context | result: nil}}
  end

  defmodule NoAddressSigner do
    @behaviour X402.Signer

    defstruct []

    def address(_signer), do: {:error, :no_address}
    def sign_eip712(_signer, _digest, _typed_data), do: {:error, :no_key}
  end

  defmodule FailingSigner do
    @behaviour X402.Signer

    defstruct []

    def address(_signer), do: {:ok, "0x1563915e194d8cfba1943570603f7606a3115508"}
    def sign_eip712(_signer, _digest, _typed_data), do: {:error, :signer_unavailable}
  end

  defmodule InvalidBeforeSettleHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def before_settle(_context, _metadata), do: :nonsense
  end

  defmodule ThrowingBeforeVerifyHooks do
    @behaviour X402.Hooks

    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def before_verify(_context, _metadata), do: throw(:engine_boom)
  end

  defmodule TupleHaltHooks do
    @behaviour X402.Hooks

    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def before_verify(_context, _metadata), do: {:halt, {:rate_limited, 42}}
  end

  defmodule RaisingAfterVerifyHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate on_verify_failure(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def after_verify(_context, _metadata), do: raise("after boom")
  end

  defmodule RaisingFailureHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default

    def on_verify_failure(_context, _metadata), do: raise("failure hook boom")
    def on_settle_failure(_context, _metadata), do: raise("failure hook boom")
  end

  defmodule InvalidFailureReturnHooks do
    @behaviour X402.Hooks

    defdelegate before_verify(context, metadata), to: X402.Hooks.Default
    defdelegate after_verify(context, metadata), to: X402.Hooks.Default
    defdelegate before_settle(context, metadata), to: X402.Hooks.Default
    defdelegate after_settle(context, metadata), to: X402.Hooks.Default
    defdelegate on_settle_failure(context, metadata), to: X402.Hooks.Default

    def on_verify_failure(_context, _metadata), do: :bogus
  end

  describe "hooks" do
    test "before_verify halt becomes a rejected wire response", context do
      engine = engine(context, hooks: HaltHooks)
      requirements = requirements()

      assert Engine.verify(engine, signed_payload(requirements), requirements) ==
               {:ok,
                %{
                  "isValid" => false,
                  "invalidReason" => "blocked_by_policy",
                  "payer" => @payer
                }}

      refute_received {:rpc, _method, _params}
    end

    test "before_settle halt becomes a failed wire response", context do
      engine = engine(context, hooks: HaltHooks)
      requirements = requirements()

      assert Engine.settle(engine, signed_payload(requirements), requirements) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "not_verified",
                  "transaction" => "",
                  "network" => @network,
                  "payer" => @payer
                }}

      refute_received {:rpc, _method, _params}
    end

    test "on_verify_failure can recover a rejected verification", context do
      engine = engine(context, hooks: RecoverHooks)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert Engine.verify(engine, payload, requirements(%{"amount" => "20000"})) ==
               {:ok, %{"isValid" => true, "payer" => "0xrecovered"}}
    end

    test "on_settle_failure can recover a failed settlement", context do
      engine = engine(context, hooks: RecoverHooks, stub: %{receipts: [%{"status" => "0x0"}]})
      requirements = requirements()

      assert Engine.settle(engine, signed_payload(requirements), requirements) ==
               {:ok, %{"success" => true, "transaction" => "0xrecovered"}}
    end

    test "after_verify can replace the successful result", context do
      engine = engine(context, hooks: ReplaceResultHooks)
      requirements = requirements()

      assert {:ok, %{"isValid" => true, "note" => "audited"}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "after_verify leaving no result keeps the original response", context do
      engine = engine(context, hooks: NilResultHooks)
      requirements = requirements()

      assert {:ok, %{"isValid" => true, "payer" => @payer}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "a raising hook is an infrastructure error", context do
      engine = engine(context, hooks: RaisingHooks)
      requirements = requirements()

      assert {:error, {:hook_callback_failed, :before_verify, {:exception, %RuntimeError{}}}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "an invalid hook return is an infrastructure error", context do
      engine = engine(context, hooks: InvalidReturnHooks)
      requirements = requirements()

      assert {:error, {:hook_invalid_return, :after_verify, :nonsense}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "supported omits signers when the signer has no address", context do
      engine = engine(context, signer: %NoAddressSigner{})

      assert %{"signers" => %{}} = Engine.supported(engine)
    end

    test "on_verify_failure can recover an infrastructure error", context do
      engine = engine(context, hooks: RecoverHooks)
      requirements = requirements()
      payload = signed_payload(requirements)
      Bypass.down(context.bypass)

      assert Engine.verify(engine, payload, requirements) ==
               {:ok, %{"isValid" => true, "payer" => "0xrecovered"}}
    end

    test "responses omit the payer when the payload has none", context do
      engine = engine(context)

      assert Engine.verify(engine, %{"x402Version" => 2}, requirements(%{"scheme" => "upto"})) ==
               {:ok, %{"isValid" => false, "invalidReason" => "unsupported_scheme"}}
    end
  end

  describe "hook failure branches" do
    test "an invalid before_settle return is an infrastructure error", context do
      engine = engine(context, hooks: InvalidBeforeSettleHooks)
      requirements = requirements()

      assert {:error, {:hook_invalid_return, :before_settle, :nonsense}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:rpc, _method, _params}
    end

    test "a throwing hook is an infrastructure error", context do
      engine = engine(context, hooks: ThrowingBeforeVerifyHooks)
      requirements = requirements()

      assert {:error, {:hook_callback_failed, :before_verify, {:throw, :engine_boom}}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "a non-atom halt reason is stringified with inspect", context do
      engine = engine(context, hooks: TupleHaltHooks)
      requirements = requirements()

      assert {:ok, %{"isValid" => false, "invalidReason" => "{:rate_limited, 42}"}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "a raising after_verify on a successful verification is an infrastructure error",
         context do
      engine = engine(context, hooks: RaisingAfterVerifyHooks)
      requirements = requirements()

      assert {:error, {:hook_callback_failed, :after_verify, {:exception, %RuntimeError{}}}} =
               Engine.verify(engine, signed_payload(requirements), requirements)
    end

    test "a raising on_verify_failure on a rejected payment is an infrastructure error",
         context do
      engine = engine(context, hooks: RaisingFailureHooks)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:error, {:hook_callback_failed, :on_verify_failure, {:exception, %RuntimeError{}}}} =
               Engine.verify(engine, payload, requirements(%{"amount" => "20000"}))
    end

    test "a raising on_settle_failure on a failed settlement is an infrastructure error",
         context do
      engine = engine(context, hooks: RaisingFailureHooks)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:error, {:hook_callback_failed, :on_settle_failure, {:exception, %RuntimeError{}}}} =
               Engine.settle(engine, payload, requirements(%{"amount" => "20000"}))
    end

    test "a raising on_verify_failure on an infrastructure error keeps the hook error",
         context do
      engine = engine(context, hooks: RaisingFailureHooks)
      requirements = requirements()
      payload = signed_payload(requirements)
      Bypass.down(context.bypass)

      assert {:error, {:hook_callback_failed, :on_verify_failure, {:exception, %RuntimeError{}}}} =
               Engine.verify(engine, payload, requirements)
    end

    test "an invalid on_verify_failure return is an infrastructure error", context do
      engine = engine(context, hooks: InvalidFailureReturnHooks)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:error, {:hook_invalid_return, :on_verify_failure, :bogus}} =
               Engine.verify(engine, payload, requirements(%{"amount" => "20000"}))
    end
  end

  describe "settle/3 with pathological node responses" do
    test "a signer failure after the preflight is an infrastructure error", context do
      engine = engine(context, signer: %FailingSigner{})
      requirements = requirements()

      assert {:error, {:settle_error, :signer_unavailable}} =
               Engine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:rpc, "eth_sendRawTransaction", _params}
    end

    test "a transport failure on the settle preflight batch is an infrastructure error",
         context do
      engine = scripted_engine(context, fail_settle_batch: true)
      requirements = requirements()

      assert {:error, {:rpc_error, {:http_error, 500}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a transport failure on the preflight batch with a nonce manager", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        scripted_engine(context, fail_settle_batch: true, engine: [nonce_manager: manager])

      requirements = requirements()

      assert {:error, {:rpc_error, {:http_error, 500}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a non-numeric gas estimate is an infrastructure error", context do
      engine = scripted_engine(context, results: %{"eth_estimateGas" => "0x12zz"})
      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_response, "0x12zz"}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "an unprefixed gas estimate is an infrastructure error", context do
      engine = scripted_engine(context, results: %{"eth_estimateGas" => "60000"})
      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_response, "60000"}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a non-numeric pending nonce is an infrastructure error", context do
      engine = scripted_engine(context, results: %{"eth_getTransactionCount" => "0xzz"})
      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_response, "0xzz"}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a node-side error on the pending nonce is an infrastructure error", context do
      engine =
        scripted_engine(context,
          results: %{
            "eth_getTransactionCount" => {:error, %{"code" => -32_000, "message" => "boom"}}
          }
        )

      requirements = requirements()

      assert {:error, {:rpc_error, {:jsonrpc_error, _error}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "a failing eth_gasPrice fallback is an infrastructure error", context do
      engine =
        scripted_engine(context,
          results: %{
            "eth_maxPriorityFeePerGas" =>
              {:error, %{"code" => -32_601, "message" => "method not found"}},
            "eth_gasPrice" => {:error, %{"code" => -32_601, "message" => "method not found"}}
          }
        )

      requirements = requirements()

      assert {:error, {:rpc_error, {:jsonrpc_error, _error}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "with a nonce manager, a non-numeric fetched nonce is an infrastructure error",
         context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        scripted_engine(context,
          engine: [nonce_manager: manager],
          results: %{"eth_getTransactionCount" => "0xzz"}
        )

      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_nonce, "0xzz"}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "with a nonce manager, an unprefixed fetched nonce is an infrastructure error",
         context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        scripted_engine(context,
          engine: [nonce_manager: manager],
          results: %{"eth_getTransactionCount" => "17"}
        )

      requirements = requirements()

      assert {:error, {:rpc_error, {:invalid_nonce, "17"}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end

    test "with a nonce manager, a node-side nonce error is an infrastructure error", context do
      manager = start_supervised!({X402.Facilitator.NonceManager, []})

      engine =
        scripted_engine(context,
          engine: [nonce_manager: manager],
          results: %{
            "eth_getTransactionCount" => {:error, %{"code" => -32_000, "message" => "boom"}}
          }
        )

      requirements = requirements()

      assert {:error, {:rpc_error, {:jsonrpc_error, _error}}} =
               Engine.settle(engine, signed_payload(requirements), requirements)
    end
  end

  # Scripted JSON-RPC stub with raw per-method result injection, for
  # pathological node responses X402.TestRPCStub cannot produce (garbage hex
  # quantities, node-side errors on specific methods, failing only the settle
  # preflight batch). Overrides map a method name to a raw JSON-RPC result or
  # to `{:error, error_object}`.
  defp scripted_engine(context, opts) do
    results = Keyword.get(opts, :results, %{})
    fail_settle_batch? = Keyword.get(opts, :fail_settle_batch, false)

    Bypass.stub(context.bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)

      settle_batch? =
        is_list(decoded) and Enum.any?(decoded, &(&1["method"] == "eth_estimateGas"))

      if fail_settle_batch? and settle_batch? do
        Plug.Conn.resp(conn, 500, "boom")
      else
        scripted_reply(conn, decoded, results)
      end
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{context.bypass.port}", finch: context.finch)

    {:ok, engine} =
      [
        rpc: rpc,
        signer: facilitator_signer(),
        networks: [@network],
        receipt_timeout_ms: 500,
        receipt_interval_ms: 10
      ]
      |> Keyword.merge(Keyword.get(opts, :engine, []))
      |> Engine.new()

    engine
  end

  defp scripted_reply(conn, decoded, results) do
    responses = decoded |> List.wrap() |> Enum.map(&scripted_response(&1, results))
    response = if is_list(decoded), do: responses, else: hd(responses)

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(200, Jason.encode!(response))
  end

  defp scripted_response(%{"id" => id, "method" => method, "params" => params}, results) do
    case Map.get(results, method, scripted_default(method, params)) do
      {:error, error} -> %{"jsonrpc" => "2.0", "id" => id, "error" => error}
      result -> %{"jsonrpc" => "2.0", "id" => id, "result" => result}
    end
  end

  defp scripted_default("eth_chainId", _params), do: "0x14a34"

  defp scripted_default("eth_getCode", [address, _block]) do
    case String.downcase(address) == String.downcase(@asset) do
      true -> "0x6001"
      false -> "0x"
    end
  end

  defp scripted_default("eth_call", _params),
    do: "0x" <> Base.encode16(<<1_000_000::unsigned-big-integer-size(256)>>, case: :lower)

  defp scripted_default("eth_estimateGas", _params), do: "0xea60"
  defp scripted_default("eth_maxPriorityFeePerGas", _params), do: "0xf4240"
  defp scripted_default("eth_feeHistory", _params), do: %{"baseFeePerGas" => ["0x64", "0x78"]}
  defp scripted_default("eth_gasPrice", _params), do: "0x1e8480"
  defp scripted_default("eth_getTransactionCount", _params), do: "0x5"
  defp scripted_default("eth_sendRawTransaction", _params), do: @tx_hash
  defp scripted_default("eth_getTransactionReceipt", _params), do: %{"status" => "0x1"}

  defp pad_word(bytes) when byte_size(bytes) <= 32,
    do: :binary.copy(<<0>>, 32 - byte_size(bytes)) <> bytes
end
