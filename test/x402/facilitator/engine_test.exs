defmodule X402.Facilitator.EngineTest do
  use ExUnit.Case, async: false

  alias X402.EIP3009
  alias X402.ERC6492
  alias X402.Facilitator.Engine
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

  defp pad_word(bytes) when byte_size(bytes) <= 32,
    do: :binary.copy(<<0>>, 32 - byte_size(bytes)) <> bytes
end
