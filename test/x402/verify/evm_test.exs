defmodule X402.Verify.EVMTest do
  use ExUnit.Case, async: false

  alias X402.EIP3009
  alias X402.ERC6492
  alias X402.RPC
  alias X402.Signer.LocalKey
  alias X402.Verify.EVM

  import X402.TestHelpers

  doctest X402.Verify.EVM

  @private_key "0x" <> String.duplicate("11", 32)
  @payer "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @factory "0x3333333333333333333333333333333333333333"
  @multicall3 "0xca11bde05977b3631167028862be2a173976ca11"
  @smart_wallet "0x4444444444444444444444444444444444444444"

  # -- Fixtures ---------------------------------------------------------------

  defp requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => "eip155:84532",
        "amount" => "10000",
        "asset" => @asset,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 600,
        "extra" => %{"name" => "USDC", "version" => "2"}
      },
      overrides
    )
  end

  defp signer do
    {:ok, signer} = LocalKey.new(@private_key)
    signer
  end

  defp signed_payload(requirements) do
    {:ok, scheme_payload} = EIP3009.sign(requirements, signer())
    envelope(requirements, scheme_payload)
  end

  defp envelope(requirements, scheme_payload) do
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp unsigned_payload(requirements, from, signature_hex, auth_overrides \\ %{}) do
    now = System.system_time(:second)

    authorization =
      Map.merge(
        %{
          "from" => from,
          "to" => requirements["payTo"],
          "value" => requirements["amount"],
          "validAfter" => Integer.to_string(now - 60),
          "validBefore" => Integer.to_string(now + 600),
          "nonce" => "0x" <> String.duplicate("ab", 32)
        },
        auth_overrides
      )

    envelope(requirements, %{"signature" => signature_hex, "authorization" => authorization})
  end

  defp put_authorization(payload, key, value) do
    update_in(payload, ["payload", "authorization"], &Map.put(&1, key, value))
  end

  defp contract_payload(requirements) do
    unsigned_payload(requirements, @smart_wallet, "0x" <> String.duplicate("22", 80))
  end

  defp counterfactual_payload(requirements) do
    inner = :crypto.strong_rand_bytes(65)
    {:ok, wrapped} = ERC6492.wrap(@factory, <<0xDE, 0xAD>>, inner)
    wrapped_hex = "0x" <> Base.encode16(wrapped, case: :lower)
    unsigned_payload(requirements, @smart_wallet, wrapped_hex)
  end

  defp verify_with_revert(context, overrides) do
    rpc = stub_rpc(context, Map.merge(%{simulate: {:revert, "opaque failure"}}, overrides))
    requirements = requirements()
    payload = signed_payload(requirements)
    EVM.verify(payload, requirements, level: :full, rpc: rpc)
  end

  # -- JSON-RPC stub ----------------------------------------------------------

  defp stub_defaults do
    %{
      chain_id: 84_532,
      code: %{String.downcase(@asset) => "0x6001"},
      balance: 1_000_000,
      diagnosis_balance: nil,
      is_valid_signature: :magic,
      simulate: :ok,
      authorization_state: {:ok, false},
      token_name: "USDC",
      token_version: "2",
      multicall: [{true, <<>>}, {true, <<>>}]
    }
  end

  defp stub_rpc(%{bypass: bypass, finch: finch}, overrides) do
    config = Map.merge(stub_defaults(), Map.new(overrides))
    test_pid = self()

    Bypass.expect(bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      response =
        case Jason.decode!(body) do
          requests when is_list(requests) ->
            diagnosis? = Enum.any?(requests, &authorization_state_request?/1)
            Enum.map(requests, &handle_rpc(&1, config, test_pid, diagnosis?))

          request ->
            handle_rpc(request, config, test_pid, false)
        end

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(response))
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: finch)
    rpc
  end

  defp authorization_state_request?(%{
         "method" => "eth_call",
         "params" => [%{"data" => data} | _]
       }),
       do: String.starts_with?(data, "0xe94a0102")

  defp authorization_state_request?(_request), do: false

  defp handle_rpc(
         %{"id" => id, "method" => method, "params" => params},
         config,
         test_pid,
         diagnosis?
       ) do
    send(test_pid, {:rpc, method, params})

    case rpc_result(method, params, config, diagnosis?) do
      {:ok, result} -> %{"jsonrpc" => "2.0", "id" => id, "result" => result}
      {:error, error} -> %{"jsonrpc" => "2.0", "id" => id, "error" => error}
    end
  end

  defp rpc_result("eth_chainId", [], %{chain_id: :invalid}, _diagnosis?), do: {:ok, "0x"}

  defp rpc_result("eth_chainId", [], config, _diagnosis?),
    do: {:ok, "0x" <> Integer.to_string(config.chain_id, 16)}

  defp rpc_result("eth_getCode", [_address, _block], %{code: :error}, _diagnosis?),
    do: {:error, %{"code" => -32_000, "message" => "boom"}}

  defp rpc_result("eth_getCode", [address, _block], config, _diagnosis?),
    do: {:ok, Map.get(config.code, String.downcase(address), "0x")}

  defp rpc_result("eth_call", [%{"data" => "0x" <> data_hex} | _rest], config, diagnosis?) do
    dispatch_call(Base.decode16!(data_hex, case: :mixed), config, diagnosis?)
  end

  # balanceOf(address)
  defp dispatch_call(<<0x70, 0xA0, 0x82, 0x31, _rest::binary>>, config, diagnosis?) do
    balance =
      case {diagnosis?, config.diagnosis_balance} do
        {true, value} when not is_nil(value) -> value
        _other -> config.balance
      end

    case balance do
      :revert -> revert_error("balanceOf failed")
      {:raw, hex} -> {:ok, hex}
      value -> {:ok, uint_hex(value)}
    end
  end

  # isValidSignature(bytes32,bytes)
  defp dispatch_call(<<0x16, 0x26, 0xBA, 0x7E, args::binary>>, config, _diagnosis?) do
    <<_digest::binary-size(32), _offset::unsigned-big-integer-size(256),
      _length::unsigned-big-integer-size(256), _signature::binary>> = args

    case config.is_valid_signature do
      :magic -> {:ok, "0x1626ba7e" <> String.duplicate("00", 28)}
      :wrong_value -> {:ok, "0x" <> String.duplicate("ff", 32)}
      :revert -> revert_error("invalid signature")
      :empty -> {:ok, "0x"}
      :number -> {:ok, 42}
    end
  end

  # transferWithAuthorization — (v,r,s) and bytes variants
  defp dispatch_call(<<0xE3, 0xEE, 0x16, 0x0E, _rest::binary>>, config, _diagnosis?),
    do: simulate_result(config)

  defp dispatch_call(<<0xCF, 0x09, 0x29, 0x95, _rest::binary>>, config, _diagnosis?),
    do: simulate_result(config)

  # authorizationState(address,bytes32)
  defp dispatch_call(<<0xE9, 0x4A, 0x01, 0x02, _rest::binary>>, config, _diagnosis?) do
    case config.authorization_state do
      {:ok, used?} -> {:ok, uint_hex(if(used?, do: 1, else: 0))}
      {:raw, hex} -> {:ok, hex}
      :revert -> revert_error("authorizationState failed")
    end
  end

  # name()
  defp dispatch_call(<<0x06, 0xFD, 0xDE, 0x03>>, config, _diagnosis?) do
    case config.token_name do
      :revert -> revert_error("name failed")
      {:raw, hex} -> {:ok, hex}
      name -> {:ok, string_hex(name)}
    end
  end

  # version()
  defp dispatch_call(<<0x54, 0xFD, 0x4D, 0x50>>, config, _diagnosis?),
    do: {:ok, string_hex(config.token_version)}

  # aggregate3((address,bool,bytes)[])
  defp dispatch_call(<<0x82, 0xAD, 0x56, 0xCB, _rest::binary>>, config, _diagnosis?) do
    case config.multicall do
      :revert -> revert_error("multicall failed")
      :empty -> {:ok, "0x"}
      {:raw, hex} -> {:ok, hex}
      results -> {:ok, aggregate3_hex(results)}
    end
  end

  defp simulate_result(config) do
    case config.simulate do
      :ok -> {:ok, "0x"}
      {:revert, message} -> revert_error(message)
      {:revert_no_data, message} -> {:error, %{"code" => 3, "message" => message}}
      {:revert_raw, error} -> {:error, error}
    end
  end

  defp revert_error(message) do
    {:error,
     %{
       "code" => 3,
       "message" => "execution reverted: #{message}",
       "data" => "0x08c379a0" <> strip0x(string_hex(message))
     }}
  end

  defp strip0x("0x" <> hex), do: hex

  defp uint_hex(value),
    do: "0x" <> Base.encode16(<<value::unsigned-big-integer-size(256)>>, case: :lower)

  defp string_hex(string) do
    padded = string <> :binary.copy(<<0>>, rem(32 - rem(byte_size(string), 32), 32))

    "0x" <>
      Base.encode16(
        <<32::unsigned-big-integer-size(256), byte_size(string)::unsigned-big-integer-size(256)>> <>
          padded,
        case: :lower
      )
  end

  defp aggregate3_hex(results) do
    tuples =
      Enum.map(results, fn {success, data} ->
        flag = if success, do: 1, else: 0
        padded = data <> :binary.copy(<<0>>, rem(32 - rem(byte_size(data), 32), 32))

        <<flag::unsigned-big-integer-size(256), 64::unsigned-big-integer-size(256),
          byte_size(data)::unsigned-big-integer-size(256)>> <> padded
      end)

    {offsets, _end} =
      Enum.map_reduce(tuples, 32 * length(tuples), fn tuple, position ->
        {position, position + byte_size(tuple)}
      end)

    array =
      <<length(tuples)::unsigned-big-integer-size(256)>> <>
        Enum.map_join(offsets, &<<&1::unsigned-big-integer-size(256)>>) <> Enum.join(tuples)

    "0x" <> Base.encode16(<<32::unsigned-big-integer-size(256)>> <> array, case: :lower)
  end

  # -- Structural level -------------------------------------------------------

  describe "level :structural" do
    test "accepts a well-formed payload" do
      requirements = requirements()
      payload = unsigned_payload(requirements, @payer, "0x" <> String.duplicate("11", 130))

      assert {:ok, %{payer: @payer, level: :structural, signature_type: nil}} =
               EVM.verify(payload, requirements, level: :structural)
    end

    test "rejects non-map payload sections" do
      assert EVM.verify(%{"x402Version" => 2}, requirements(), level: :structural) ==
               {:error, {:invalid, :invalid_payload}}

      assert EVM.verify(
               %{"accepted" => requirements(), "payload" => "nope"},
               requirements(),
               level: :structural
             ) ==
               {:error, {:invalid, :invalid_payload}}
    end

    test "rejects scheme mismatches on either side" do
      requirements = requirements()
      payload = unsigned_payload(requirements, @payer, "0x11")

      upto = put_in(payload, ["accepted", "scheme"], "upto")

      assert EVM.verify(upto, requirements, level: :structural) ==
               {:error, {:invalid, :scheme_mismatch}}

      assert EVM.verify(payload, requirements(%{"scheme" => "upto"}), level: :structural) ==
               {:error, {:invalid, :scheme_mismatch}}
    end

    test "rejects network mismatches" do
      requirements = requirements()
      payload = unsigned_payload(requirements(%{"network" => "eip155:1"}), @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :network_mismatch}}
    end

    test "rejects non-EVM networks" do
      solana = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
      requirements = requirements(%{"network" => solana})
      payload = unsigned_payload(requirements, @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :unsupported_network}}
    end

    test "rejects a missing EIP-712 domain" do
      requirements = requirements(%{"extra" => %{"version" => "2"}})
      payload = unsigned_payload(requirements, @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :missing_eip712_domain}}
    end

    test "rejects non-default asset transfer methods" do
      requirements =
        requirements(%{
          "extra" => %{"name" => "USDC", "version" => "2", "assetTransferMethod" => "permit2"}
        })

      payload = unsigned_payload(requirements, @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :unsupported_transfer_method}}
    end

    test "rejects an invalid asset address" do
      requirements = requirements(%{"asset" => "0x123"})
      payload = unsigned_payload(requirements, @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_requirements}}
    end

    test "rejects missing or malformed signatures" do
      requirements = requirements()

      for signature <- ["0x", "0xzz", "not hex", nil] do
        payload = unsigned_payload(requirements, @payer, signature)

        assert EVM.verify(payload, requirements, level: :structural) ==
                 {:error, {:invalid, :invalid_signature}},
               "expected #{inspect(signature)} to be rejected"
      end
    end

    test "rejects malformed authorization objects" do
      requirements = requirements()
      base = unsigned_payload(requirements, @payer, "0x11")

      missing = update_in(base, ["payload"], &Map.delete(&1, "authorization"))

      assert EVM.verify(missing, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}

      bad_from = put_authorization(base, "from", "0x123")

      assert EVM.verify(bad_from, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}

      bad_nonce = put_authorization(base, "nonce", "0xabcd")

      assert EVM.verify(bad_nonce, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}

      bad_value = put_authorization(base, "value", "10.5e3")

      assert EVM.verify(bad_value, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}

      bad_time = put_authorization(base, "validBefore", "soon")

      assert EVM.verify(bad_time, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}
    end

    test "rejects recipients that do not match payTo" do
      requirements = requirements()

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{
          "to" => "0x1111111111111111111111111111111111111111"
        })

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :recipient_mismatch}}
    end

    test "accepts payTo equality case-insensitively" do
      requirements = requirements()

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{"to" => String.downcase(@pay_to)})

      assert {:ok, _result} = EVM.verify(payload, requirements, level: :structural)
    end

    test "rejects amounts that do not exactly match" do
      requirements = requirements()
      payload = unsigned_payload(requirements, @payer, "0x11", %{"value" => "10001"})

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :value_mismatch}}
    end

    test "rejects validBefore inside the 6-second settlement buffer" do
      now = System.system_time(:second)
      requirements = requirements()

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{
          "validBefore" => Integer.to_string(now + 5)
        })

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :valid_before_expired}}
    end

    test "accepts validBefore beyond the settlement buffer" do
      now = System.system_time(:second)
      requirements = requirements()

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{
          "validBefore" => Integer.to_string(now + 15)
        })

      assert {:ok, _result} = EVM.verify(payload, requirements, level: :structural)
    end

    test "rejects validAfter in the future" do
      now = System.system_time(:second)
      requirements = requirements()

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{
          "validAfter" => Integer.to_string(now + 60)
        })

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :valid_after_in_future}}
    end

    test "accepts integer timing and amount fields" do
      now = System.system_time(:second)
      requirements = requirements(%{"amount" => 10_000})

      payload =
        unsigned_payload(requirements, @payer, "0x11", %{
          "value" => 10_000,
          "validAfter" => now - 60,
          "validBefore" => now + 600
        })

      assert {:ok, _result} = EVM.verify(payload, requirements, level: :structural)
    end

    test "requires an explicit level" do
      assert_raise NimbleOptions.ValidationError, fn ->
        EVM.verify(%{}, %{}, [])
      end
    end

    test "rejects requirements whose extra is not a map" do
      requirements = requirements(%{"extra" => "nope"})
      payload = unsigned_payload(requirements, @payer, "0x11")

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_requirements}}
    end

    test "rejects non-integer authorization values" do
      requirements = requirements()
      payload = unsigned_payload(requirements, @payer, "0x11", %{"value" => 10_000.5})

      assert EVM.verify(payload, requirements, level: :structural) ==
               {:error, {:invalid, :invalid_authorization}}
    end
  end

  # -- Signature level --------------------------------------------------------

  describe "level :signature" do
    test "verifies a payload signed by the payer" do
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{payer: @payer, level: :signature, signature_type: :eoa}} =
               EVM.verify(payload, requirements, level: :signature)
    end

    test "rejects tampering with each signed authorization field" do
      requirements = requirements()
      payload = signed_payload(requirements)

      tampered_nonce = put_authorization(payload, "nonce", "0x" <> String.duplicate("cd", 32))

      assert EVM.verify(tampered_nonce, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}

      original_after = get_in(payload, ["payload", "authorization", "validAfter"])
      shifted_after = Integer.to_string(String.to_integer(original_after) - 1)
      tampered_after = put_authorization(payload, "validAfter", shifted_after)

      assert EVM.verify(tampered_after, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}

      original_before = get_in(payload, ["payload", "authorization", "validBefore"])
      shifted_before = Integer.to_string(String.to_integer(original_before) + 1)
      tampered_before = put_authorization(payload, "validBefore", shifted_before)

      assert EVM.verify(tampered_before, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}

      tampered_value = put_authorization(payload, "value", "10001")
      tampered_requirements = requirements(%{"amount" => "10001"})
      tampered_payload = put_in(tampered_value, ["accepted", "amount"], "10001")

      assert EVM.verify(tampered_payload, tampered_requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a payload claiming a different payer" do
      requirements = requirements()

      payload =
        put_authorization(
          signed_payload(requirements),
          "from",
          "0x1111111111111111111111111111111111111111"
        )

      assert EVM.verify(payload, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a signature over a different EIP-712 domain" do
      requirements = requirements()
      payload = signed_payload(requirements)

      other_requirements = requirements(%{"extra" => %{"name" => "USDX", "version" => "2"}})
      other_payload = put_in(payload, ["accepted", "extra", "name"], "USDX")

      assert EVM.verify(other_payload, other_requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects garbage 65-byte signatures" do
      requirements = requirements()
      payload = unsigned_payload(requirements, @payer, "0x" <> String.duplicate("11", 65))

      assert EVM.verify(payload, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "refuses smart-wallet signatures without RPC (fail closed)" do
      requirements = requirements()

      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xAB>>, :crypto.strong_rand_bytes(65))
      wrapped_hex = "0x" <> Base.encode16(wrapped, case: :lower)
      wrapped_payload = unsigned_payload(requirements, @smart_wallet, wrapped_hex)

      assert EVM.verify(wrapped_payload, requirements, level: :signature) ==
               {:error, {:invalid, :smart_wallet_requires_rpc}}

      contract_sig =
        unsigned_payload(requirements, @smart_wallet, "0x" <> String.duplicate("11", 33))

      assert EVM.verify(contract_sig, requirements, level: :signature) ==
               {:error, {:invalid, :smart_wallet_requires_rpc}}
    end

    test "rejects a malformed ERC-6492 wrapper" do
      requirements = requirements()
      malformed = <<1, 2, 3>> <> ERC6492.magic_suffix()
      signature_hex = "0x" <> Base.encode16(malformed, case: :lower)
      payload = unsigned_payload(requirements, @payer, signature_hex)

      assert EVM.verify(payload, requirements, level: :signature) ==
               {:error, {:invalid, :invalid_signature}}
    end
  end

  # -- Full level -------------------------------------------------------------

  describe "level :full" do
    setup [:setup_bypass, :setup_finch]

    test "requires a configured RPC endpoint" do
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full) == {:error, :rpc_not_configured}
    end

    test "verifies an EOA payment end to end", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{payer: @payer, level: :full, signature_type: :eoa}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)

      assert_received {:rpc, "eth_chainId", []}
      assert_received {:rpc, "eth_getCode", [@payer, "latest"]}
      assert_received {:rpc, "eth_call", [%{"data" => "0x70a08231" <> _args} | _block]}
      assert_received {:rpc, "eth_call", [%{"data" => "0xe3ee160e" <> _args} | _block]}
    end

    test "rejects an invalid EOA signature", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()

      payload =
        put_authorization(
          signed_payload(requirements),
          "nonce",
          "0x" <> String.duplicate("cd", 32)
        )

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a chain id mismatch before any signature work", context do
      rpc = stub_rpc(context, %{chain_id: 1})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:chain_id_mismatch, 84_532, 1}}
    end

    test "skips the chain id check when disabled", context do
      rpc = stub_rpc(context, %{chain_id: 1})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, _result} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc, verify_chain_id: false)

      refute_received {:rpc, "eth_chainId", []}
    end

    test "rejects an asset without bytecode", context do
      rpc = stub_rpc(context, %{code: %{}})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :asset_not_deployed_contract}}
    end

    test "rejects an underfunded payer", context do
      rpc = stub_rpc(context, %{balance: 9_999})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :insufficient_balance}}
    end

    test "fails closed when the balance probe reverts", context do
      rpc = stub_rpc(context, %{balance: :revert})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :balance_check_failed}}
    end

    test "skips simulation when disabled for deployed payers", context do
      rpc = stub_rpc(context, %{simulate: {:revert, "should not run"}})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, _result} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc, simulate: false)

      refute_received {:rpc, "eth_call", [%{"data" => "0xe3ee160e" <> _args} | _block]}
    end

    test "fails closed on transport errors", context do
      {:ok, rpc} =
        RPC.new(rpc_url: "http://localhost:#{context.bypass.port}", finch: context.finch)

      Bypass.down(context.bypass)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:error, {:rpc_error, {:transport_error, _reason}}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)
    end

    test "fails closed when eth_getCode errors node-side", context do
      rpc = stub_rpc(context, %{code: :error})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:error, {:rpc_error, {:jsonrpc_error, _error}}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)
    end

    test "fails closed on an undecodable chain id", context do
      rpc = stub_rpc(context, %{chain_id: :invalid})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:rpc_error, {:invalid_response, "0x"}}}
    end

    test "rejects an undecodable balance return", context do
      rpc = stub_rpc(context, %{balance: {:raw, "0x12"}})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :balance_check_failed}}
    end

    test "treats undecodable payer bytecode as no code", context do
      rpc = stub_rpc(context, %{code: %{String.downcase(@asset) => "0x6001", @payer => "zz"}})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{signature_type: :eoa}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)
    end

    test "accepts EOA signatures with a 0/1 recovery byte", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()
      payload = signed_payload(requirements)

      "0x" <> signature_hex = get_in(payload, ["payload", "signature"])
      <<compact::binary-size(64), v>> = Base.decode16!(signature_hex, case: :mixed)
      shifted = compact <> <<v - 27>>
      shifted_hex = "0x" <> Base.encode16(shifted, case: :lower)
      payload = put_in(payload, ["payload", "signature"], shifted_hex)

      assert {:ok, %{signature_type: :eoa}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)
    end

    test "rejects a non-65-byte signature from an undeployed payer", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()
      payload = unsigned_payload(requirements, @smart_wallet, "0x" <> String.duplicate("22", 33))

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end
  end

  describe "level :full — ERC-1271" do
    setup [:setup_bypass, :setup_finch]

    test "accepts a deployed wallet returning the magic value", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"}
        })

      requirements = requirements()
      payload = contract_payload(requirements)

      assert {:ok, %{signature_type: :erc1271}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)

      assert_received {:rpc, "eth_call",
                       [%{"to" => @smart_wallet, "data" => "0x1626ba7e" <> _args} | _block]}
    end

    test "simulates a 65-byte ERC-1271 signature through the bytes overload", context do
      # A smart wallet's signature can be exactly 65 bytes; the (v, r, s)
      # overload would run on-chain ECDSA and wrongly reject it. Overload
      # selection must follow the verified signature TYPE, not byte length.
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"}
        })

      requirements = requirements()

      payload =
        unsigned_payload(requirements, @smart_wallet, "0x" <> String.duplicate("22", 65))

      assert {:ok, %{signature_type: :erc1271}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)

      assert_received {:rpc, "eth_call", [%{"data" => "0xcf092995" <> _args} | _block]}
      refute_received {:rpc, "eth_call", [%{"data" => "0xe3ee160e" <> _args} | _block2]}
    end

    test "rejects uint256-overflowing timing values instead of crashing" do
      requirements = requirements()
      payload = contract_payload(requirements)

      overflowing =
        put_in(
          payload,
          ["payload", "authorization", "validBefore"],
          Integer.to_string(Integer.pow(2, 256))
        )

      assert {:error, {:invalid, _reason}} =
               EVM.verify(overflowing, requirements, level: :structural)
    end

    test "rejects a wallet returning a non-magic value", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"},
          is_valid_signature: :wrong_value
        })

      requirements = requirements()

      assert EVM.verify(contract_payload(requirements), requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a wallet whose isValidSignature reverts", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"},
          is_valid_signature: :revert
        })

      requirements = requirements()

      assert EVM.verify(contract_payload(requirements), requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a wallet returning a non-string result", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"},
          is_valid_signature: :number
        })

      requirements = requirements()

      assert EVM.verify(contract_payload(requirements), requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "rejects a wallet returning empty data", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"},
          is_valid_signature: :empty
        })

      requirements = requirements()

      assert EVM.verify(contract_payload(requirements), requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :invalid_signature}}
    end

    test "unwraps ERC-6492 for a deployed wallet and passes the inner signature", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"}
        })

      requirements = requirements()

      inner = :crypto.strong_rand_bytes(65)
      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xAB>>, inner)
      wrapped_hex = "0x" <> Base.encode16(wrapped, case: :lower)
      payload = unsigned_payload(requirements, @smart_wallet, wrapped_hex)

      assert {:ok, %{signature_type: :erc1271}} =
               EVM.verify(payload, requirements, level: :full, rpc: rpc)

      assert_received {:rpc, "eth_call",
                       [%{"to" => @smart_wallet, "data" => "0x1626ba7e" <> data} | _block]}

      assert String.contains?(data, Base.encode16(inner, case: :lower))
    end
  end

  describe "level :full — ERC-6492 counterfactual" do
    setup [:setup_bypass, :setup_finch]

    test "rejects counterfactual payments by default (empty factory allowlist)", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()

      assert EVM.verify(counterfactual_payload(requirements), requirements,
               level: :full,
               rpc: rpc
             ) ==
               {:error, {:invalid, :eip6492_factory_not_allowed}}
    end

    test "rejects counterfactual payments when simulation is disabled", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               simulate: false,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :undeployed_smart_wallet}}
    end

    test "accepts an allowlisted factory when the atomic simulation succeeds", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()

      assert {:ok, %{signature_type: :erc6492_counterfactual}} =
               EVM.verify(
                 counterfactual_payload(requirements),
                 requirements,
                 level: :full,
                 rpc: rpc,
                 eip6492_allowed_factories: [String.upcase(@factory)]
               )

      assert_received {:rpc, "eth_call",
                       [%{"to" => to, "data" => "0x82ad56cb" <> _args} | _block]}

      assert String.downcase(to) == @multicall3
    end

    test "rejects when the transfer leg of the simulation fails", context do
      revert_data =
        <<0x08, 0xC3, 0x79, 0xA0>> <>
          Base.decode16!(
            String.replace_prefix(
              string_hex("FiatTokenV2: authorization is used or canceled"),
              "0x",
              ""
            ),
            case: :lower
          )

      rpc = stub_rpc(context, %{multicall: [{true, <<>>}, {false, revert_data}]})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :nonce_already_used}}
    end

    test "falls back to diagnosis on an unclassifiable transfer failure", context do
      rpc = stub_rpc(context, %{multicall: [{true, <<>>}, {false, <<>>}]})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "treats an empty multicall return as a failed simulation", context do
      rpc = stub_rpc(context, %{multicall: :empty})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "diagnoses a multicall that reverts outright", context do
      rpc = stub_rpc(context, %{multicall: :revert})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "treats a truncated multicall return as a failed simulation", context do
      truncated =
        "0x" <>
          Base.encode16(
            <<32::unsigned-big-integer-size(256), 2::unsigned-big-integer-size(256),
              0::unsigned-big-integer-size(256)>>,
            case: :lower
          )

      rpc = stub_rpc(context, %{multicall: {:raw, truncated}})
      requirements = requirements()

      assert EVM.verify(
               counterfactual_payload(requirements),
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "rejects a counterfactual wrapper with an empty inner signature", context do
      rpc = stub_rpc(context, %{})
      requirements = requirements()

      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xDE, 0xAD>>, <<>>)
      wrapped_hex = "0x" <> Base.encode16(wrapped, case: :lower)
      payload = unsigned_payload(requirements, @smart_wallet, wrapped_hex)

      assert EVM.verify(
               payload,
               requirements,
               level: :full,
               rpc: rpc,
               eip6492_allowed_factories: [@factory]
             ) ==
               {:error, {:invalid, :invalid_signature}}
    end
  end

  describe "level :full — simulation diagnosis" do
    setup [:setup_bypass, :setup_finch]

    test "classifies known revert messages without a diagnosis batch", context do
      rpc =
        stub_rpc(context, %{simulate: {:revert, "FiatTokenV2: authorization is used or canceled"}})

      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :nonce_already_used}}

      refute_received {:rpc, "eth_call", [%{"data" => "0xe94a0102" <> _args} | _block]}
    end

    test "classifies revert reasons carried only in error data", context do
      rpc =
        stub_rpc(context, %{
          simulate: {:revert, "ERC20: transfer amount exceeds balance"}
        })

      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :insufficient_balance}}
    end

    test "diagnoses a token without EIP-3009 support", context do
      assert verify_with_revert(context, %{authorization_state: :revert}) ==
               {:error, {:invalid, :eip3009_not_supported}}
    end

    test "diagnoses an already-used nonce", context do
      assert verify_with_revert(context, %{authorization_state: {:ok, true}}) ==
               {:error, {:invalid, :nonce_already_used}}
    end

    test "diagnoses a token name mismatch", context do
      assert verify_with_revert(context, %{token_name: "USDX"}) ==
               {:error, {:invalid, :token_name_mismatch}}
    end

    test "diagnoses a token version mismatch", context do
      assert verify_with_revert(context, %{token_version: "1"}) ==
               {:error, {:invalid, :token_version_mismatch}}
    end

    test "diagnoses a balance drained between preflight and simulation", context do
      assert verify_with_revert(context, %{diagnosis_balance: 1}) ==
               {:error, {:invalid, :insufficient_balance}}
    end

    test "falls back to simulation_failed when nothing is conclusive", context do
      assert verify_with_revert(context, %{}) == {:error, {:invalid, :simulation_failed}}
    end

    test "tolerates undecodable diagnosis probe results", context do
      assert verify_with_revert(context, %{
               authorization_state: {:raw, "0x01"},
               token_name: :revert,
               diagnosis_balance: {:raw, "0x01"}
             }) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "tolerates an undecodable token name string", context do
      assert verify_with_revert(context, %{token_name: {:raw, "0x12"}}) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "classifies from the message when error data is not hex", context do
      rpc =
        stub_rpc(context, %{
          simulate:
            {:revert_raw,
             %{
               "code" => 3,
               "message" => "execution reverted: FiatTokenV2: authorization is expired",
               "data" => "0xzz"
             }}
        })

      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :valid_before_expired}}
    end

    test "diagnoses when the revert carries only a malformed Error(string)", context do
      rpc =
        stub_rpc(context, %{
          simulate: {:revert_raw, %{"code" => 3, "data" => "0x08c379a0"}}
        })

      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "handles reverts without error data", context do
      rpc =
        stub_rpc(context, %{
          simulate: {:revert_no_data, "execution reverted: FiatTokenV2: authorization is expired"}
        })

      requirements = requirements()
      payload = signed_payload(requirements)

      assert EVM.verify(payload, requirements, level: :full, rpc: rpc) ==
               {:error, {:invalid, :valid_before_expired}}
    end
  end

  describe "ABI selectors" do
    setup [:setup_bypass, :setup_finch]

    test "hardcoded selectors match keccak256 of the canonical signatures", context do
      rpc =
        stub_rpc(context, %{
          code: %{String.downcase(@asset) => "0x6001", @smart_wallet => "0x6001"}
        })

      requirements = requirements()
      payload = unsigned_payload(requirements, @smart_wallet, "0x" <> String.duplicate("22", 80))

      assert {:ok, _result} = EVM.verify(payload, requirements, level: :full, rpc: rpc)

      assert_received {:rpc, "eth_call", [%{"data" => "0x70a08231" <> _b} | _block1]}
      assert_received {:rpc, "eth_call", [%{"data" => "0x1626ba7e" <> _i} | _block2]}
      assert_received {:rpc, "eth_call", [%{"data" => "0xcf092995" <> _t} | _block3]}

      for {signature, selector} <- [
            {"balanceOf(address)", "70a08231"},
            {"isValidSignature(bytes32,bytes)", "1626ba7e"},
            {"authorizationState(address,bytes32)", "e94a0102"},
            {"transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
             "e3ee160e"},
            {"transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)",
             "cf092995"},
            {"name()", "06fdde03"},
            {"version()", "54fd4d50"},
            {"aggregate3((address,bool,bytes)[])", "82ad56cb"}
          ] do
        <<computed::binary-size(4), _rest::binary>> = ExKeccak.hash_256(signature)

        assert Base.encode16(computed, case: :lower) == selector,
               "selector drift for #{signature}"
      end
    end
  end

  describe "reason_string/1" do
    test "maps canonical reasons and falls back to the atom name" do
      assert EVM.reason_string(:valid_before_expired) ==
               "invalid_exact_evm_payload_authorization_valid_before"

      assert EVM.reason_string(:asset_not_deployed_contract) == "asset_not_deployed_contract"
      assert EVM.reason_string(:smart_wallet_requires_rpc) == "invalid_exact_evm_signature"
      assert EVM.reason_string(:invalid_authorization) == "invalid_authorization"
    end
  end
end
