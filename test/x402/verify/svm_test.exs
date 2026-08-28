defmodule X402.Verify.SVMTest do
  use ExUnit.Case, async: false

  alias X402.Scheme.ExactSVM
  alias X402.Signer.SolanaKey
  alias X402.Solana.Transaction
  alias X402.Verify.SVM

  import X402.TestHelpers

  doctest X402.Verify.SVM

  # Golden fixture keys shared with test/x402/scheme/exact_svm_test.exs:
  # client seed 0x01*32, fee payer seed 0x02*32, payTo seed 0x03*32.
  @client_seed :binary.copy(<<1>>, 32)
  @client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @fee_payer "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
  @pay_to "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse"
  @usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
  @memo "pi_3abc123def456"
  @network "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

  setup :setup_bypass
  setup :setup_finch

  defp signer do
    {:ok, signer} = SolanaKey.new(@client_seed)
    signer
  end

  defp requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => "1000",
        "asset" => @usdc,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 60,
        "extra" => %{
          "feePayer" => @fee_payer,
          "memo" => @memo,
          "recentBlockhash" => @blockhash
        }
      },
      overrides
    )
  end

  defp signed_payload(overrides \\ %{}) do
    reqs = requirements(overrides)
    {:ok, scheme_payload} = ExactSVM.sign(reqs, signer(), [])
    {%{"x402Version" => 2, "accepted" => reqs, "payload" => scheme_payload}, reqs}
  end

  defp structural_opts(overrides \\ []) do
    Keyword.merge([level: :structural, fee_payer: @fee_payer], overrides)
  end

  describe "verify/3 at :structural" do
    test "accepts the reference payment and reports the transfer authority" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts()) ==
               {:ok, %{payer: @client, level: :structural}}
    end

    test "rejects non-exact schemes on either side" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, Map.put(reqs, "scheme", "upto"), structural_opts()) ==
               {:error, {:invalid, :unsupported_scheme}}

      tampered = put_in(payload["accepted"]["scheme"], "upto")

      assert SVM.verify(tampered, reqs, structural_opts()) ==
               {:error, {:invalid, :unsupported_scheme}}
    end

    test "rejects network mismatches and non-Solana networks" do
      {payload, reqs} = signed_payload()
      other = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

      assert SVM.verify(payload, Map.put(reqs, "network", other), structural_opts()) ==
               {:error, {:invalid, :network_mismatch}}

      # An agreeing non-Solana network is equally unverifiable here.
      evm_reqs = Map.put(reqs, "network", "eip155:84532")
      evm_payload = put_in(payload["accepted"]["network"], "eip155:84532")

      assert SVM.verify(evm_payload, evm_reqs, structural_opts()) ==
               {:error, {:invalid, :network_mismatch}}
    end

    test "requires a valid extra.feePayer" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, Map.put(reqs, "extra", %{}), structural_opts()) ==
               {:error, {:invalid, :missing_fee_payer}}

      invalid = put_in(reqs["extra"]["feePayer"], "not-an-address")

      assert SVM.verify(payload, invalid, structural_opts()) ==
               {:error, {:invalid, :missing_fee_payer}}
    end

    test "rejects a fee payer this facilitator does not manage" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(fee_payer: @pay_to)) ==
               {:error, {:invalid, :fee_payer_not_managed}}
    end

    test "rejects undecodable transactions" do
      {payload, reqs} = signed_payload()

      for transaction <- ["!!!", Base.encode64(:crypto.strong_rand_bytes(50))] do
        broken = put_in(payload["payload"], %{"transaction" => transaction})

        assert SVM.verify(broken, reqs, structural_opts()) ==
                 {:error, {:invalid, :transaction_could_not_be_decoded}}
      end

      assert SVM.verify(Map.delete(payload, "payload"), reqs, structural_opts()) ==
               {:error, {:invalid, :invalid_payload}}
    end

    test "rejects a transaction whose account 0 is not the advertised fee payer" do
      # Signed against a different sponsor: the requirements advertise (and
      # this facilitator manages) @fee_payer, but account 0 is @pay_to.
      {payload, _reqs} =
        signed_payload(%{
          "extra" => %{"feePayer" => @pay_to, "memo" => @memo, "recentBlockhash" => @blockhash}
        })

      assert SVM.verify(payload, requirements(), structural_opts()) ==
               {:error, {:invalid, :fee_payer_mismatch}}
    end

    test "enforces the optional required-signature cap" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(max_required_signatures: 1)) ==
               {:error, {:invalid, :excessive_signers}}

      assert {:ok, _result} =
               SVM.verify(payload, reqs, structural_opts(max_required_signatures: 2))
    end

    test "rejects a tampered client signature" do
      {payload, reqs} = signed_payload()
      wire = Base.decode64!(payload["payload"]["transaction"])

      # Wire layout: compact-u16 count (1 byte here), 64-byte fee payer
      # slot, 64-byte client slot. Flip a byte inside the client signature.
      <<prefix::binary-size(70), byte, rest::binary>> = wire
      tampered_wire = <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>

      tampered =
        put_in(payload["payload"], %{"transaction" => Base.encode64(tampered_wire)})

      assert SVM.verify(tampered, reqs, structural_opts()) ==
               {:error, {:invalid, :signature_invalid}}
    end

    test "rejects address-lookup-table transactions fail-closed" do
      {payload, reqs} = signed_payload()

      {:ok, decoded} =
        payload["payload"]["transaction"] |> Base.decode64!() |> Transaction.decode()

      # Rewrite the trailing ALT count (0) to 1, append a minimal lookup
      # entry, and RE-SIGN the mutated message so the signature check
      # (which runs first) passes and the ALT rejection itself is hit.
      message_size = byte_size(decoded.message_bytes) - 1
      <<body::binary-size(message_size), 0>> = decoded.message_bytes
      alt_message = body <> <<1>> <> :binary.copy(<<7>>, 32) <> <<1, 200>> <> <<0>>
      client_signature = :crypto.sign(:eddsa, :none, alt_message, [@client_seed, :ed25519])
      wire = <<2>> <> <<0::512>> <> client_signature <> alt_message

      alt_payload = put_in(payload["payload"], %{"transaction" => Base.encode64(wire)})

      assert SVM.verify(alt_payload, reqs, structural_opts()) ==
               {:error, {:invalid, :alt_resolution_not_available}}
    end

    test "maps static-layout precheck failures onto their reasons" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, Map.put(reqs, "amount", "2000"), structural_opts()) ==
               {:error, {:invalid, :amount_mismatch}}

      other_mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

      assert SVM.verify(payload, Map.put(reqs, "asset", other_mint), structural_opts()) ==
               {:error, {:invalid, :mint_mismatch}}

      assert SVM.verify(payload, Map.put(reqs, "payTo", @fee_payer), structural_opts()) ==
               {:error, {:invalid, :recipient_mismatch}}

      mismatched_memo = put_in(reqs["extra"]["memo"], "different-memo")

      assert SVM.verify(payload, mismatched_memo, structural_opts()) ==
               {:error, {:invalid, :memo_mismatch}}
    end

    test "fails closed on uninterpretable requirements instead of skipping checks" do
      {payload, reqs} = signed_payload()

      # ExactSVM.precheck (a gate-side pre-filter) SKIPS the amount/mint/
      # recipient comparisons when the field is unparseable, deferring to
      # the facilitator — which is this module, so it must reject instead.
      for amount <- ["10.5", "not-a-number", "-1", nil, 1.5] do
        assert SVM.verify(payload, Map.put(reqs, "amount", amount), structural_opts()) ==
                 {:error, {:invalid, :invalid_requirements_amount}},
               "amount #{inspect(amount)} must fail closed"
      end

      assert SVM.verify(payload, Map.put(reqs, "asset", "not-base58!"), structural_opts()) ==
               {:error, {:invalid, :invalid_requirements_asset}}

      assert SVM.verify(payload, Map.put(reqs, "payTo", "bogus"), structural_opts()) ==
               {:error, {:invalid, :invalid_requirements_pay_to}}
    end

    test "raises on missing required options" do
      {payload, reqs} = signed_payload()

      assert_raise NimbleOptions.ValidationError, fn ->
        SVM.verify(payload, reqs, level: :structural)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        SVM.verify(payload, reqs, fee_payer: @fee_payer)
      end
    end
  end

  describe "verify/3 at :full" do
    test "requires an RPC configuration when simulating" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(level: :full)) ==
               {:error, :rpc_not_configured}
    end

    test "passes without RPC when simulation is disabled" do
      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(level: :full, simulate: false)) ==
               {:ok, %{payer: @client, level: :full}}
    end

    test "simulates the original base64 transaction", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      {payload, reqs} = signed_payload()
      transaction = payload["payload"]["transaction"]

      assert SVM.verify(payload, reqs, structural_opts(level: :full, rpc: rpc)) ==
               {:ok, %{payer: @client, level: :full}}

      assert_received {:solana_rpc, "simulateTransaction", [^transaction, _config]}
    end

    test "rejects payments whose simulation errs", context do
      rpc =
        X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch, %{
          simulate: {:ok, %{"InstructionError" => [2, %{"Custom" => 1}]}}
        })

      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(level: :full, rpc: rpc)) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "maps a node-level simulateTransaction rejection to the simulation-failed verdict",
         context do
      # The node evaluated the request and rejected the transaction — a
      # verdict about the payment, not an infrastructure failure.
      rpc =
        X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch, %{
          simulate:
            {:error,
             %{"code" => -32_602, "message" => "invalid transaction: could not be sanitized"}}
        })

      {payload, reqs} = signed_payload()

      assert SVM.verify(payload, reqs, structural_opts(level: :full, rpc: rpc)) ==
               {:error, {:invalid, :simulation_failed}}
    end

    test "fails closed on RPC transport failures", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      Bypass.down(context.bypass)
      {payload, reqs} = signed_payload()

      assert {:error, {:rpc_error, {:transport_error, _reason}}} =
               SVM.verify(payload, reqs, structural_opts(level: :full, rpc: rpc))
    end

    test "does not simulate when a structural check already failed", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      {payload, reqs} = signed_payload()

      assert SVM.verify(
               payload,
               Map.put(reqs, "amount", "2000"),
               structural_opts(level: :full, rpc: rpc)
             ) == {:error, {:invalid, :amount_mismatch}}

      refute_received {:solana_rpc, "simulateTransaction", _params}
    end
  end

  describe "reason_string/1" do
    test "adopts the TypeScript reference vocabulary" do
      assert SVM.reason_string(:unsupported_scheme) == "invalid_exact_svm_unsupported_scheme"
      assert SVM.reason_string(:network_mismatch) == "invalid_exact_svm_network_mismatch"

      assert SVM.reason_string(:missing_fee_payer) ==
               "invalid_exact_svm_payload_missing_fee_payer"

      assert SVM.reason_string(:fee_payer_not_managed) ==
               "invalid_exact_svm_fee_payer_not_managed_by_facilitator"

      assert SVM.reason_string(:transaction_could_not_be_decoded) ==
               "invalid_exact_svm_payload_transaction_could_not_be_decoded"

      assert SVM.reason_string(:excessive_signers) ==
               "invalid_exact_svm_payload_excessive_signers"

      assert SVM.reason_string(:signature_invalid) ==
               "invalid_exact_svm_payload_signature_invalid"

      assert SVM.reason_string(:alt_resolution_not_available) ==
               "invalid_exact_svm_smart_wallet_alt_resolution_not_available"

      assert SVM.reason_string(:instruction_count) ==
               "invalid_exact_svm_payload_transaction_instructions_length"

      assert SVM.reason_string(:invalid_compute_limit_instruction) ==
               "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"

      assert SVM.reason_string(:invalid_compute_price_instruction) ==
               "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"

      assert SVM.reason_string(:compute_price_too_high) ==
               "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"

      assert SVM.reason_string(:missing_transfer_instruction) ==
               "invalid_exact_svm_payload_no_transfer_instruction"

      assert SVM.reason_string(:fee_payer_not_isolated) ==
               "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"

      assert SVM.reason_string(:recipient_mismatch) ==
               "invalid_exact_svm_payload_recipient_mismatch"

      assert SVM.reason_string(:memo_count) == "invalid_exact_svm_payload_memo_count"
      assert SVM.reason_string(:memo_mismatch) == "invalid_exact_svm_payload_memo_mismatch"

      assert SVM.reason_string(:verification_failed) == "invalid_exact_svm_verification_failed"

      # Uninterpretable-requirements rejections surface as the generic
      # verification failure on the wire.
      assert SVM.reason_string(:invalid_requirements_amount) ==
               "invalid_exact_svm_verification_failed"

      assert SVM.reason_string(:invalid_requirements_asset) ==
               "invalid_exact_svm_verification_failed"

      assert SVM.reason_string(:invalid_requirements_pay_to) ==
               "invalid_exact_svm_verification_failed"

      assert SVM.reason_string(:simulation_failed) ==
               "invalid_exact_svm_transaction_simulation_failed"
    end
  end
end
