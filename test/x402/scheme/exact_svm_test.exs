defmodule X402.Scheme.ExactSVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.ExactSVM

  alias X402.Base58
  alias X402.Client
  alias X402.PaymentSignature
  alias X402.Scheme.ExactSVM
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey
  alias X402.Solana
  alias X402.Solana.Transaction

  # ---------------------------------------------------------------------------
  # Reference fixture, generated with the official Solana TypeScript stack
  # (@solana/kit 8.0.0 + @solana-program/token{,-2022} + compute-budget),
  # mirroring typescript/packages/mechanisms/svm/src/exact/client/scheme.ts
  # from the x402 monorepo verbatim: v0 message, instructions
  # [SetComputeUnitLimit(20_000), SetComputeUnitPrice(1), TransferChecked,
  # Memo], partiallySignTransactionMessageWithSigners, base64 wire encoding.
  #
  # Keys: client seed 0x01*32, fee payer seed 0x02*32, payTo seed 0x03*32.
  # ---------------------------------------------------------------------------
  @client_seed :binary.copy(<<1>>, 32)
  @client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @fee_payer "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
  @pay_to "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse"
  @usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
  @memo "pi_3abc123def456"

  @reference_transaction "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" <>
                           "AAAAAAAAAAAAAAAAAAAW+SpluuKWpSopmb3NGvPXNIz0wyrIAv52H2hmLkoT6zq52KCy" <>
                           "kTjqwZBGQn5/l7gycYMEih9thyEI+tOww8EGgAIBBAiBOXcOqH0XX1ajVGbDTH7My42K" <>
                           "kbTuN6Jd9g9bj8mzlIqI4910CfGV/VLbLTy6XXLKZwm/HZQSG/N0iAG0D29cK8kCOGhp" <>
                           "AsJh82TGFPHsq0/z4F9YGhwIBT/HU9NN52y3u4T1/jPeFaQeWwjr0hpa8fhuRvZTRT6H" <>
                           "DzBHpR7Q4AMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAxvp6877brTo9ZfNq" <>
                           "q8l0MbG75MLS9uDkfKYCA0UvXWEFSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVE" <>
                           "jQbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpyV29u5s5tb9yxXaxLxIjPB/v" <>
                           "cv+BhIj3ODTS8YLYlusEBAAFAiBOAAAEAAkDAQAAAAAAAAAHBAIFAwEKDOgDAAAAAAAA" <>
                           "BgYAEHBpXzNhYmMxMjNkZWY0NTYA"

  defp signer do
    {:ok, signer} = SolanaKey.new(@client_seed)
    signer
  end

  defp requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
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

    {%{
       "x402Version" => 2,
       "accepted" => reqs,
       "payload" => scheme_payload
     }, reqs}
  end

  describe "sign/3 against the TypeScript reference fixture" do
    test "produces a byte-identical partially signed transaction" do
      assert ExactSVM.sign(requirements(), signer(), []) ==
               {:ok, %{"transaction" => @reference_transaction}}
    end

    test "decoding the produced bytes re-asserts every field" do
      {:ok, %{"transaction" => encoded}} = ExactSVM.sign(requirements(), signer(), [])
      {:ok, decoded} = encoded |> Base.decode64!() |> Transaction.decode()

      assert decoded.version == 0
      assert decoded.num_required_signatures == 2
      assert decoded.num_readonly_signed == 1
      assert decoded.num_readonly_unsigned == 4
      assert decoded.address_table_lookups == 0

      # Account 0 is the sponsor's fee payer; its signature slot is the
      # 64-byte zero placeholder (partially signed transaction).
      {:ok, fee_payer_pubkey} = Solana.decode_address(@fee_payer)
      assert hd(decoded.static_accounts) == fee_payer_pubkey
      assert [<<0::512>>, client_signature] = decoded.signatures

      # The client's Ed25519 signature covers the message bytes and
      # verifies against the client public key.
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, @client_seed)

      assert :crypto.verify(
               :eddsa,
               :none,
               decoded.message_bytes,
               client_signature,
               [public, :ed25519]
             )

      {:ok, blockhash} = Solana.decode_address(@blockhash)
      assert decoded.recent_blockhash == blockhash

      # Reference instruction set, in order.
      assert [limit_ix, price_ix, transfer_ix, memo_ix] = decoded.instructions
      assert limit_ix.data == <<2, 20_000::32-little>>
      assert price_ix.data == <<3, 1::64-little>>
      assert transfer_ix.data == <<12, 1000::64-little, 6>>
      assert memo_ix.data == @memo

      # TransferChecked destination is the ATA derived from payTo + asset.
      {:ok, dest_ata} = Solana.associated_token_address(@pay_to, @usdc)
      {:ok, dest_pubkey} = Solana.decode_address(dest_ata)
      destination_index = Enum.at(transfer_ix.account_indices, 2)
      assert Enum.at(decoded.static_accounts, destination_index) == dest_pubkey

      # The transfer authority is the client, not the fee payer.
      {:ok, client_pubkey} = Solana.decode_address(@client)
      authority_index = Enum.at(transfer_ix.account_indices, 3)
      assert Enum.at(decoded.static_accounts, authority_index) == client_pubkey
    end

    test "generates a random hex nonce memo when extra.memo is absent" do
      reqs =
        requirements(%{
          "extra" => %{"feePayer" => @fee_payer, "recentBlockhash" => @blockhash}
        })

      {:ok, %{"transaction" => encoded}} = ExactSVM.sign(reqs, signer(), [])
      {:ok, decoded} = encoded |> Base.decode64!() |> Transaction.decode()

      memo_ix = List.last(decoded.instructions)
      assert byte_size(memo_ix.data) == 32
      assert memo_ix.data =~ ~r/^[0-9a-f]{32}$/

      # Nonces differ between builds (transaction uniqueness).
      {:ok, %{"transaction" => second}} = ExactSVM.sign(reqs, signer(), [])
      assert second != encoded
    end
  end

  describe "sign/3 option handling" do
    test "requires extra.feePayer" do
      assert ExactSVM.sign(requirements(%{"extra" => %{}}), signer(), []) ==
               {:error, :missing_fee_payer}

      assert ExactSVM.sign(
               requirements(%{"extra" => %{"feePayer" => "not-an-address"}}),
               signer(),
               []
             ) == {:error, :missing_fee_payer}
    end

    test "blockhash: server hint wins, then :svm_blockhash, then the fetcher" do
      no_hint = requirements(%{"extra" => %{"feePayer" => @fee_payer, "memo" => @memo}})

      # Server hint produces the reference transaction even when an option
      # is also given.
      assert ExactSVM.sign(requirements(), signer(), svm_blockhash: other_blockhash()) ==
               {:ok, %{"transaction" => @reference_transaction}}

      # Without the hint the option is used.
      assert ExactSVM.sign(no_hint, signer(), svm_blockhash: @blockhash) ==
               {:ok, %{"transaction" => @reference_transaction}}

      # Then the fetcher.
      parent = self()

      fetcher = fn network ->
        send(parent, {:fetched, network})
        {:ok, @blockhash}
      end

      assert ExactSVM.sign(no_hint, signer(), svm_blockhash_fetcher: fetcher) ==
               {:ok, %{"transaction" => @reference_transaction}}

      assert_received {:fetched, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}

      # A malformed hint falls through to the option (spec: "when absent or
      # malformed, the client MUST fetch a recent blockhash itself").
      bad_hint =
        requirements(%{
          "extra" => %{
            "feePayer" => @fee_payer,
            "memo" => @memo,
            "recentBlockhash" => "bogus"
          }
        })

      assert ExactSVM.sign(bad_hint, signer(), svm_blockhash: @blockhash) ==
               {:ok, %{"transaction" => @reference_transaction}}

      # With no source at all, a structured error.
      assert ExactSVM.sign(no_hint, signer(), []) == {:error, :missing_blockhash}
    end

    test "fetcher failures surface as blockhash_fetch_failed" do
      no_hint = requirements(%{"extra" => %{"feePayer" => @fee_payer}})

      assert ExactSVM.sign(no_hint, signer(), svm_blockhash_fetcher: fn _n -> {:error, :down} end) ==
               {:error, {:blockhash_fetch_failed, :down}}

      assert ExactSVM.sign(no_hint, signer(), svm_blockhash_fetcher: fn _n -> {:ok, "bogus"} end) ==
               {:error, :invalid_blockhash}
    end

    test "unknown mints need :svm_decimals (and optionally :svm_token_program)" do
      unknown_mint = Base58.encode(:crypto.strong_rand_bytes(32))
      reqs = requirements(%{"asset" => unknown_mint})

      assert ExactSVM.sign(reqs, signer(), []) == {:error, {:unknown_asset, unknown_mint}}

      assert {:ok, %{"transaction" => encoded}} =
               ExactSVM.sign(reqs, signer(),
                 svm_decimals: 9,
                 svm_token_program: Solana.token_2022_program()
               )

      {:ok, decoded} = encoded |> Base.decode64!() |> Transaction.decode()
      transfer_ix = Enum.at(decoded.instructions, 2)
      assert transfer_ix.data == <<12, 1000::64-little, 9>>

      {:ok, token_2022} = Solana.decode_address(Solana.token_2022_program())
      assert Enum.at(decoded.static_accounts, transfer_ix.program_index) == token_2022
    end

    test "rejects an over-long seller memo" do
      long_memo = String.duplicate("a", 257)
      reqs = put_in(requirements()["extra"]["memo"], long_memo)

      assert ExactSVM.sign(reqs, signer(), []) == {:error, :memo_too_long}
    end

    test "rejects signers without a Solana address or Ed25519 support" do
      {:ok, evm_signer} = LocalKey.new("0x" <> String.duplicate("11", 32))
      assert ExactSVM.sign(requirements(), evm_signer, []) == {:error, :invalid_payer_address}
    end

    test "rejects invalid amounts" do
      assert ExactSVM.sign(requirements(%{"amount" => "1.5"}), signer(), []) ==
               {:error, :invalid_amount}

      assert ExactSVM.sign(requirements(%{"amount" => "-3"}), signer(), []) ==
               {:error, :invalid_amount}

      assert ExactSVM.sign(requirements(%{"amount" => nil}), signer(), []) ==
               {:error, :invalid_amount}
    end

    test "rejects invalid asset and payTo addresses" do
      evm_address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

      assert ExactSVM.sign(requirements(%{"asset" => evm_address}), signer(), []) ==
               {:error, :invalid_asset}

      assert ExactSVM.sign(requirements(%{"payTo" => evm_address}), signer(), []) ==
               {:error, :invalid_pay_to}
    end

    test "rejects a malformed :svm_blockhash option" do
      no_hint = requirements(%{"extra" => %{"feePayer" => @fee_payer}})

      assert ExactSVM.sign(no_hint, signer(), svm_blockhash: "bogus") ==
               {:error, :invalid_blockhash}
    end

    test "wraps a fetcher returning a bare value" do
      no_hint = requirements(%{"extra" => %{"feePayer" => @fee_payer}})

      assert ExactSVM.sign(no_hint, signer(), svm_blockhash_fetcher: fn _network -> :whoops end) ==
               {:error, {:blockhash_fetch_failed, :whoops}}
    end

    test "known assets keep their table metadata under partial overrides" do
      # Explicit token program with table decimals.
      assert ExactSVM.sign(requirements(), signer(), svm_token_program: Solana.token_program()) ==
               {:ok, %{"transaction" => @reference_transaction}}

      # Explicit decimals with the table's token program.
      assert ExactSVM.sign(requirements(), signer(), svm_decimals: 6) ==
               {:ok, %{"transaction" => @reference_transaction}}
    end

    test "signable? requires a requirements map" do
      refute ExactSVM.signable?(nil)
    end
  end

  describe "validate_payload/3" do
    test "accepts a well-formed payload" do
      {payload, reqs} = signed_payload()
      assert ExactSVM.validate_payload(payload, reqs, []) == :ok
    end

    test "rejects structural failures" do
      {payload, reqs} = signed_payload()

      assert ExactSVM.validate_payload(%{"payload" => %{}}, reqs, []) ==
               {:error, {:invalid_scheme_payment, :missing_transaction}}

      assert ExactSVM.validate_payload(
               put_in(payload["payload"], %{"transaction" => "!"}),
               reqs,
               []
             ) ==
               {:error, {:invalid_scheme_payment, :invalid_base64}}

      oversized = Base.encode64(:binary.copy(<<0>>, 1233))

      assert ExactSVM.validate_payload(
               put_in(payload["payload"], %{"transaction" => oversized}),
               reqs,
               []
             ) == {:error, {:invalid_scheme_payment, :transaction_too_large}}

      garbage = Base.encode64(:crypto.strong_rand_bytes(100))

      assert ExactSVM.validate_payload(
               put_in(payload["payload"], %{"transaction" => garbage}),
               reqs,
               []
             ) == {:error, {:invalid_scheme_payment, :invalid_transaction}}
    end

    test "rejects a fee payer differing from the advertised one" do
      {payload, reqs} = signed_payload()
      other_reqs = put_in(reqs["extra"]["feePayer"], @pay_to)

      assert ExactSVM.validate_payload(payload, other_reqs, []) ==
               {:error, {:invalid_scheme_payment, :fee_payer_mismatch}}
    end

    test "skips the fee payer check when the requirements do not advertise one" do
      {payload, reqs} = signed_payload()
      assert ExactSVM.validate_payload(payload, Map.put(reqs, "extra", %{}), []) == :ok
    end

    test "treats a non-map scheme payload as a missing transaction" do
      {_payload, reqs} = signed_payload()

      assert ExactSVM.validate_payload(%{"payload" => "nope"}, reqs, []) ==
               {:error, {:invalid_scheme_payment, :missing_transaction}}

      assert ExactSVM.validate_payload(%{}, reqs, []) ==
               {:error, {:invalid_scheme_payment, :missing_transaction}}
    end
  end

  describe "precheck/3" do
    test "accepts the reference transaction" do
      {payload, reqs} = signed_payload()
      assert ExactSVM.precheck(payload, reqs, []) == :ok
    end

    test "rejects certain semantic mismatches on the positional transfer" do
      {payload, reqs} = signed_payload()

      assert ExactSVM.precheck(payload, Map.put(reqs, "amount", "2000"), []) ==
               {:error, {:precheck_failed, :amount_mismatch}}

      other_mint = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

      assert ExactSVM.precheck(payload, Map.put(reqs, "asset", other_mint), []) ==
               {:error, {:precheck_failed, :mint_mismatch}}

      assert ExactSVM.precheck(payload, Map.put(reqs, "payTo", @fee_payer), []) ==
               {:error, {:precheck_failed, :recipient_mismatch}}
    end

    test "enforces the seller memo" do
      {payload, reqs} = signed_payload()

      mismatched = put_in(reqs["extra"]["memo"], "different-memo")

      assert ExactSVM.precheck(payload, mismatched, []) ==
               {:error, {:precheck_failed, :memo_mismatch}}

      # A transaction without any memo instruction fails the count check.
      {:ok, compiled} =
        Transaction.compile(@fee_payer, instructions_without_memo(), @blockhash)

      no_memo_payload = wire_payload(compiled)

      assert ExactSVM.precheck(no_memo_payload, reqs, []) ==
               {:error, {:precheck_failed, :memo_count}}
    end

    test "rejects layouts outside the static-path whitelist" do
      {_payload, reqs} = signed_payload()

      # Too few instructions (spec §3.1 requires 3–7).
      {:ok, compiled} =
        Transaction.compile(
          @fee_payer,
          Enum.take(instructions_without_memo(), 2),
          @blockhash
        )

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :instruction_count}}

      # An unknown program in the optional tail.
      unknown_program = Base58.encode(:crypto.strong_rand_bytes(32))

      rogue = %{program: unknown_program, accounts: [], data: "x"}

      {:ok, compiled} =
        Transaction.compile(@fee_payer, instructions_without_memo() ++ [rogue], @blockhash)

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :unknown_optional_instruction}}

      # Compute unit price beyond the 5 lamports/CU static-path cap.
      [limit, _price, transfer] = instructions_without_memo()

      {:ok, compiled} =
        Transaction.compile(
          @fee_payer,
          [limit, Transaction.set_compute_unit_price(5_000_001), transfer],
          @blockhash
        )

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :compute_price_too_high}}

      # Swapped compute-budget instructions break the reference order.
      [limit, price, transfer] = instructions_without_memo()

      {:ok, compiled} = Transaction.compile(@fee_payer, [price, limit, transfer], @blockhash)

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :invalid_compute_limit_instruction}}
    end

    test "rejects a malformed compute price and a missing positional transfer" do
      {_payload, reqs} = signed_payload()
      [limit, price, transfer] = instructions_without_memo()

      bogus_price = %{program: Solana.compute_budget_program(), accounts: [], data: <<9, 9>>}

      {:ok, compiled} =
        Transaction.compile(@fee_payer, [limit, bogus_price, transfer], @blockhash)

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :invalid_compute_price_instruction}}

      {:ok, compiled} =
        Transaction.compile(@fee_payer, [limit, price, Transaction.memo("x")], @blockhash)

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :missing_transfer_instruction}}
    end

    test "rejects two memo instructions when the seller pinned one" do
      {_payload, reqs} = signed_payload()

      {:ok, compiled} =
        Transaction.compile(
          @fee_payer,
          instructions_without_memo() ++ [Transaction.memo(@memo), Transaction.memo("second")],
          @blockhash
        )

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :memo_count}}
    end

    test "skips semantic checks the requirements cannot back locally" do
      {payload, reqs} = signed_payload()

      uninterpretable =
        reqs
        |> Map.put("amount", "not-a-number")
        |> Map.put("asset", "0xnot-solana")
        |> Map.put("payTo", "0xnot-solana")

      assert ExactSVM.precheck(payload, uninterpretable, []) == :ok
    end

    test "rejects a fee payer referenced by an instruction (isolation, spec 2.1.1)" do
      # The fee payer as transfer authority would let the sponsor's
      # signature move the sponsor's funds.
      {:ok, source_ata} = Solana.associated_token_address(@fee_payer, @usdc)
      {:ok, dest_ata} = Solana.associated_token_address(@pay_to, @usdc)

      transfer =
        Transaction.transfer_checked(%{
          source: source_ata,
          mint: @usdc,
          destination: dest_ata,
          authority: @fee_payer,
          amount: 1000,
          decimals: 6,
          token_program: Solana.token_program()
        })

      [limit, price, _transfer] = instructions_without_memo()

      {:ok, compiled} =
        Transaction.compile(
          @fee_payer,
          [limit, price, transfer, Transaction.memo(@memo)],
          @blockhash
        )

      {_payload, reqs} = signed_payload()

      assert ExactSVM.precheck(wire_payload(compiled), reqs, []) ==
               {:error, {:precheck_failed, :fee_payer_not_isolated}}
    end

    test "passes transactions using address lookup tables through to the facilitator" do
      {payload, reqs} = signed_payload()

      wire = Base.decode64!(payload["payload"]["transaction"])
      # Rewrite the trailing ALT count (0) to 1 and append a minimal
      # lookup entry: 32-byte table address, one writable index, none
      # read-only.
      body_size = byte_size(wire) - 1
      <<body::binary-size(body_size), 0>> = wire
      with_alt = body <> <<1>> <> :binary.copy(<<7>>, 32) <> <<1, 200>> <> <<0>>

      alt_payload = put_in(payload["payload"], %{"transaction" => Base.encode64(with_alt)})

      assert ExactSVM.precheck(alt_payload, reqs, []) == :ok
    end

    test "rejects undecodable payloads" do
      {_payload, reqs} = signed_payload()

      assert ExactSVM.precheck(%{"payload" => %{"transaction" => "!"}}, reqs, []) ==
               {:error, {:precheck_failed, :invalid_transaction}}
    end
  end

  describe "client integration" do
    test "build_payment selects and signs the SVM entry among multiple accepts" do
      evm_entry = %{
        "scheme" => "exact",
        "network" => "eip155:84532",
        "amount" => "10000",
        "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "payTo" => "0x2222222222222222222222222222222222222222",
        "maxTimeoutSeconds" => 300,
        # No EIP-712 domain — not signable by ExactEVM.
        "extra" => %{}
      }

      payment_required = %{
        "x402Version" => 2,
        "resource" => %{"url" => "https://api.example.com/paid", "mimeType" => "application/json"},
        "accepts" => [evm_entry, requirements()],
        "extensions" => %{}
      }

      assert {:ok, payload} = Client.build_payment(payment_required, signer())
      assert payload["accepted"] == requirements()
      assert payload["payload"]["transaction"] == @reference_transaction

      # Round-trip through the header codec and server-side validation.
      {:ok, header} = Client.encode_payment(payload)
      {:ok, decoded} = PaymentSignature.decode(header)
      assert {:ok, ^decoded} = PaymentSignature.validate(decoded, requirements())
    end

    test "select_requirements skips SVM entries without extra.feePayer" do
      no_fee_payer = requirements(%{"extra" => %{}})

      assert Client.select_requirements(%{"accepts" => [no_fee_payer]}) ==
               {:error, :no_acceptable_requirements}

      assert Client.select_requirements(%{"accepts" => [no_fee_payer, requirements()]}) ==
               {:ok, requirements()}
    end
  end

  # -- helpers ----------------------------------------------------------------

  defp other_blockhash, do: Base58.encode(:binary.copy(<<9>>, 32))

  defp instructions_without_memo do
    {:ok, source_ata} = Solana.associated_token_address(@client, @usdc)
    {:ok, dest_ata} = Solana.associated_token_address(@pay_to, @usdc)

    [
      Transaction.set_compute_unit_limit(20_000),
      Transaction.set_compute_unit_price(1),
      Transaction.transfer_checked(%{
        source: source_ata,
        mint: @usdc,
        destination: dest_ata,
        authority: @client,
        amount: 1000,
        decimals: 6,
        token_program: Solana.token_program()
      })
    ]
  end

  defp wire_payload(compiled) do
    wire = Transaction.serialize(compiled, %{})

    %{
      "x402Version" => 2,
      "accepted" => requirements(),
      "payload" => %{"transaction" => Base.encode64(wire)}
    }
  end
end
