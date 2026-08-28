defmodule X402.Facilitator.SVMEngineTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias X402.Base58
  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator.PendingSettlementStore
  alias X402.Facilitator.SVMEngine
  alias X402.Scheme.ExactSVM
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey
  alias X402.Solana.Transaction

  import X402.TestHelpers

  # Golden fixture keys shared with test/x402/scheme/exact_svm_test.exs:
  # the engine's signer is the fee payer (seed 0x02*32), so client-signed
  # ExactSVM payloads feed it directly.
  @client_seed :binary.copy(<<1>>, 32)
  @client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @fee_payer_seed :binary.copy(<<2>>, 32)
  @fee_payer "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
  @pay_to "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse"
  @usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
  @memo "pi_3abc123def456"
  @network "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

  defmodule FailingPendingStore do
    @behaviour X402.Facilitator.PendingSettlementStore

    @impl true
    def get(_store, _key), do: :miss

    @impl true
    def put(_store, _key, _entry), do: {:error, :boom}

    @impl true
    def delete(_store, _key), do: :ok
  end

  defmodule HaltHooks do
    @behaviour X402.Hooks

    @impl true
    def before_verify(_context, _metadata), do: {:halt, "blocked_by_policy"}

    @impl true
    def after_verify(context, _metadata), do: {:cont, context}

    @impl true
    def on_verify_failure(context, _metadata), do: {:cont, context}

    @impl true
    def before_settle(_context, _metadata), do: {:halt, "blocked_by_policy"}

    @impl true
    def after_settle(context, _metadata), do: {:cont, context}

    @impl true
    def on_settle_failure(context, _metadata), do: {:cont, context}
  end

  setup [:setup_bypass, :setup_finch]

  # -- Fixtures ---------------------------------------------------------------

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

  defp signed_payload(requirements) do
    {:ok, client_signer} = SolanaKey.new(@client_seed)
    {:ok, scheme_payload} = ExactSVM.sign(requirements, client_signer, [])
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp engine(context, overrides \\ []) do
    rpc =
      X402.TestSolanaRPCStub.stub_rpc(
        context.bypass,
        context.finch,
        Keyword.get(overrides, :stub, %{})
      )

    {:ok, signer} = SolanaKey.new(@fee_payer_seed)

    {:ok, engine} =
      SVMEngine.new(
        Keyword.merge(
          [
            rpc: rpc,
            signer: signer,
            networks: [@network],
            confirm_timeout_ms: 500,
            confirm_interval_ms: 10
          ],
          Keyword.delete(overrides, :stub)
        )
      )

    engine
  end

  defp settlement_cache do
    name = :"svm_settlement_cache_#{System.unique_integer([:positive])}"
    start_supervised!({ETSCache, name: name, ttl_ms: 120_000})
    {ETSCache, name}
  end

  defp pending_store do
    name = :"svm_pending_store_#{System.unique_integer([:positive])}"
    start_supervised!({PendingSettlementStore.ETS, name: name})
    {PendingSettlementStore.ETS, name}
  end

  # The engine's settlement key: SHA-256 of the message bytes.
  defp transaction_key(payload) do
    {:ok, decoded} = payload["payload"]["transaction"] |> Base.decode64!() |> Transaction.decode()
    Base.encode16(:crypto.hash(:sha256, decoded.message_bytes), case: :lower)
  end

  defp fee_payer_public do
    {public, _private} = :crypto.generate_key(:eddsa, :ed25519, @fee_payer_seed)
    public
  end

  # -- new/1 ------------------------------------------------------------------

  describe "new/1" do
    test "builds a validated engine", context do
      engine = engine(context)

      assert engine.simulate
      assert engine.simulate_in_settle
      assert engine.settlement_cache == nil
      assert engine.pending_settlement_store == nil
      assert engine.confirm_timeout_ms == 500
    end

    test "rejects non-Solana networks", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      {:ok, signer} = SolanaKey.new(@fee_payer_seed)

      assert {:error, %NimbleOptions.ValidationError{}} =
               SVMEngine.new(rpc: rpc, signer: signer, networks: ["eip155:84532"])

      assert {:error, %NimbleOptions.ValidationError{}} =
               SVMEngine.new(rpc: rpc, signer: signer, networks: [])
    end

    test "rejects signers without sign_ed25519/2", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      {:ok, evm_signer} = LocalKey.new("0x" <> String.duplicate("11", 32))

      assert {:error, %NimbleOptions.ValidationError{}} =
               SVMEngine.new(rpc: rpc, signer: evm_signer, networks: [@network])
    end

    test "rejects invalid settlement cache and pending store adapters", context do
      rpc = X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch)
      {:ok, signer} = SolanaKey.new(@fee_payer_seed)
      base = [rpc: rpc, signer: signer, networks: [@network]]

      assert {:error, %NimbleOptions.ValidationError{}} =
               SVMEngine.new(base ++ [settlement_cache: :nope])

      assert {:error, %NimbleOptions.ValidationError{}} =
               SVMEngine.new(base ++ [pending_settlement_store: {NotAStore, :nope}])
    end
  end

  # -- supported/1 ------------------------------------------------------------

  describe "supported/1" do
    test "lists one exact kind per network with the fee payer in extra", context do
      engine = engine(context)

      # Reference resource servers discover the fee payer to advertise in
      # their 402 challenges from each kind's extra.feePayer (the reference
      # facilitator's getExtra); "signers" alone is never consulted for it.
      assert SVMEngine.supported(engine) == %{
               "kinds" => [
                 %{
                   "x402Version" => 2,
                   "scheme" => "exact",
                   "network" => @network,
                   "extra" => %{"feePayer" => @fee_payer}
                 }
               ],
               "extensions" => [],
               "signers" => %{"solana:*" => [@fee_payer]}
             }
    end
  end

  # -- verify/3 ---------------------------------------------------------------

  describe "verify/3" do
    test "accepts a valid payment and simulates it", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert SVMEngine.verify(engine, payload, requirements) ==
               {:ok, %{"isValid" => true, "payer" => @client}}

      assert_received {:solana_rpc, "simulateTransaction", _params}
    end

    test "skips simulation when disabled", context do
      engine = engine(context, simulate: false)
      requirements = requirements()

      assert {:ok, %{"isValid" => true}} =
               SVMEngine.verify(engine, signed_payload(requirements), requirements)

      refute_received {:solana_rpc, "simulateTransaction", _params}
    end

    test "routes version, scheme, and network", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert SVMEngine.verify(engine, Map.put(payload, "x402Version", 1), requirements) ==
               {:ok,
                %{
                  "isValid" => false,
                  "invalidReason" => "invalid_x402_version",
                  "payer" => @client
                }}

      assert {:ok, %{"invalidReason" => "unsupported_scheme"}} =
               SVMEngine.verify(engine, payload, Map.put(requirements, "scheme", "upto"))

      other_network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

      assert {:ok, %{"invalidReason" => "invalid_network"}} =
               SVMEngine.verify(engine, payload, Map.put(requirements, "network", other_network))
    end

    test "rejects payments with canonical reason strings", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert SVMEngine.verify(engine, payload, Map.put(requirements, "amount", "2000")) ==
               {:ok,
                %{
                  "isValid" => false,
                  "invalidReason" => "invalid_exact_svm_payload_amount_mismatch",
                  "payer" => @client
                }}

      unmanaged = put_in(requirements["extra"]["feePayer"], @pay_to)
      unmanaged_payload = signed_payload(unmanaged)

      assert {:ok,
              %{
                "isValid" => false,
                "invalidReason" => "invalid_exact_svm_fee_payer_not_managed_by_facilitator"
              }} = SVMEngine.verify(engine, unmanaged_payload, unmanaged)
    end

    test "rejects a tampered client signature", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      wire = Base.decode64!(payload["payload"]["transaction"])
      <<prefix::binary-size(70), byte, rest::binary>> = wire
      tampered_wire = <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>
      tampered = put_in(payload["payload"], %{"transaction" => Base.encode64(tampered_wire)})

      assert {:ok,
              %{
                "isValid" => false,
                "invalidReason" => "invalid_exact_svm_payload_signature_invalid"
              }} = SVMEngine.verify(engine, tampered, requirements)
    end

    test "enforces max_required_signatures", context do
      engine = engine(context, max_required_signatures: 1)
      requirements = requirements()

      assert {:ok,
              %{
                "isValid" => false,
                "invalidReason" => "invalid_exact_svm_payload_excessive_signers"
              }} = SVMEngine.verify(engine, signed_payload(requirements), requirements)
    end

    test "node-level simulation rejection is a verdict, not an infrastructure error", context do
      # The node evaluated the request and rejected the transaction (a
      # JSON-RPC error, e.g. unsanitizable input): a 200 rejection, not an
      # opaque 500.
      engine =
        engine(context,
          stub: %{
            simulate:
              {:error,
               %{"code" => -32_602, "message" => "invalid transaction: could not be sanitized"}}
          }
        )

      requirements = requirements()

      assert SVMEngine.verify(engine, signed_payload(requirements), requirements) ==
               {:ok,
                %{
                  "isValid" => false,
                  "invalidReason" => "invalid_exact_svm_transaction_simulation_failed",
                  "payer" => @client
                }}
    end

    test "returns infrastructure errors when the node is unreachable", context do
      engine = engine(context)
      Bypass.down(context.bypass)
      requirements = requirements()

      assert {:error, {:rpc_error, _reason}} =
               SVMEngine.verify(engine, signed_payload(requirements), requirements)
    end

    test "before_verify halts turn into rejected responses", context do
      engine = engine(context, hooks: HaltHooks)
      requirements = requirements()

      assert {:ok, %{"isValid" => false, "invalidReason" => "blocked_by_policy"}} =
               SVMEngine.verify(engine, signed_payload(requirements), requirements)
    end
  end

  # -- settle/3 ---------------------------------------------------------------

  describe "settle/3" do
    test "co-signs the fee payer slot and broadcasts the wire", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      {:ok, original} =
        payload["payload"]["transaction"] |> Base.decode64!() |> Transaction.decode()

      assert {:ok, response} = SVMEngine.settle(engine, payload, requirements)

      assert_received {:solana_rpc, "sendTransaction", [broadcast_base64, config]}
      assert config["skipPreflight"] == true
      assert config["encoding"] == "base64"

      # The broadcast wire is the client's transaction with slot 0 filled:
      # same message bytes, client signature preserved, fee-payer signature
      # verifying over the message bytes.
      {:ok, broadcast} = broadcast_base64 |> Base.decode64!() |> Transaction.decode()
      assert broadcast.message_bytes == original.message_bytes
      assert Enum.at(broadcast.signatures, 1) == Enum.at(original.signatures, 1)

      [fee_payer_signature, _client_signature] = broadcast.signatures

      assert :crypto.verify(
               :eddsa,
               :none,
               broadcast.message_bytes,
               fee_payer_signature,
               [fee_payer_public(), :ed25519]
             )

      # The transaction id is the Base58 slot-0 signature.
      assert response == %{
               "success" => true,
               "transaction" => Base58.encode(fee_payer_signature),
               "network" => @network,
               "payer" => @client
             }

      assert_received {:solana_rpc, "getSignatureStatuses", _params}
    end

    test "re-simulates by default, matching the reference facilitators", context do
      engine = engine(context)
      requirements = requirements()

      assert {:ok, %{"success" => true}} =
               SVMEngine.settle(engine, signed_payload(requirements), requirements)

      assert_received {:solana_rpc, "simulateTransaction", _params}
    end

    test "simulate_in_settle: false skips the settle-time simulation", context do
      engine = engine(context, simulate_in_settle: false)
      requirements = requirements()

      assert {:ok, %{"success" => true}} =
               SVMEngine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:solana_rpc, "simulateTransaction", _params}
    end

    test "a failing settle-time simulation broadcasts nothing", context do
      engine =
        engine(context,
          stub: %{simulate: {:ok, %{"InstructionError" => [2, %{"Custom" => 1}]}}}
        )

      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_svm_transaction_simulation_failed",
                "transaction" => ""
              }} = SVMEngine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:solana_rpc, "sendTransaction", _params}
    end

    test "rejected re-verification broadcasts nothing", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = Map.put(requirements, "amount", "2000")

      assert SVMEngine.settle(engine, payload, tampered) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "invalid_exact_svm_payload_amount_mismatch",
                  "transaction" => "",
                  "network" => @network,
                  "payer" => @client
                }}

      refute_received {:solana_rpc, "sendTransaction", _params}
    end

    test "routes before settling", context do
      engine = engine(context)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{"success" => false, "errorReason" => "invalid_x402_version"}} =
               SVMEngine.settle(engine, Map.put(payload, "x402Version", 1), requirements)

      refute_received {:solana_rpc, "sendTransaction", _params}
    end

    test "rejects duplicate settlements and keeps the claim on success", context do
      cache = settlement_cache()
      engine = engine(context, settlement_cache: cache)
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok, %{"success" => true}} = SVMEngine.settle(engine, payload, requirements)
      assert_received {:solana_rpc, "sendTransaction", _params}

      assert SVMEngine.settle(engine, payload, requirements) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "duplicate_settlement",
                  "transaction" => "",
                  "network" => @network,
                  "payer" => @client
                }}

      refute_received {:solana_rpc, "sendTransaction", _params}
    end

    test "releases the claim on verify failure", context do
      cache = settlement_cache()
      engine = engine(context, settlement_cache: cache)
      requirements = requirements()
      payload = signed_payload(requirements)
      txkey = transaction_key(payload)

      assert {:ok, %{"success" => false}} =
               SVMEngine.settle(engine, payload, Map.put(requirements, "amount", "2000"))

      assert Cache.get(cache, "svm:" <> txkey) == :miss

      # The corrected retry is not duplicate-blocked.
      assert {:ok, %{"success" => true}} = SVMEngine.settle(engine, payload, requirements)
    end

    test "node-side broadcast rejection releases the claim", context do
      cache = settlement_cache()

      engine =
        engine(context,
          settlement_cache: cache,
          stub: %{send: {:error, %{"code" => -32_002, "message" => "Blockhash not found"}}}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert SVMEngine.settle(engine, payload, requirements) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "unexpected_settle_error",
                  "transaction" => "",
                  "network" => @network,
                  "payer" => @client
                }}

      assert Cache.get(cache, "svm:" <> transaction_key(payload)) == :miss
    end

    test "on-chain failure is terminal, includes the signature, and releases the claim",
         context do
      cache = settlement_cache()

      failed_status = [
        %{"confirmationStatus" => "confirmed", "err" => %{"InstructionError" => [2, 1]}}
      ]

      confirmed_status = [%{"confirmationStatus" => "confirmed", "err" => nil}]

      engine =
        engine(context,
          settlement_cache: cache,
          stub: %{statuses: [failed_status, confirmed_status]}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_svm_transaction_failed",
                "transaction" => transaction,
                "payer" => @client
              }} = SVMEngine.settle(engine, payload, requirements)

      assert transaction != ""

      # The claim was released, so a retry is NOT duplicate-blocked: it
      # broadcasts again and confirms against the second scripted status.
      assert {:ok, %{"success" => true}} = SVMEngine.settle(engine, payload, requirements)
    end

    test "an err at processed commitment keeps polling until confirmed", context do
      # A "processed"-level err can sit on a minority fork that is later
      # discarded; the reference only trusts an err at confirmed/finalized.
      processed_err = [
        %{"confirmationStatus" => "processed", "err" => %{"InstructionError" => [2, 1]}}
      ]

      confirmed_err = [
        %{"confirmationStatus" => "confirmed", "err" => %{"InstructionError" => [2, 1]}}
      ]

      engine = engine(context, stub: %{statuses: [processed_err, confirmed_err]})
      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "invalid_exact_svm_transaction_failed",
                "transaction" => transaction
              }} = SVMEngine.settle(engine, payload, requirements)

      assert transaction != ""

      # Both scripted statuses were consumed: the processed-level err alone
      # did not terminate the poll.
      assert_received {:solana_rpc, "getSignatureStatuses", _first_poll}
      assert_received {:solana_rpc, "getSignatureStatuses", _second_poll}
    end

    test "an err seen only at processed commitment times out as settlement_pending", context do
      processed_err = [
        %{"confirmationStatus" => "processed", "err" => %{"InstructionError" => [2, 1]}}
      ]

      engine =
        engine(context,
          confirm_timeout_ms: 50,
          confirm_interval_ms: 10,
          # After the processed+err answer the exhausted queue answers [nil]
          # forever: never confirmed.
          stub: %{statuses: [processed_err]}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => transaction
              }} = SVMEngine.settle(engine, payload, requirements)

      assert transaction != ""
    end

    test "without a pending store, settlement_pending releases the claim so a retry re-broadcasts",
         context do
      cache = settlement_cache()

      engine =
        engine(context,
          settlement_cache: cache,
          confirm_timeout_ms: 50,
          confirm_interval_ms: 10,
          # An empty queue answers [nil] forever: never confirmed.
          stub: %{statuses: []}
        )

      requirements = requirements()
      payload = signed_payload(requirements)
      txkey = transaction_key(payload)

      assert {:ok, %{"success" => false, "errorReason" => "settlement_pending"}} =
               SVMEngine.settle(engine, payload, requirements)

      assert_received {:solana_rpc, "sendTransaction", _first_broadcast}

      # Nothing was recorded, so a retry has nothing to reconcile against:
      # the claim must be released so the retry can re-broadcast the
      # identical wire bytes (the network collapses them to one transaction
      # id) instead of dead-ending on duplicate_settlement.
      assert Cache.get(cache, "svm:" <> txkey) == :miss

      assert {:ok, %{"success" => false, "errorReason" => "settlement_pending"}} =
               SVMEngine.settle(engine, payload, requirements)

      assert_received {:solana_rpc, "sendTransaction", _second_broadcast}
    end

    test "confirmation timeout records the pending settlement", context do
      cache = settlement_cache()
      store = pending_store()

      engine =
        engine(context,
          settlement_cache: cache,
          pending_settlement_store: store,
          confirm_timeout_ms: 50,
          confirm_interval_ms: 10,
          # An empty queue answers [nil] forever: never confirmed.
          stub: %{statuses: []}
        )

      requirements = requirements()
      payload = signed_payload(requirements)
      txkey = transaction_key(payload)

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "settlement_pending",
                "transaction" => signature
              }} = SVMEngine.settle(engine, payload, requirements)

      assert {:hit,
              %{transaction: ^signature, provenance: :node_acknowledged, raw_transaction: nil}} =
               PendingSettlementStore.get(store, txkey)

      # The claim is kept while the broadcast may still land.
      assert {:hit, :verified} = Cache.get(cache, "svm:" <> txkey)
    end

    test "pending fast path reconciles without a second broadcast", context do
      store = pending_store()

      engine =
        engine(context,
          settlement_cache: settlement_cache(),
          pending_settlement_store: store
        )

      requirements = requirements()
      payload = signed_payload(requirements)
      txkey = transaction_key(payload)
      signature = Base58.encode(:binary.copy(<<9>>, 64))

      :ok =
        PendingSettlementStore.put(store, txkey, %{
          transaction: signature,
          provenance: :node_acknowledged,
          raw_transaction: nil
        })

      assert SVMEngine.settle(engine, payload, requirements) ==
               {:ok,
                %{
                  "success" => true,
                  "transaction" => signature,
                  "network" => @network,
                  "payer" => @client
                }}

      refute_received {:solana_rpc, "sendTransaction", _params}
      assert_received {:solana_rpc, "getSignatureStatuses", [[^signature]]}

      # Delete-before-reconcile: the entry is consumed.
      assert PendingSettlementStore.get(store, txkey) == :miss
    end

    test "ambiguous transport failure records the locally computed signature", context do
      cache = settlement_cache()
      store = pending_store()

      engine =
        engine(context,
          settlement_cache: cache,
          pending_settlement_store: store,
          stub: %{send: :http_error}
        )

      requirements = requirements()
      payload = signed_payload(requirements)
      txkey = transaction_key(payload)

      {:ok, decoded} =
        payload["payload"]["transaction"] |> Base.decode64!() |> Transaction.decode()

      # Ed25519 is deterministic: the slot-0 signature — and therefore the
      # transaction id — is known before the node answers.
      expected_signature =
        :crypto.sign(:eddsa, :none, decoded.message_bytes, [@fee_payer_seed, :ed25519])
        |> Base58.encode()

      assert SVMEngine.settle(engine, payload, requirements) ==
               {:ok,
                %{
                  "success" => false,
                  "errorReason" => "settlement_pending",
                  "transaction" => expected_signature,
                  "network" => @network,
                  "payer" => @client
                }}

      assert {:hit,
              %{
                transaction: ^expected_signature,
                provenance: :local_hash,
                raw_transaction: raw
              }} = PendingSettlementStore.get(store, txkey)

      # The recorded wire is the fully signed transaction.
      assert {:ok, recorded} = Transaction.decode(raw)
      assert Base58.encode(hd(recorded.signatures)) == expected_signature

      # Ambiguous broadcast: the claim is kept.
      assert {:hit, :verified} = Cache.get(cache, "svm:" <> txkey)
    end

    test "a failing pending store downgrades settlement_pending to terminal", context do
      engine =
        engine(context,
          pending_settlement_store: {FailingPendingStore, :whatever},
          confirm_timeout_ms: 50,
          confirm_interval_ms: 10,
          stub: %{statuses: []}
        )

      requirements = requirements()
      payload = signed_payload(requirements)

      log =
        capture_log(fn ->
          assert {:ok,
                  %{
                    "success" => false,
                    "errorReason" => "invalid_exact_svm_transaction_failed",
                    "transaction" => transaction
                  }} = SVMEngine.settle(engine, payload, requirements)

          assert transaction != ""
        end)

      assert log =~ "failed to persist for retry"
    end

    test "before_settle halts turn into failure responses", context do
      engine = engine(context, hooks: HaltHooks)
      requirements = requirements()

      assert {:ok,
              %{
                "success" => false,
                "errorReason" => "blocked_by_policy",
                "transaction" => ""
              }} = SVMEngine.settle(engine, signed_payload(requirements), requirements)

      refute_received {:solana_rpc, "sendTransaction", _params}
    end
  end
end
