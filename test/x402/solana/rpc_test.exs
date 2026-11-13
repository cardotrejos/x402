defmodule X402.Solana.RPCTest do
  use ExUnit.Case, async: false

  alias X402.RPC
  alias X402.Solana

  import X402.TestHelpers

  @blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
  @signature "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"

  setup :setup_bypass
  setup :setup_finch

  defp rpc(%{bypass: bypass, finch: finch}) do
    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: finch)
    rpc
  end

  defp expect_rpc(bypass, result_or_error, on_request \\ fn _request -> :ok end) do
    Bypass.expect_once(bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      on_request.(Jason.decode!(body))

      payload =
        case result_or_error do
          {:result, result} -> %{"jsonrpc" => "2.0", "id" => 1, "result" => result}
          {:error, error} -> %{"jsonrpc" => "2.0", "id" => 1, "error" => error}
        end

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(payload))
    end)
  end

  defp value_envelope(value), do: %{"context" => %{"slot" => 123}, "value" => value}

  describe "get_latest_blockhash/2" do
    test "unwraps the context/value envelope", context do
      expect_rpc(
        context.bypass,
        {:result,
         value_envelope(%{"blockhash" => @blockhash, "lastValidBlockHeight" => 350_000})},
        fn request ->
          assert %{
                   "method" => "getLatestBlockhash",
                   "params" => [%{"commitment" => "confirmed"}]
                 } = request
        end
      )

      assert Solana.RPC.get_latest_blockhash(rpc(context)) ==
               {:ok, %{blockhash: @blockhash, last_valid_block_height: 350_000}}
    end

    test "honors the :commitment option", context do
      expect_rpc(
        context.bypass,
        {:result, value_envelope(%{"blockhash" => @blockhash, "lastValidBlockHeight" => 1})},
        fn request ->
          assert %{"params" => [%{"commitment" => "finalized"}]} = request
        end
      )

      assert {:ok, _value} =
               Solana.RPC.get_latest_blockhash(rpc(context), commitment: "finalized")
    end

    test "rejects malformed values as invalid responses", context do
      expect_rpc(context.bypass, {:result, value_envelope(%{"blockhash" => @blockhash})})

      assert {:error, {:invalid_response, %{"blockhash" => @blockhash}}} =
               Solana.RPC.get_latest_blockhash(rpc(context))
    end

    test "rejects a missing envelope", context do
      expect_rpc(context.bypass, {:result, %{"blockhash" => @blockhash}})

      assert {:error, {:invalid_response, _value}} =
               Solana.RPC.get_latest_blockhash(rpc(context))
    end

    test "rejects a non-string blockhash", context do
      wrong_type = %{"blockhash" => 12_345, "lastValidBlockHeight" => 350_000}
      expect_rpc(context.bypass, {:result, value_envelope(wrong_type)})

      assert Solana.RPC.get_latest_blockhash(rpc(context)) ==
               {:error, {:invalid_response, wrong_type}}
    end

    test "rejects a negative last valid block height", context do
      negative = %{"blockhash" => @blockhash, "lastValidBlockHeight" => -1}
      expect_rpc(context.bypass, {:result, value_envelope(negative)})

      assert Solana.RPC.get_latest_blockhash(rpc(context)) ==
               {:error, {:invalid_response, negative}}
    end

    test "reads the blockhash the scripted Solana node serves", context do
      rpc =
        X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch, %{
          blockhash: @blockhash,
          last_valid_block_height: 4_242
        })

      assert Solana.RPC.get_latest_blockhash(rpc) ==
               {:ok, %{blockhash: @blockhash, last_valid_block_height: 4_242}}

      assert_received {:solana_rpc, "getLatestBlockhash", [%{"commitment" => "confirmed"}]}
    end
  end

  describe "batched Solana requests" do
    test "the scripted node answers a batch in request order", context do
      rpc =
        X402.TestSolanaRPCStub.stub_rpc(context.bypass, context.finch, %{
          blockhash: @blockhash,
          last_valid_block_height: 77
        })

      assert {:ok, [{:ok, blockhash_result}, {:ok, statuses_result}]} =
               RPC.batch(rpc, [
                 {"getLatestBlockhash", [%{"commitment" => "confirmed"}]},
                 {"getSignatureStatuses", [[@signature], %{"searchTransactionHistory" => true}]}
               ])

      assert blockhash_result["value"] == %{
               "blockhash" => @blockhash,
               "lastValidBlockHeight" => 77
             }

      assert statuses_result["value"] == [%{"confirmationStatus" => "confirmed", "err" => nil}]

      assert_received {:solana_rpc, "getLatestBlockhash", _params}
      assert_received {:solana_rpc, "getSignatureStatuses", _params}
    end
  end

  describe "simulate_transaction/3" do
    test "sends the reference simulation config and unwraps the verdict", context do
      transaction = Base.encode64("wire-bytes")

      expect_rpc(
        context.bypass,
        {:result, value_envelope(%{"err" => nil, "logs" => ["Program log: ok"]})},
        fn request ->
          assert %{
                   "method" => "simulateTransaction",
                   "params" => [
                     ^transaction,
                     %{
                       "sigVerify" => false,
                       "replaceRecentBlockhash" => false,
                       "commitment" => "confirmed",
                       "encoding" => "base64"
                     }
                   ]
                 } = request
        end
      )

      assert Solana.RPC.simulate_transaction(rpc(context), transaction) ==
               {:ok, %{err: nil, logs: ["Program log: ok"]}}
    end

    test "carries a non-nil err through", context do
      expect_rpc(
        context.bypass,
        {:result, value_envelope(%{"err" => %{"InstructionError" => [2, "Custom"]}})}
      )

      assert Solana.RPC.simulate_transaction(rpc(context), Base.encode64("x")) ==
               {:ok, %{err: %{"InstructionError" => [2, "Custom"]}, logs: nil}}
    end

    test "rejects a simulation value that is not a map", context do
      expect_rpc(context.bypass, {:result, value_envelope("simulation unavailable")})

      assert Solana.RPC.simulate_transaction(rpc(context), Base.encode64("x")) ==
               {:error, {:invalid_response, "simulation unavailable"}}
    end

    test "passes node-side errors through as jsonrpc errors", context do
      expect_rpc(context.bypass, {:error, %{"code" => -32_602, "message" => "invalid params"}})

      assert {:error, {:jsonrpc_error, %{code: -32_602, message: "invalid params"}}} =
               Solana.RPC.simulate_transaction(rpc(context), Base.encode64("x"))
    end
  end

  describe "send_transaction/3" do
    test "sends with skipPreflight and returns the signature", context do
      transaction = Base.encode64("wire-bytes")

      expect_rpc(context.bypass, {:result, @signature}, fn request ->
        assert %{
                 "method" => "sendTransaction",
                 "params" => [
                   ^transaction,
                   %{
                     "encoding" => "base64",
                     "skipPreflight" => true,
                     "preflightCommitment" => "confirmed"
                   }
                 ]
               } = request
      end)

      assert Solana.RPC.send_transaction(rpc(context), transaction) == {:ok, @signature}
    end

    test "rejects a non-string result", context do
      expect_rpc(context.bypass, {:result, 42})

      assert Solana.RPC.send_transaction(rpc(context), Base.encode64("x")) ==
               {:error, {:invalid_response, 42}}
    end

    test "surfaces transport failures", context do
      Bypass.down(context.bypass)

      assert {:error, {:transport_error, _reason}} =
               Solana.RPC.send_transaction(rpc(context), Base.encode64("x"))
    end
  end

  describe "get_signature_statuses/2" do
    test "maps entries and preserves nil for unknown signatures", context do
      expect_rpc(
        context.bypass,
        {:result,
         value_envelope([
           nil,
           %{"confirmationStatus" => "confirmed", "err" => nil, "slot" => 5},
           %{"confirmationStatus" => "finalized", "err" => %{"InstructionError" => [0, 1]}}
         ])},
        fn request ->
          assert %{
                   "method" => "getSignatureStatuses",
                   "params" => [[@signature], %{"searchTransactionHistory" => true}]
                 } = request
        end
      )

      assert Solana.RPC.get_signature_statuses(rpc(context), [@signature]) ==
               {:ok,
                [
                  nil,
                  %{confirmation_status: "confirmed", err: nil},
                  %{confirmation_status: "finalized", err: %{"InstructionError" => [0, 1]}}
                ]}
    end

    test "normalizes a missing confirmationStatus to nil", context do
      expect_rpc(context.bypass, {:result, value_envelope([%{"err" => nil}])})

      assert Solana.RPC.get_signature_statuses(rpc(context), [@signature]) ==
               {:ok, [%{confirmation_status: nil, err: nil}]}
    end

    test "rejects a non-list value", context do
      expect_rpc(context.bypass, {:result, value_envelope(%{"nope" => true})})

      assert Solana.RPC.get_signature_statuses(rpc(context), [@signature]) ==
               {:error, {:invalid_response, %{"nope" => true}}}
    end
  end
end
