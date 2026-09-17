defmodule X402.RateLimiterTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  doctest X402.RateLimiter

  alias X402.RateLimiter

  defmodule ScriptedStore do
    @moduledoc false
    @behaviour X402.RateLimiter

    @impl true
    def hit(script, key, limit, window_ms) when is_function(script, 3),
      do: script.(key, limit, window_ms)
  end

  defmodule NotAStore do
    @moduledoc false
    def something_else, do: :ok
  end

  describe "validate_options/1" do
    test "accepts every option" do
      key_fun = fn _context -> :tenant end

      assert {:ok,
              %{
                limit: 3,
                window_ms: 500,
                key: ^key_fun,
                store: {ScriptedStore, :ref},
                on_error: :deny
              }} =
               RateLimiter.validate_options(
                 limit: 3,
                 window_ms: 500,
                 key: key_fun,
                 store: {ScriptedStore, :ref},
                 on_error: :deny
               )
    end

    test "accepts :ip as a key" do
      assert {:ok, %{key: :ip}} = RateLimiter.validate_options(limit: 1, window_ms: 1, key: :ip)
    end

    test "rejects a missing window" do
      assert {:error, message} = RateLimiter.validate_options(limit: 1)
      assert message =~ ":window_ms"
    end

    test "rejects an unknown key kind" do
      assert {:error, message} = RateLimiter.validate_options(limit: 1, window_ms: 1, key: :user)
      assert message =~ ":key"
    end

    test "rejects a store module that does not implement hit/4" do
      assert {:error, message} =
               RateLimiter.validate_options(limit: 1, window_ms: 1, store: NotAStore)

      assert message =~ "X402.RateLimiter (hit/4)"
    end

    test "rejects a store value that is neither a module nor a tuple" do
      assert {:error, message} =
               RateLimiter.validate_options(limit: 1, window_ms: 1, store: "redis")

      assert message =~ "{module, ref}"
    end

    test "rejects an unknown on_error policy" do
      assert {:error, message} =
               RateLimiter.validate_options(limit: 1, window_ms: 1, on_error: :retry)

      assert message =~ ":on_error"
    end
  end

  describe "resolve_key/2" do
    test "a key function may return any term" do
      context = %{
        conn: %{remote_ip: nil},
        payer: "0xabc",
        payment_payload: %{},
        requirements: %{}
      }

      assert RateLimiter.resolve_key(%{key: fn ctx -> {:custom, ctx.payer} end}, context) ==
               {:custom, "0xabc"}
    end

    test "non-EVM payer addresses keep their case" do
      context = %{
        conn: %{remote_ip: nil},
        payer: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        payment_payload: %{},
        requirements: %{}
      }

      assert RateLimiter.resolve_key(%{key: :payer}, context) ==
               {:payer, "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"}
    end

    test ":ip without a remote address yields a nil ip key" do
      context = %{conn: %{}, payer: nil, payment_payload: %{}, requirements: %{}}
      assert RateLimiter.resolve_key(%{key: :ip}, context) == {:ip, nil}
    end
  end

  describe "payer/3" do
    @requirements %{"scheme" => "exact", "network" => "eip155:8453"}
    @payload %{
      "accepted" => @requirements,
      "payload" => %{"authorization" => %{"from" => "0x1"}}
    }

    test "accepts atom keys" do
      assert RateLimiter.payer(%{
               accepted: %{scheme: "exact", network: "eip155:8453"},
               payload: %{authorization: %{from: "0x1"}}
             }) == "0x1"

      assert RateLimiter.payer(@payload, %{body: %{payer: "0x2"}}) == "0x2"
    end

    test "ignores blank addresses" do
      assert RateLimiter.payer(put_in(@payload, ["payload", "authorization", "from"], "")) == nil
    end

    test "ignores payloads without a scheme payload" do
      assert RateLimiter.payer(%{"x402Version" => 2}) == nil
    end

    test "falls back to the payload when the verify response names no usable payer" do
      assert RateLimiter.payer(@payload, %{"isValid" => true}) == "0x1"
      assert RateLimiter.payer(@payload, %{"isValid" => true, "payer" => ""}) == "0x1"
      assert RateLimiter.payer(@payload, %{"isValid" => true, "payer" => 42}) == "0x1"
      assert RateLimiter.payer(@payload, %{status: 200, body: "not json"}) == "0x1"
      assert RateLimiter.payer(@payload, nil) == "0x1"
    end

    test "ignores unrelated authorization fields for non-EVM and unknown schemes" do
      for requirements <- [
            %{"scheme" => "exact", "network" => "solana:mainnet"},
            %{"scheme" => "upto", "network" => "solana:mainnet"},
            %{"scheme" => "custom", "network" => "eip155:8453"},
            %{}
          ] do
        assert RateLimiter.payer(@payload, nil, requirements) == nil
      end

      assert RateLimiter.payer(Map.delete(@payload, "accepted")) == nil
    end

    test "uses only the verified transfer method's signer" do
      payload = put_in(@payload, ["payload", "permit2Authorization"], %{"from" => "0x2"})
      permit2 = Map.put(@requirements, "extra", %{"assetTransferMethod" => "permit2"})
      unsupported = put_in(permit2, ["extra", "assetTransferMethod"], "erc7710")

      assert RateLimiter.payer(payload, nil, @requirements) == "0x1"
      assert RateLimiter.payer(payload, nil, permit2) == "0x2"
      assert RateLimiter.payer(payload, nil, Map.put(@requirements, "scheme", "upto")) == "0x2"
      assert RateLimiter.payer(payload, nil, unsupported) == nil
      assert RateLimiter.payer(@payload, nil, permit2) == nil
    end
  end

  describe "check/2" do
    test "passes the store ref, key, limit, and window to the store" do
      owner = self()

      script = fn key, limit, window_ms ->
        send(owner, {:hit, key, limit, window_ms})
        {:allow, limit - 1}
      end

      config = config(store: {ScriptedStore, script})

      assert RateLimiter.check(config, {:payer, "0xabc"}) == {:allow, 4}
      assert_receive {:hit, {:payer, "0xabc"}, 5, 1_000}
    end

    test "propagates a deny" do
      config = config(store: {ScriptedStore, fn _key, _limit, _window -> {:deny, 250} end})
      assert RateLimiter.check(config, :key) == {:deny, 250}
    end

    test "allows and logs on a store error by default" do
      config = config(store: {ScriptedStore, fn _key, _limit, _window -> {:error, :down} end})

      log = capture_log(fn -> assert RateLimiter.check(config, :key) == {:allow, 5} end)

      assert log =~ "ScriptedStore failed (:down); allowing the request"
    end

    test "denies for one second on a store error when configured" do
      config =
        config(
          store: {ScriptedStore, fn _key, _limit, _window -> {:error, :down} end},
          on_error: :deny
        )

      log = capture_log(fn -> assert RateLimiter.check(config, :key) == {:deny, 1_000} end)

      assert log =~ "denying the request"
    end

    test "treats a raising store as an error" do
      config = config(store: {ScriptedStore, fn _key, _limit, _window -> raise "boom" end})

      log = capture_log(fn -> assert RateLimiter.check(config, :key) == {:allow, 5} end)

      assert log =~ "%RuntimeError{message: \"boom\"}"
    end

    test "treats a throwing store as an error" do
      config = config(store: {ScriptedStore, fn _key, _limit, _window -> throw(:nope) end})

      log = capture_log(fn -> assert RateLimiter.check(config, :key) == {:allow, 5} end)

      assert log =~ "{:throw, :nope}"
    end

    test "treats an invalid return as an error" do
      config = config(store: {ScriptedStore, fn _key, _limit, _window -> :maybe end})

      log = capture_log(fn -> assert RateLimiter.check(config, :key) == {:allow, 5} end)

      assert log =~ "{:invalid_return, :maybe}"
    end

    test "treats a negative remaining or non-positive retry as invalid" do
      negative = config(store: {ScriptedStore, fn _key, _limit, _window -> {:allow, -1} end})
      zero = config(store: {ScriptedStore, fn _key, _limit, _window -> {:deny, 0} end})

      capture_log(fn ->
        assert RateLimiter.check(negative, :key) == {:allow, 5}
        assert RateLimiter.check(zero, :key) == {:allow, 5}
      end)
    end
  end

  defp config(overrides) do
    Map.merge(
      %{limit: 5, window_ms: 1_000, key: :payer, store: {ScriptedStore, nil}, on_error: :allow},
      Map.new(overrides)
    )
  end
end
