defmodule X402.ExtensionTest do
  use ExUnit.Case, async: true
  doctest X402.Extension

  import ExUnit.CaptureLog

  alias X402.Extension
  alias X402.Hooks.RequestContext

  defmodule KeyOnly do
    @moduledoc false
    @behaviour X402.Extension

    def key, do: "key-only"
  end

  defmodule Full do
    @moduledoc false
    @behaviour X402.Extension

    def key, do: "full"

    def init(opts) do
      case Keyword.get(opts, :mode, :ok) do
        :bad_init -> {:error, "bad mode"}
        _mode -> {:ok, opts}
      end
    end

    def advertise(opts, _context) do
      case opts[:mode] do
        :silent -> nil
        _mode -> %{"info" => %{"mode" => opts[:mode]}}
      end
    end

    def validate(echoed, advertised, _opts) do
      case echoed do
        nil -> :ok
        ^advertised -> :ok
        _other -> {:error, :echo_differs}
      end
    end

    def after_verify(payload, _requirements, _result, opts) do
      send(self(), {:after_verify, payload, opts[:mode]})
      if opts[:mode] == :raise, do: raise("verify boom")
    end

    def after_settle(_payload, _requirements, _result, opts) do
      send(self(), {:after_settle, opts[:mode]})
      if opts[:mode] == :throw, do: throw(:settle_boom)
    end
  end

  describe "validate_spec/1" do
    test "accepts modules with or without init/1" do
      assert {:ok, {KeyOnly, []}} = Extension.validate_spec(KeyOnly)
      assert {:ok, {KeyOnly, [x: 1]}} = Extension.validate_spec({KeyOnly, x: 1})
      assert {:ok, {Full, [mode: :ok]}} = Extension.validate_spec({Full, mode: :ok})
    end

    test "surfaces init errors and non-adapters" do
      assert {:error, message} = Extension.validate_spec({Full, mode: :bad_init})
      assert message =~ "bad mode"
      assert message =~ "Full"

      assert {:error, message} = Extension.validate_spec(Enum)
      assert message =~ "expected a module implementing X402.Extension"

      assert {:error, _message} = Extension.validate_spec({KeyOnly, %{}})
      assert {:error, _message} = Extension.validate_spec("nope")
    end
  end

  describe "advertise_all/3" do
    test "skips adapters without advertise/2 or returning nil" do
      context = RequestContext.new(transport: :http)

      entries = [{KeyOnly, []}, {Full, mode: :silent}, {Full, mode: :loud}]
      base = %{"static" => %{"info" => %{}}}

      assert Extension.advertise_all(entries, context, base) == %{
               "static" => %{"info" => %{}},
               "full" => %{"info" => %{"mode" => :loud}}
             }
    end
  end

  describe "validate_all/3" do
    test "matches values by key across atom and string keys and stops at the first error" do
      entries = [{KeyOnly, []}, {Full, mode: :ok}]
      advertised = %{full: %{"info" => %{"mode" => :ok}}}

      assert :ok = Extension.validate_all(entries, %{}, advertised)
      assert :ok = Extension.validate_all(entries, nil, advertised)

      assert :ok =
               Extension.validate_all(
                 entries,
                 %{"full" => %{"info" => %{"mode" => :ok}}},
                 advertised
               )

      assert {:error, {:extension_invalid, "full", :echo_differs}} =
               Extension.validate_all(entries, %{full: %{"info" => %{}}}, advertised)
    end
  end

  describe "after_verify_all/4 and after_settle_all/4" do
    test "notify every adapter defining the callback and log failures" do
      entries = [{KeyOnly, []}, {Full, mode: :raise}, {Full, mode: :throw}]

      log =
        capture_log(fn ->
          assert :ok = Extension.after_verify_all(entries, %{"p" => 1}, %{}, %{status: 200})
          assert :ok = Extension.after_settle_all(entries, %{}, %{}, %{status: 200})
        end)

      assert_received {:after_verify, %{"p" => 1}, :raise}
      assert_received {:after_verify, %{"p" => 1}, :throw}
      assert_received {:after_settle, :raise}
      assert_received {:after_settle, :throw}
      assert log =~ "after_verify/4 failed"
      assert log =~ "verify boom"
      assert log =~ "after_settle/4 failed"
      assert log =~ "settle_boom"
    end
  end
end
