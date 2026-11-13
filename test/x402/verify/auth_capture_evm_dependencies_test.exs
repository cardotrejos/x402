defmodule X402.Verify.AuthCaptureEVMDependenciesTest do
  # Replaces optional crypto dependencies for the duration of a test, so this
  # file must not run concurrently with others.
  use ExUnit.Case, async: false

  alias X402.TestAuthCapture, as: Fixture
  alias X402.Verify.AuthCaptureEVM, as: Verify

  describe "levels that need the optional crypto dependencies" do
    test "a missing keccak implementation fails closed at the signature level" do
      vector = Fixture.vector()
      opts = [level: :signature, now: Fixture.fixture()["now"]]

      with_unavailable_module(ExKeccak, fn ->
        assert Verify.verify(Fixture.envelope(vector), vector["requirements"], opts) ==
                 {:error, :missing_dependency}
      end)

      assert {:ok, %{level: :signature}} =
               Verify.verify(Fixture.envelope(vector), vector["requirements"], opts)
    end

    test "the structural level needs neither dependency" do
      vector = Fixture.vector()
      opts = [level: :structural, now: Fixture.fixture()["now"]]

      for module <- [ExKeccak, ExSecp256k1] do
        with_unavailable_module(module, fn ->
          assert {:ok, %{level: :structural, payment_info_hash: nil}} =
                   Verify.verify(Fixture.envelope(vector), vector["requirements"], opts)
        end)
      end
    end

    test "a missing secp256k1 implementation never downgrades a client signature check" do
      vector = Fixture.vector()
      opts = [level: :signature, now: Fixture.fixture()["now"]]

      with_unavailable_module(ExSecp256k1, fn ->
        assert Verify.verify(Fixture.envelope(vector), vector["requirements"], opts) ==
                 {:error, :missing_dependency}
      end)
    end

    test "a missing secp256k1 implementation never downgrades an authorizer signature check" do
      vector = Fixture.vector()
      capture = Fixture.lifecycle(vector, "capture")
      opts = [level: :signature, now: Fixture.fixture()["now"]]

      assert {:ok, %{operation: :capture}} = Verify.verify(capture, capture["accepted"], opts)

      with_unavailable_module(ExSecp256k1, fn ->
        assert Verify.verify(capture, capture["accepted"], opts) == {:error, :missing_dependency}
      end)
    end
  end

  @spec with_unavailable_module(module(), (-> term())) :: term()
  defp with_unavailable_module(module, fun) when is_atom(module) and is_function(fun, 0) do
    {^module, original_binary, original_path} = :code.get_object_code(module)
    original_conflict_setting = Code.get_compiler_option(:ignore_module_conflict)

    Code.put_compiler_option(:ignore_module_conflict, true)

    try do
      Code.compile_string("defmodule #{inspect(module)} do\nend")
      fun.()
    after
      :code.purge(module)
      {:module, ^module} = :code.load_binary(module, original_path, original_binary)
      Code.put_compiler_option(:ignore_module_conflict, original_conflict_setting)
    end
  end
end
