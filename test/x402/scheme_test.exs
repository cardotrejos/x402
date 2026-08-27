defmodule X402.SchemeTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme

  alias X402.Scheme

  defmodule MetadataOnly do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "metadata-only"

    @impl X402.Scheme
    def networks, do: ["test:*"]
  end

  defmodule FullScheme do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "full"

    @impl X402.Scheme
    def networks, do: ["test:*"]

    @impl X402.Scheme
    def signable?(requirements), do: Map.get(requirements, "signable", false)

    @impl X402.Scheme
    def sign(_requirements, _signer, _opts), do: {:ok, %{"signed" => true}}

    @impl X402.Scheme
    def validate_payload(_payload, _requirements, _opts), do: {:error, :always_invalid}

    @impl X402.Scheme
    def precheck(_payload, _requirements, _opts), do: {:error, {:precheck_failed, :always}}
  end

  describe "validate_module/1" do
    test "accepts modules implementing scheme/0 and networks/0" do
      assert Scheme.validate_module(MetadataOnly) == {:ok, MetadataOnly}
      assert Scheme.validate_module(FullScheme) == {:ok, FullScheme}
    end

    test "rejects modules missing the required callbacks" do
      assert {:error, message} = Scheme.validate_module(Enum)
      assert message =~ "X402.Scheme"
    end

    test "rejects non-module terms" do
      assert {:error, _message} = Scheme.validate_module("not a module")
      assert {:error, _message} = Scheme.validate_module(123)
    end
  end

  describe "signs?/1" do
    test "reflects whether sign/3 is exported" do
      assert Scheme.signs?(FullScheme)
      refute Scheme.signs?(MetadataOnly)
    end
  end

  describe "signable?/2" do
    test "defaults to true when signable?/1 is not implemented" do
      assert Scheme.signable?(MetadataOnly, %{})
    end

    test "delegates to the module when implemented" do
      assert Scheme.signable?(FullScheme, %{"signable" => true})
      refute Scheme.signable?(FullScheme, %{})
    end
  end

  describe "validate_payload/4" do
    test "defaults to :ok when validate_payload/3 is not implemented" do
      assert Scheme.validate_payload(MetadataOnly, %{}, %{}, []) == :ok
    end

    test "delegates to the module when implemented" do
      assert Scheme.validate_payload(FullScheme, %{}, %{}, []) == {:error, :always_invalid}
    end
  end

  describe "precheck/4" do
    test "defaults to :ok when precheck/3 is not implemented" do
      assert Scheme.precheck(MetadataOnly, %{}, %{}, []) == :ok
    end

    test "delegates to the module when implemented" do
      assert Scheme.precheck(FullScheme, %{}, %{}, []) ==
               {:error, {:precheck_failed, :always}}
    end
  end
end
