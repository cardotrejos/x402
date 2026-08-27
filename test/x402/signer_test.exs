defmodule X402.SignerTest do
  use ExUnit.Case, async: true

  doctest X402.Signer
  doctest X402.Signer.LocalKey

  alias X402.EIP3009
  alias X402.Signer
  alias X402.Signer.LocalKey

  @typed_data %{"domain" => %{}, "types" => %{}, "primaryType" => "T", "message" => %{}}

  defmodule ZeroVSigner do
    @moduledoc false
    # Wraps a LocalKey but reports the recovery byte as 0/1, the way some
    # external signing APIs do — exercises the dispatcher's normalization.
    @behaviour X402.Signer

    alias X402.Signer.LocalKey

    defstruct [:inner]

    @impl true
    def address(%{inner: inner}), do: LocalKey.address(inner)

    @impl true
    def sign_eip712(%{inner: inner}, digest, typed_data) do
      {:ok, <<compact::binary-size(64), v>>} = LocalKey.sign_eip712(inner, digest, typed_data)

      {:ok, compact <> <<v - 27>>}
    end
  end

  defmodule MalformedSigner do
    @moduledoc false
    @behaviour X402.Signer

    defstruct []

    @impl true
    def address(_signer), do: {:ok, "0x1111111111111111111111111111111111111111"}

    @impl true
    def sign_eip712(_signer, _digest, _typed_data), do: {:ok, <<1, 2, 3>>}
  end

  defmodule RecordingSigner do
    @moduledoc false
    @behaviour X402.Signer

    alias X402.Signer.LocalKey

    defstruct [:owner, :inner]

    @impl true
    def address(%{inner: inner}), do: LocalKey.address(inner)

    @impl true
    def sign_eip712(%{owner: owner, inner: inner}, digest, typed_data) do
      send(owner, {:signed, digest, typed_data})
      LocalKey.sign_eip712(inner, digest, typed_data)
    end
  end

  defp local_key(key \\ :crypto.strong_rand_bytes(32)) do
    {:ok, signer} = LocalKey.new(key)
    signer
  end

  describe "LocalKey.new/1" do
    test "accepts a raw 32-byte key, bare hex, and 0x-prefixed hex" do
      key = :crypto.strong_rand_bytes(32)
      hex = Base.encode16(key, case: :lower)

      {:ok, from_raw} = LocalKey.new(key)
      {:ok, from_hex} = LocalKey.new(hex)
      {:ok, from_prefixed} = LocalKey.new("0x" <> hex)

      assert from_raw.address == from_hex.address
      assert from_hex.address == from_prefixed.address
      assert String.match?(from_raw.address, ~r/^0x[0-9a-f]{40}$/)
    end

    test "rejects malformed keys" do
      assert LocalKey.new("0x1234") == {:error, :invalid_private_key}
      assert LocalKey.new(:crypto.strong_rand_bytes(31)) == {:error, :invalid_private_key}
      assert LocalKey.new(:crypto.strong_rand_bytes(33)) == {:error, :invalid_private_key}
      assert LocalKey.new(String.duplicate("zz", 32)) == {:error, :invalid_private_key}
      assert LocalKey.new(nil) == {:error, :invalid_private_key}
    end

    test "matches the address derived by X402.EIP3009" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, signer} = LocalKey.new(key)

      assert EIP3009.derive_address(key) == {:ok, signer.address}
    end
  end

  describe "LocalKey signing" do
    test "produces a 65-byte signature recovering to the signer address" do
      signer = local_key()
      digest = :crypto.strong_rand_bytes(32)

      assert {:ok, signature} = LocalKey.sign_eip712(signer, digest, @typed_data)
      assert byte_size(signature) == 65
      assert <<_compact::binary-size(64), v>> = signature
      assert v in [27, 28]

      assert EIP3009.recover_signer(digest, signature) == {:ok, signer.address}
    end

    test "rejects digests that are not 32 bytes" do
      signer = local_key()

      assert LocalKey.sign_eip712(signer, <<1, 2, 3>>, @typed_data) ==
               {:error, :invalid_digest}
    end

    test "redacts the private key when inspected" do
      key = :crypto.strong_rand_bytes(32)
      signer = local_key(key)
      rendered = inspect(signer)

      assert rendered =~ signer.address
      refute rendered =~ Base.encode16(key, case: :lower)
      refute rendered =~ Base.encode16(key, case: :upper)
    end
  end

  describe "Signer dispatch" do
    test "address/1 dispatches on the struct module" do
      signer = local_key()
      assert Signer.address(signer) == {:ok, signer.address}
    end

    test "address/1 rejects non-struct signers" do
      assert Signer.address(%{}) == {:error, :invalid_signer}
      assert Signer.address("signer") == {:error, :invalid_signer}
    end

    test "sign_eip712/3 normalizes a 0/1 recovery byte to 27/28" do
      inner = local_key()
      signer = %ZeroVSigner{inner: inner}
      digest = :crypto.strong_rand_bytes(32)

      assert {:ok, <<_compact::binary-size(64), v>> = signature} =
               Signer.sign_eip712(signer, digest, @typed_data)

      assert v in [27, 28]
      assert EIP3009.recover_signer(digest, signature) == {:ok, inner.address}
    end

    test "sign_eip712/3 rejects malformed implementation output" do
      assert Signer.sign_eip712(%MalformedSigner{}, :crypto.strong_rand_bytes(32), @typed_data) ==
               {:error, :invalid_signature_format}
    end

    test "sign_eip712/3 rejects non-struct signers" do
      assert Signer.sign_eip712(:signer, <<0::256>>, @typed_data) == {:error, :invalid_signer}
    end

    test "passes the digest and full typed data to the implementation" do
      signer = %RecordingSigner{owner: self(), inner: local_key()}
      digest = :crypto.strong_rand_bytes(32)

      assert {:ok, _signature} = Signer.sign_eip712(signer, digest, @typed_data)
      assert_received {:signed, ^digest, @typed_data}
    end
  end
end
