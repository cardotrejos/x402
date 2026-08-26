defmodule X402.Facilitator.AuthTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator.Auth
  alias X402.Facilitator.Auth.CDP

  doctest X402.Facilitator.Auth

  describe "new/1" do
    test "normalizes nil to no auth" do
      assert {:ok, nil} = Auth.new(nil)
    end

    test "dispatches a bare module to its new/1 with empty options" do
      assert {:error, {:missing_credential, :api_key_id}} = Auth.new(CDP)
    end

    test "builds an auth module with explicit options" do
      assert {:ok, %CDP{api_key_id: "key-123", key_format: :ed25519}} =
               Auth.new(
                 {CDP, api_key_id: "key-123", api_key_secret: X402.TestAuthKeys.ed25519_secret()}
               )
    end

    test "returns the module error on invalid options" do
      assert {:error, {:missing_credential, :api_key_secret}} =
               Auth.new({CDP, api_key_id: "key-123"})
    end
  end

  describe "headers/2" do
    test "returns no headers when auth is nil" do
      assert {:ok, []} = Auth.headers(nil, %{method: :post, host: "x", path: "/verify"})
    end

    test "delegates to the configured auth module" do
      {:ok, auth} =
        Auth.new({CDP, api_key_id: "key-123", api_key_secret: X402.TestAuthKeys.ed25519_secret()})

      assert {:ok,
              [
                {"authorization", "Bearer " <> _token},
                {"correlation-context", _context}
              ]} = Auth.headers(auth, %{method: :post, host: "x", path: "/verify"})
    end
  end
end
