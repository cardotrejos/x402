defmodule X402.Extensions.SIWX.ChallengeTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX.Challenge

  alias X402.Extensions.SIWX.Challenge

  @base [domain: "api.example.com", uri: "https://api.example.com"]

  describe "build/1" do
    test "includes every optional info field when configured" do
      issued_at = ~U[2024-01-15 10:30:00.250Z]

      challenge =
        Challenge.build(
          @base ++
            [
              supported_chains: [%{chain_id: "eip155:8453"}],
              statement: "Sign in",
              resources: ["https://api.example.com/premium"],
              expiration_seconds: 60,
              nonce: String.duplicate("ab", 16),
              issued_at: issued_at,
              not_before: ~U[2024-01-15 10:31:00Z],
              request_id: "req-1"
            ]
        )

      assert challenge["info"] == %{
               "domain" => "api.example.com",
               "uri" => "https://api.example.com",
               "version" => "1",
               "nonce" => String.duplicate("ab", 16),
               "issuedAt" => "2024-01-15T10:30:00.250Z",
               "expirationTime" => "2024-01-15T10:31:00.250Z",
               "statement" => "Sign in",
               "resources" => ["https://api.example.com/premium"],
               "notBefore" => "2024-01-15T10:31:00.000Z",
               "requestId" => "req-1"
             }
    end

    test "normalizes supported chain entries from maps, keyword lists, and wire keys" do
      challenge =
        Challenge.build(
          @base ++
            [
              supported_chains: [
                [chain_id: "eip155:1"],
                %{"chainId" => "eip155:8453", "type" => "eip191", "signatureScheme" => "eip1271"},
                %{chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", signature_scheme: "siws"}
              ]
            ]
        )

      assert challenge["supportedChains"] == [
               %{"chainId" => "eip155:1", "type" => "eip191"},
               %{"chainId" => "eip155:8453", "type" => "eip191", "signatureScheme" => "eip1271"},
               %{
                 "chainId" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                 "type" => "ed25519",
                 "signatureScheme" => "siws"
               }
             ]
    end

    test "raises for invalid supported chains" do
      for chains <- [
            [],
            :nope,
            [%{chain_id: "cosmos:hub"}],
            [%{chain_id: 1}],
            [%{chain_id: "eip155:1", type: "ed25519"}],
            [%{chain_id: "eip155:1", signature_scheme: "rsa"}],
            [[1, 2]],
            ["eip155:1"]
          ] do
        assert_raise NimbleOptions.ValidationError, fn ->
          Challenge.build(@base ++ [supported_chains: chains])
        end
      end
    end

    test "raises for missing required options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        Challenge.build(supported_chains: [%{chain_id: "eip155:1"}])
      end
    end
  end
end
