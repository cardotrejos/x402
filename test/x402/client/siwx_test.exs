defmodule X402.Client.SIWXTest do
  use ExUnit.Case, async: true

  doctest X402.Client.SIWX

  alias X402.Client.SIWX, as: ClientSIWX
  alias X402.Extensions.SIWX
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey

  @evm_chain "eip155:8453"
  @solana_chain "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  @resource "https://api.example.com/premium"

  defp evm_signer do
    {:ok, signer} = LocalKey.new("0x" <> String.duplicate("11", 32))
    signer
  end

  defp solana_signer do
    {:ok, signer} = SolanaKey.new(:binary.copy(<<1>>, 32))
    signer
  end

  defp challenge(opts \\ []) do
    SIWX.challenge(
      Keyword.merge(
        [
          domain: "api.example.com",
          uri: "https://api.example.com",
          supported_chains: [%{chain_id: @evm_chain}, %{chain_id: @solana_chain}]
        ],
        opts
      )
    )
  end

  defp payment_required(challenge) do
    %{"x402Version" => 2, "accepts" => [], "extensions" => %{"sign-in-with-x" => challenge}}
  end

  defp verify(header, chain_id) do
    SIWX.verify(header,
      domain: "api.example.com",
      uri: "https://api.example.com",
      supported_chains: [%{chain_id: chain_id}]
    )
  end

  describe "validate_opts/1" do
    test "validates nested options" do
      assert {:ok, opts} =
               ClientSIWX.validate_opts(
                 chain_id: @evm_chain,
                 address: "0xabc",
                 signature_scheme: "eip191",
                 domain: "api.example.com"
               )

      assert opts[:chain_id] == @evm_chain
      assert opts[:signature_scheme] == "eip191"

      assert {:error, message} = ClientSIWX.validate_opts(chain_id: 8453)
      assert message =~ ":chain_id"
      assert {:error, _message} = ClientSIWX.validate_opts(chain_id: :auto, unknown: 1)
      assert {:error, _message} = ClientSIWX.validate_opts("auto")
    end
  end

  describe "authenticate/4 with an explicit chain" do
    test "signs an EVM challenge that verifies on the server side" do
      signer = evm_signer()
      challenge = challenge()

      assert {:ok, proof} =
               ClientSIWX.authenticate(
                 payment_required(challenge),
                 signer,
                 [chain_id: @evm_chain],
                 resource_url: @resource
               )

      assert proof.chain_id == @evm_chain
      assert proof.address == signer.address
      assert {:ok, identity} = verify(proof.header, @evm_chain)
      assert identity.address == signer.address
      assert identity.fields["nonce"] == challenge["info"]["nonce"]
    end

    test "forwards :address and :signature_scheme to the proof" do
      other = "0x0000000000000000000000000000000000000001"

      assert {:ok, proof} =
               ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
                 chain_id: @evm_chain,
                 domain: "api.example.com",
                 address: other,
                 signature_scheme: "eip1271"
               )

      assert proof.address == other
      assert {:ok, {:spec, fields}} = SIWX.decode_signed(proof.header)
      assert fields["signatureScheme"] == "eip1271"
    end

    test "returns signer and chain errors wrapped as {:siwx, reason}" do
      payment_required = payment_required(challenge())

      assert ClientSIWX.authenticate(payment_required, solana_signer(),
               chain_id: @evm_chain,
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_signer}}

      assert ClientSIWX.authenticate(payment_required, evm_signer(),
               chain_id: "eip155:1",
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}

      assert ClientSIWX.authenticate(payment_required, evm_signer(),
               chain_id: "eip155:x",
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :invalid_chain_id}}

      assert ClientSIWX.authenticate(payment_required, evm_signer(),
               chain_id: "cosmos:hub",
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}
    end

    test "rejects challenges without an info map" do
      payment_required = payment_required(%{"supportedChains" => []})

      assert ClientSIWX.authenticate(payment_required, evm_signer(), chain_id: @evm_chain) ==
               {:error, {:siwx, :invalid_challenge}}
    end

    test "returns :none without a challenge" do
      assert ClientSIWX.authenticate(%{"accepts" => []}, evm_signer(), chain_id: @evm_chain) ==
               :none

      assert ClientSIWX.authenticate(%{"extensions" => %{"other" => %{}}}, evm_signer(),
               chain_id: @evm_chain
             ) == :none
    end
  end

  describe "authenticate/4 with chain_id: :auto" do
    test "an EVM signer picks the first eip155 chain" do
      chains = [%{chain_id: @solana_chain}, %{chain_id: "eip155:1"}, %{chain_id: @evm_chain}]
      payment_required = payment_required(challenge(supported_chains: chains))

      assert {:ok, %{chain_id: "eip155:1"}} =
               ClientSIWX.authenticate(payment_required, evm_signer(),
                 chain_id: :auto,
                 domain: "api.example.com"
               )
    end

    test "a Solana signer picks the first solana chain" do
      assert {:ok, %{chain_id: @solana_chain, header: header}} =
               ClientSIWX.authenticate(payment_required(challenge()), solana_signer(),
                 chain_id: :auto,
                 domain: "api.example.com"
               )

      assert {:ok, %{address: "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"}} =
               verify(header, @solana_chain)
    end

    test "fails when no advertised chain matches the signer" do
      payment_required = payment_required(challenge(supported_chains: [%{chain_id: @evm_chain}]))

      assert ClientSIWX.authenticate(payment_required, solana_signer(),
               chain_id: :auto,
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}

      no_chains = payment_required(%{"info" => challenge()["info"], "supportedChains" => "nope"})

      assert ClientSIWX.authenticate(no_chains, evm_signer(),
               chain_id: :auto,
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}

      assert ClientSIWX.authenticate(payment_required, %URI{},
               chain_id: :auto,
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}

      assert ClientSIWX.authenticate(payment_required, %{not: :a_struct},
               chain_id: :auto,
               domain: "api.example.com"
             ) ==
               {:error, {:siwx, :unsupported_chain}}
    end

    test "ignores malformed supportedChains entries" do
      challenge = %{
        "info" => challenge()["info"],
        "supportedChains" => [
          "nope",
          %{"type" => "eip191"},
          %{"chainId" => "cosmos:hub"},
          [chain_id: @evm_chain]
        ]
      }

      assert {:ok, %{chain_id: @evm_chain}} =
               ClientSIWX.authenticate(payment_required(challenge), evm_signer(),
                 chain_id: :auto,
                 domain: "api.example.com"
               )
    end
  end

  describe "authenticate/4 origin binding" do
    test "accepts bracketed IPv6 URI pins without rewriting the signed challenge" do
      for {domain, uri} <- [
            {"[::1]:3000", "http://[::1]:3000/tools/test"},
            {"[::1]:80", "http://[::1]:80/tools/test"},
            {"[2001:DB8::1]", "https://[2001:DB8::1]/tools/test"},
            {"[2001:db8::1]:443", "https://[2001:db8::1]:443/tools/test"}
          ],
          context <- [[transport: :mcp], [transport: :http, resource_url: uri]] do
        ipv6 = challenge(domain: domain, uri: uri)

        assert {:ok, proof} =
                 ClientSIWX.authenticate(
                   payment_required(ipv6),
                   evm_signer(),
                   [chain_id: @evm_chain, domain: domain, uri: uri],
                   context
                 )

        assert {:ok, {:spec, fields}} = SIWX.decode_signed(proof.header)
        assert fields["domain"] == domain
        assert fields["uri"] == uri
      end
    end

    test "derives bracketed IPv6 domains from the HTTP resource URL" do
      uri = "http://[::1]:3000/tools/test"

      for domain <- ["[::1]", "[::1]:3000"],
          opts <- [[chain_id: @evm_chain], [chain_id: @evm_chain, uri: uri]] do
        assert {:ok, _proof} =
                 ClientSIWX.authenticate(
                   payment_required(challenge(domain: domain, uri: uri)),
                   evm_signer(),
                   opts,
                   transport: :http,
                   resource_url: uri
                 )
      end
    end

    test "IPv6 URI pins reject other hosts and ports before consent" do
      uri = "http://[::1]:3000/tools/test"

      for domain <- ["[::2]:3000", "[::1]:3001", "::1:3000"] do
        assert {:error, {:siwx, :domain_mismatch}} =
                 ClientSIWX.authenticate(
                   payment_required(challenge(domain: domain, uri: uri)),
                   evm_signer(),
                   [chain_id: @evm_chain, domain: domain, uri: uri],
                   transport: :mcp,
                   before_sign: fn -> flunk("mismatched IPv6 domain reached consent") end
                 )
      end
    end

    test "matches domain case without rewriting the signed challenge" do
      mixed = challenge(domain: "API.Example.COM:8443", uri: "https://API.Example.COM:8443")

      for opts <- [
            [resource_url: "https://api.example.com:8443/premium"],
            [resource_url: "https://API.EXAMPLE.COM:8443/premium"]
          ] do
        assert {:ok, proof} =
                 ClientSIWX.authenticate(
                   payment_required(mixed),
                   evm_signer(),
                   [chain_id: @evm_chain],
                   opts
                 )

        assert {:ok, {:spec, fields}} = SIWX.decode_signed(proof.header)
        assert fields["domain"] == mixed["info"]["domain"]
        assert fields["uri"] == mixed["info"]["uri"]
      end

      assert {:ok, _proof} =
               ClientSIWX.authenticate(payment_required(mixed), evm_signer(),
                 chain_id: @evm_chain,
                 domain: "api.example.com:8443"
               )

      assert {:ok, _proof} =
               ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
                 chain_id: @evm_chain,
                 domain: "API.EXAMPLE.COM"
               )
    end

    test "case-insensitive matching retains host, scheme and port boundaries" do
      for domain <- ["EVIL.EXAMPLE.COM", "API.EXAMPLE.COM:8443", "API.EXAMPLE.COM.evil.test"] do
        assert ClientSIWX.authenticate(
                 payment_required(challenge(domain: domain)),
                 evm_signer(),
                 [chain_id: @evm_chain],
                 resource_url: @resource
               ) == {:error, {:siwx, :domain_mismatch}}
      end

      for uri <- [
            "https://EVIL.EXAMPLE.COM",
            "http://API.EXAMPLE.COM",
            "https://API.EXAMPLE.COM:8443"
          ] do
        assert ClientSIWX.authenticate(
                 payment_required(challenge(uri: uri)),
                 evm_signer(),
                 [chain_id: @evm_chain],
                 resource_url: @resource
               ) == {:error, {:siwx, :uri_mismatch}}
      end
    end

    test "accepts a domain with the resource's port and rejects other hosts" do
      port_challenge =
        challenge(domain: "api.example.com:8443", uri: "https://api.example.com:8443")

      assert {:ok, _proof} =
               ClientSIWX.authenticate(
                 payment_required(port_challenge),
                 evm_signer(),
                 [chain_id: @evm_chain],
                 resource_url: "https://api.example.com:8443/premium"
               )

      assert ClientSIWX.authenticate(
               payment_required(challenge()),
               evm_signer(),
               [chain_id: @evm_chain],
               resource_url: "https://evil.example.com/premium"
             ) ==
               {:error, {:siwx, :domain_mismatch}}
    end

    test "rejects a uri whose origin differs from the resource URL" do
      challenge = challenge(uri: "http://api.example.com")

      assert ClientSIWX.authenticate(
               payment_required(challenge),
               evm_signer(),
               [chain_id: @evm_chain],
               resource_url: @resource
             ) ==
               {:error, {:siwx, :uri_mismatch}}

      missing_uri = %{challenge() | "info" => Map.delete(challenge()["info"], "uri")}

      assert ClientSIWX.authenticate(
               payment_required(missing_uri),
               evm_signer(),
               [chain_id: @evm_chain],
               resource_url: @resource
             ) ==
               {:error, {:siwx, :uri_mismatch}}
    end

    test "an explicit :domain wins over the resource URL and a missing domain fails" do
      assert {:ok, _proof} =
               ClientSIWX.authenticate(
                 payment_required(challenge()),
                 evm_signer(),
                 [chain_id: @evm_chain, domain: "api.example.com"],
                 resource_url: "https://api.example.com/premium"
               )

      assert ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
               chain_id: @evm_chain,
               domain: "other.example.com"
             ) == {:error, {:siwx, :domain_mismatch}}

      no_domain = %{challenge() | "info" => Map.delete(challenge()["info"], "domain")}

      assert ClientSIWX.authenticate(payment_required(no_domain), evm_signer(),
               chain_id: @evm_chain
             ) == {:error, {:siwx, :domain_mismatch}}
    end

    test "refuses signing without a trusted domain or resource URL" do
      for domain <- [nil, ""] do
        assert ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
                 chain_id: @evm_chain,
                 domain: domain
               ) == {:error, {:siwx, :domain_mismatch}}
      end

      assert ClientSIWX.authenticate(payment_required(challenge(domain: "")), evm_signer(),
               chain_id: @evm_chain,
               domain: ""
             ) == {:error, {:siwx, :domain_mismatch}}
    end

    test "a resource URL without a host matches nothing" do
      assert ClientSIWX.authenticate(
               payment_required(challenge()),
               evm_signer(),
               [chain_id: @evm_chain],
               resource_url: "premium"
             ) ==
               {:error, {:siwx, :domain_mismatch}}
    end

    test "a resource URL without a default port matches the bare host only" do
      # The domain matches, but the challenge's https origin cannot equal a
      # scheme without a known port.
      assert ClientSIWX.authenticate(
               payment_required(challenge()),
               evm_signer(),
               [chain_id: @evm_chain],
               resource_url: "custom://api.example.com/premium"
             ) == {:error, {:siwx, :uri_mismatch}}
    end
  end

  describe "fetch_challenge/1" do
    test "returns :error for anything but a map carrying the extension" do
      assert ClientSIWX.fetch_challenge("nope") == :error

      assert ClientSIWX.fetch_challenge(%{"extensions" => %{"sign-in-with-x" => "nope"}}) ==
               :error
    end
  end

  describe "telemetry" do
    setup do
      handler_id = "client-siwx-#{System.unique_integer([:positive])}"
      parent = self()

      :telemetry.attach(
        handler_id,
        [:x402, :client, :siwx],
        fn event, measurements, metadata, _config ->
          if self() == parent, do: send(parent, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    test "direct calls report the attempted chain and an unspecified transport" do
      ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
        chain_id: "eip155:1",
        domain: "api.example.com"
      )

      assert_received {:telemetry, [:x402, :client, :siwx], %{count: 1},
                       %{
                         status: :error,
                         reason: :unsupported_chain,
                         chain_id: "eip155:1",
                         transport: nil
                       }}

      refute_received {:telemetry, _, _, _}
    end

    test "failures before chain selection report nil rather than :auto or an untrusted chain" do
      for {opts, reason} <- [
            {[chain_id: @evm_chain, domain: "other.example.com"], :domain_mismatch},
            {[chain_id: :auto, domain: "api.example.com", uri: "https://api.example.com"],
             :unsupported_chain}
          ] do
        assert ClientSIWX.authenticate(payment_required(challenge()), %URI{}, opts,
                 transport: :mcp
               ) == {:error, {:siwx, reason}}

        assert_received {:telemetry, [:x402, :client, :siwx], %{count: 1},
                         %{status: :error, reason: ^reason, chain_id: nil, transport: :mcp}}

        refute_received {:telemetry, _, _, _}
      end
    end

    test "automatic selection retains the chain when proof construction fails" do
      malformed = challenge() |> update_in(["info"], &Map.delete(&1, "nonce"))

      assert {:error, {:siwx, :invalid_payload}} =
               ClientSIWX.authenticate(
                 payment_required(malformed),
                 solana_signer(),
                 [chain_id: :auto, domain: "api.example.com"],
                 transport: :http
               )

      assert_received {:telemetry, [:x402, :client, :siwx], %{count: 1},
                       %{
                         status: :error,
                         reason: :invalid_payload,
                         chain_id: @solana_chain,
                         transport: :http
                       }}

      refute_received {:telemetry, _, _, _}
    end

    test "successful signing and absent challenges do not emit an outcome prematurely" do
      assert {:ok, _proof} =
               ClientSIWX.authenticate(payment_required(challenge()), evm_signer(),
                 chain_id: :auto,
                 domain: "api.example.com"
               )

      assert :none = ClientSIWX.authenticate(%{}, evm_signer(), chain_id: :auto)
      refute_received {:telemetry, _, _, _}
    end

    test "consent rejection reports the selected chain without signing" do
      assert {:error, {:siwx, :payment_cancelled}} =
               ClientSIWX.authenticate(
                 payment_required(challenge()),
                 solana_signer(),
                 [chain_id: :auto, domain: "api.example.com", uri: "https://api.example.com"],
                 transport: :mcp,
                 before_sign: fn -> :cancel end
               )

      assert_received {:telemetry, [:x402, :client, :siwx], %{count: 1},
                       %{
                         status: :error,
                         reason: :payment_cancelled,
                         chain_id: @solana_chain,
                         transport: :mcp
                       }}

      refute_received {:telemetry, _, _, _}
    end
  end
end
