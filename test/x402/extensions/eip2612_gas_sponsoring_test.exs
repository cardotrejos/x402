defmodule X402.Extensions.EIP2612GasSponsoringTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.EIP2612GasSponsoring

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.Extensions.EIP2612GasSponsoring
  alias X402.Signer.LocalKey

  @receiver "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @permit2 "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  @max_uint256 "115792089237316195423570985008687907853269984665640564039457584007913129639935"

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 60,
    "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
  }

  @valid_info %{
    "from" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    "asset" => @contract,
    "spender" => @permit2,
    "amount" => @max_uint256,
    "nonce" => "0",
    "deadline" => "1740672154",
    "signature" => "0x" <> String.duplicate("ab", 65),
    "version" => "1"
  }

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  describe "build_extension/0" do
    test "matches the spec's declaration shape" do
      extension = EIP2612GasSponsoring.build_extension()

      assert extension["info"] == %{
               "description" =>
                 "The facilitator accepts EIP-2612 gasless Permit to `Permit2` canonical contract.",
               "version" => "1"
             }

      assert extension["schema"] == EIP2612GasSponsoring.schema()
    end

    test "the schema declares the spec's exact property names and patterns" do
      schema = EIP2612GasSponsoring.schema()

      assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
      assert schema["type"] == "object"

      assert Map.keys(schema["properties"]) |> Enum.sort() ==
               Enum.sort(~w(from asset spender amount nonce deadline signature version))

      assert schema["required"] ==
               ~w(from asset spender amount nonce deadline signature version)

      for field <- ~w(from asset spender) do
        assert schema["properties"][field]["pattern"] == "^0x[a-fA-F0-9]{40}$"
      end

      for field <- ~w(amount nonce deadline) do
        assert schema["properties"][field]["pattern"] == "^[0-9]+$"
      end

      assert schema["properties"]["signature"]["pattern"] == "^0x[a-fA-F0-9]+$"
      assert schema["properties"]["version"]["pattern"] == "^[0-9]+(\\.[0-9]+)*$"
    end

    test "round-trips through JSON" do
      assert {:ok, json} = Jason.encode(EIP2612GasSponsoring.build_extension())
      assert {:ok, _decoded} = Jason.decode(json)
    end
  end

  describe "sign_permit/3" do
    test "produces spec-shaped info with a recoverable signature" do
      signer = signer()

      assert {:ok, info} =
               EIP2612GasSponsoring.sign_permit(@requirements, signer,
                 nonce: "7",
                 deadline: "1740672154"
               )

      assert Map.keys(info) |> Enum.sort() ==
               Enum.sort(~w(from asset spender amount nonce deadline signature version))

      assert info["from"] == signer.address
      assert info["asset"] == @contract
      assert info["spender"] == @permit2
      assert info["amount"] == "10000"
      assert info["nonce"] == "7"
      assert info["deadline"] == "1740672154"
      assert info["version"] == "1"
      assert String.match?(info["signature"], ~r/^0x[0-9a-f]{130}$/)
      assert EIP2612GasSponsoring.validate_info(info) == :ok

      {:ok, domain} = EIP712.domain(@requirements)

      {:ok, digest} =
        EIP2612GasSponsoring.permit_digest(domain, %{
          "owner" => info["from"],
          "spender" => info["spender"],
          "value" => info["amount"],
          "nonce" => info["nonce"],
          "deadline" => info["deadline"]
        })

      assert EIP3009.recover_signer(digest, info["signature"]) == {:ok, signer.address}
    end

    test "defaults the deadline to now + maxTimeoutSeconds" do
      now = System.os_time(:second)

      assert {:ok, info} = EIP2612GasSponsoring.sign_permit(@requirements, signer(), nonce: 0)
      assert_in_delta String.to_integer(info["deadline"]), now + 60, 2
    end

    test "honors amount and spender overrides" do
      spender = "0x3333333333333333333333333333333333333333"

      assert {:ok, info} =
               EIP2612GasSponsoring.sign_permit(@requirements, signer(),
                 nonce: 1,
                 amount: @max_uint256,
                 spender: spender
               )

      assert info["amount"] == @max_uint256
      assert info["spender"] == spender
    end

    test "normalizes integer options to decimal strings" do
      assert {:ok, info} =
               EIP2612GasSponsoring.sign_permit(@requirements, signer(),
                 nonce: 3,
                 deadline: 1_740_672_154,
                 amount: 10_000
               )

      assert info["nonce"] == "3"
      assert info["deadline"] == "1740672154"
      assert info["amount"] == "10000"
    end

    test "rejects malformed nonce, deadline, and amount strings" do
      signer = signer()

      assert EIP2612GasSponsoring.sign_permit(@requirements, signer, nonce: "abc") ==
               {:error, :invalid_nonce}

      assert EIP2612GasSponsoring.sign_permit(@requirements, signer,
               nonce: "0",
               deadline: "soon"
             ) == {:error, :invalid_deadline}

      assert EIP2612GasSponsoring.sign_permit(@requirements, signer,
               nonce: "0",
               amount: "-1"
             ) == {:error, :invalid_amount}
    end

    test "propagates domain and signer errors" do
      missing_extra = Map.put(@requirements, "extra", %{"version" => "2"})

      assert EIP2612GasSponsoring.sign_permit(missing_extra, signer(), nonce: "0") ==
               {:error, {:missing_extra, "name"}}

      assert EIP2612GasSponsoring.sign_permit(@requirements, :not_a_signer, nonce: "0") ==
               {:error, :invalid_signer}
    end

    test "requires the nonce option" do
      assert_raise NimbleOptions.ValidationError, fn ->
        EIP2612GasSponsoring.sign_permit(@requirements, signer(), [])
      end
    end
  end

  describe "put_info/2" do
    test "creates the extensions entry when absent" do
      payload = EIP2612GasSponsoring.put_info(%{"payload" => %{}}, @valid_info)

      assert payload["extensions"]["eip2612GasSponsoring"] == %{"info" => @valid_info}
    end

    test "preserves the echoed server declaration, server fields winning" do
      declaration = EIP2612GasSponsoring.build_extension()

      payload = %{
        "payload" => %{},
        "extensions" => %{
          "eip2612GasSponsoring" => declaration,
          "other" => %{"info" => %{}}
        }
      }

      enriched = EIP2612GasSponsoring.put_info(payload, @valid_info)
      extension = enriched["extensions"]["eip2612GasSponsoring"]

      assert extension["schema"] == declaration["schema"]
      assert extension["info"]["description"] == declaration["info"]["description"]
      assert extension["info"]["version"] == declaration["info"]["version"]
      assert extension["info"]["from"] == @valid_info["from"]
      assert extension["info"]["signature"] == @valid_info["signature"]
      assert enriched["extensions"]["other"] == %{"info" => %{}}
    end
  end

  describe "extract_info/1" do
    test "returns the info from a payment payload" do
      payload = EIP2612GasSponsoring.put_info(%{"payload" => %{}}, @valid_info)

      assert EIP2612GasSponsoring.extract_info(payload) == {:ok, @valid_info}
    end

    test "rejects payloads without the extension" do
      assert EIP2612GasSponsoring.extract_info(%{}) == {:error, :extension_missing}

      assert EIP2612GasSponsoring.extract_info(%{"extensions" => %{}}) ==
               {:error, :extension_missing}

      assert EIP2612GasSponsoring.extract_info(%{
               "extensions" => %{"eip2612GasSponsoring" => %{}}
             }) == {:error, :extension_missing}

      assert EIP2612GasSponsoring.extract_info(%{
               "extensions" => %{"eip2612GasSponsoring" => "nope"}
             }) == {:error, :extension_missing}

      assert EIP2612GasSponsoring.extract_info("nope") == {:error, :extension_missing}
    end

    test "rejects info with missing or empty fields" do
      for field <- ~w(from asset spender amount nonce deadline signature version) do
        payload =
          EIP2612GasSponsoring.put_info(%{"payload" => %{}}, Map.delete(@valid_info, field))

        assert EIP2612GasSponsoring.extract_info(payload) ==
                 {:error, {:missing_info_field, field}}
      end

      payload = EIP2612GasSponsoring.put_info(%{"payload" => %{}}, %{@valid_info | "from" => ""})
      assert EIP2612GasSponsoring.extract_info(payload) == {:error, {:missing_info_field, "from"}}
    end
  end

  describe "validate_info/1" do
    test "accepts the spec's example info" do
      assert EIP2612GasSponsoring.validate_info(@valid_info) == :ok
    end

    test "rejects malformed fields" do
      cases = [
        {"from", "0x123"},
        {"asset", "not-an-address"},
        {"spender", "0x" <> String.duplicate("g", 40)},
        {"amount", "10.5"},
        {"nonce", "-1"},
        {"deadline", "tomorrow"},
        {"signature", "abcdef"},
        {"version", "v1"}
      ]

      for {field, value} <- cases do
        assert EIP2612GasSponsoring.validate_info(%{@valid_info | field => value}) ==
                 {:error, {:invalid_info_field, field}}
      end
    end

    test "rejects missing fields and non-maps" do
      assert EIP2612GasSponsoring.validate_info(Map.delete(@valid_info, "nonce")) ==
               {:error, {:missing_info_field, "nonce"}}

      assert EIP2612GasSponsoring.validate_info("nope") == {:error, :extension_missing}
    end
  end

  describe "enricher/2" do
    test "signs and attaches the extension when the server advertises it" do
      signer = signer()

      payment_required = %{
        "x402Version" => 2,
        "accepts" => [@requirements],
        "extensions" => %{"eip2612GasSponsoring" => EIP2612GasSponsoring.build_extension()}
      }

      payload = %{
        "x402Version" => 2,
        "accepted" => @requirements,
        "payload" => %{},
        "extensions" => payment_required["extensions"]
      }

      enricher = EIP2612GasSponsoring.enricher(signer, nonce: "0", deadline: "1740672154")

      assert {:ok, enriched} = enricher.(payload, payment_required)
      assert {:ok, info} = EIP2612GasSponsoring.extract_info(enriched)
      assert EIP2612GasSponsoring.validate_info(info) == :ok
      assert info["from"] == signer.address
    end

    test "passes the payload through when the extension is not advertised" do
      payload = %{"accepted" => @requirements, "payload" => %{}}
      enricher = EIP2612GasSponsoring.enricher(signer(), nonce: "0")

      assert enricher.(payload, %{"accepts" => [@requirements]}) == {:ok, payload}
      assert enricher.(payload, nil) == {:ok, payload}
    end

    test "propagates signing errors" do
      payment_required = %{
        "accepts" => [@requirements],
        "extensions" => %{"eip2612GasSponsoring" => EIP2612GasSponsoring.build_extension()}
      }

      payload = %{
        "accepted" => Map.put(@requirements, "extra", %{"version" => "2"}),
        "payload" => %{}
      }

      enricher = EIP2612GasSponsoring.enricher(signer(), nonce: "0")

      assert enricher.(payload, payment_required) == {:error, {:missing_extra, "name"}}
    end
  end
end
