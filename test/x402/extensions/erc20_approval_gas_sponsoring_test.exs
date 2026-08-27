defmodule X402.Extensions.ERC20ApprovalGasSponsoringTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.ERC20ApprovalGasSponsoring

  alias X402.Extensions.ERC20ApprovalGasSponsoring

  @from "0x857b06519E91e3A54538791bDbb0E22373e36b66"
  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @permit2 "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  @max_uint256 "115792089237316195423570985008687907853269984665640564039457584007913129639935"
  @signed_tx "0x02f8" <> String.duplicate("ab", 100)

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds" => 60,
    "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
  }

  @valid_info %{
    "from" => @from,
    "asset" => @contract,
    "spender" => @permit2,
    "amount" => @max_uint256,
    "signedTransaction" => @signed_tx,
    "version" => "1"
  }

  describe "build_extension/0" do
    test "matches the spec's declaration shape" do
      extension = ERC20ApprovalGasSponsoring.build_extension()

      assert extension["info"] == %{
               "description" =>
                 "The facilitator accepts a raw signed approval transaction and will sponsor the gas fees.",
               "version" => "1"
             }

      assert extension["schema"] == ERC20ApprovalGasSponsoring.schema()
    end

    test "the schema declares the spec's exact property names and patterns" do
      schema = ERC20ApprovalGasSponsoring.schema()

      assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
      assert schema["type"] == "object"

      assert Map.keys(schema["properties"]) |> Enum.sort() ==
               Enum.sort(~w(from asset spender amount signedTransaction version))

      assert schema["required"] == ~w(from asset spender amount signedTransaction version)

      for field <- ~w(from asset spender) do
        assert schema["properties"][field]["pattern"] == "^0x[a-fA-F0-9]{40}$"
      end

      assert schema["properties"]["amount"]["pattern"] == "^[0-9]+$"
      assert schema["properties"]["signedTransaction"]["pattern"] == "^0x[a-fA-F0-9]+$"
      assert schema["properties"]["version"]["pattern"] == "^[0-9]+(\\.[0-9]+)*$"
    end

    test "round-trips through JSON" do
      assert {:ok, json} = Jason.encode(ERC20ApprovalGasSponsoring.build_extension())
      assert {:ok, _decoded} = Jason.decode(json)
    end
  end

  describe "build_info/1" do
    test "produces spec-shaped info with defaults" do
      assert {:ok, info} =
               ERC20ApprovalGasSponsoring.build_info(
                 from: @from,
                 asset: @contract,
                 signed_transaction: @signed_tx
               )

      assert info == @valid_info
      assert ERC20ApprovalGasSponsoring.validate_info(info) == :ok
    end

    test "honors amount and spender overrides, normalizing integers" do
      spender = "0x3333333333333333333333333333333333333333"

      assert {:ok, info} =
               ERC20ApprovalGasSponsoring.build_info(
                 from: @from,
                 asset: @contract,
                 signed_transaction: @signed_tx,
                 amount: 10_000,
                 spender: spender
               )

      assert info["amount"] == "10000"
      assert info["spender"] == spender
    end

    test "rejects malformed fields with structured errors" do
      base = [from: @from, asset: @contract, signed_transaction: @signed_tx]

      assert ERC20ApprovalGasSponsoring.build_info(Keyword.put(base, :from, "0x123")) ==
               {:error, {:invalid_info_field, "from"}}

      assert ERC20ApprovalGasSponsoring.build_info(Keyword.put(base, :asset, "nope")) ==
               {:error, {:invalid_info_field, "asset"}}

      assert ERC20ApprovalGasSponsoring.build_info(Keyword.put(base, :spender, "0xdead")) ==
               {:error, {:invalid_info_field, "spender"}}

      assert ERC20ApprovalGasSponsoring.build_info(Keyword.put(base, :amount, "10.5")) ==
               {:error, {:invalid_info_field, "amount"}}

      assert ERC20ApprovalGasSponsoring.build_info(
               Keyword.put(base, :signed_transaction, "not-hex")
             ) == {:error, {:invalid_info_field, "signedTransaction"}}
    end

    test "requires from, asset, and signed_transaction" do
      assert_raise NimbleOptions.ValidationError, fn ->
        ERC20ApprovalGasSponsoring.build_info(from: @from, asset: @contract)
      end
    end
  end

  describe "put_info/2" do
    test "creates the extensions entry when absent" do
      payload = ERC20ApprovalGasSponsoring.put_info(%{"payload" => %{}}, @valid_info)

      assert payload["extensions"]["erc20ApprovalGasSponsoring"] == %{"info" => @valid_info}
    end

    test "preserves the echoed server declaration, server fields winning" do
      declaration = ERC20ApprovalGasSponsoring.build_extension()

      payload = %{
        "payload" => %{},
        "extensions" => %{"erc20ApprovalGasSponsoring" => declaration}
      }

      enriched = ERC20ApprovalGasSponsoring.put_info(payload, @valid_info)
      extension = enriched["extensions"]["erc20ApprovalGasSponsoring"]

      assert extension["schema"] == declaration["schema"]
      assert extension["info"]["description"] == declaration["info"]["description"]
      assert extension["info"]["version"] == declaration["info"]["version"]
      assert extension["info"]["signedTransaction"] == @signed_tx
    end
  end

  describe "extract_info/1" do
    test "returns the info from a payment payload" do
      payload = ERC20ApprovalGasSponsoring.put_info(%{"payload" => %{}}, @valid_info)

      assert ERC20ApprovalGasSponsoring.extract_info(payload) == {:ok, @valid_info}
    end

    test "rejects payloads without the extension" do
      assert ERC20ApprovalGasSponsoring.extract_info(%{}) == {:error, :extension_missing}

      assert ERC20ApprovalGasSponsoring.extract_info(%{"extensions" => %{}}) ==
               {:error, :extension_missing}

      assert ERC20ApprovalGasSponsoring.extract_info(%{
               "extensions" => %{"erc20ApprovalGasSponsoring" => %{"info" => "nope"}}
             }) == {:error, :extension_missing}

      assert ERC20ApprovalGasSponsoring.extract_info("nope") == {:error, :extension_missing}
    end

    test "rejects info with missing or empty fields" do
      for field <- ~w(from asset spender amount signedTransaction version) do
        payload =
          ERC20ApprovalGasSponsoring.put_info(%{"payload" => %{}}, Map.delete(@valid_info, field))

        assert ERC20ApprovalGasSponsoring.extract_info(payload) ==
                 {:error, {:missing_info_field, field}}
      end

      payload =
        ERC20ApprovalGasSponsoring.put_info(%{"payload" => %{}}, %{
          @valid_info
          | "signedTransaction" => ""
        })

      assert ERC20ApprovalGasSponsoring.extract_info(payload) ==
               {:error, {:missing_info_field, "signedTransaction"}}
    end
  end

  describe "validate_info/1" do
    test "accepts the spec's example info" do
      assert ERC20ApprovalGasSponsoring.validate_info(@valid_info) == :ok
    end

    test "rejects malformed fields" do
      cases = [
        {"from", "0x123"},
        {"asset", "not-an-address"},
        {"spender", 42},
        {"amount", "1e18"},
        {"signedTransaction", "abcdef"},
        {"version", "one"}
      ]

      for {field, value} <- cases do
        assert ERC20ApprovalGasSponsoring.validate_info(%{@valid_info | field => value}) ==
                 {:error, {:invalid_info_field, field}}
      end
    end

    test "rejects missing fields and non-maps" do
      assert ERC20ApprovalGasSponsoring.validate_info(Map.delete(@valid_info, "amount")) ==
               {:error, {:missing_info_field, "amount"}}

      assert ERC20ApprovalGasSponsoring.validate_info(nil) == {:error, :extension_missing}
    end
  end

  describe "enricher/1" do
    test "attaches the extension when the server advertises it" do
      payment_required = %{
        "x402Version" => 2,
        "accepts" => [@requirements],
        "extensions" => %{
          "erc20ApprovalGasSponsoring" => ERC20ApprovalGasSponsoring.build_extension()
        }
      }

      payload = %{
        "x402Version" => 2,
        "accepted" => @requirements,
        "payload" => %{},
        "extensions" => payment_required["extensions"]
      }

      enricher =
        ERC20ApprovalGasSponsoring.enricher(from: @from, signed_transaction: @signed_tx)

      assert {:ok, enriched} = enricher.(payload, payment_required)
      assert {:ok, info} = ERC20ApprovalGasSponsoring.extract_info(enriched)
      assert ERC20ApprovalGasSponsoring.validate_info(info) == :ok

      # asset defaulted from the accepted requirements
      assert info["asset"] == @contract
      assert info["amount"] == @max_uint256
    end

    test "honors an explicit asset" do
      other_asset = "0x4444444444444444444444444444444444444444"

      payment_required = %{
        "accepts" => [@requirements],
        "extensions" => %{
          "erc20ApprovalGasSponsoring" => ERC20ApprovalGasSponsoring.build_extension()
        }
      }

      payload = %{"accepted" => @requirements, "payload" => %{}}

      enricher =
        ERC20ApprovalGasSponsoring.enricher(
          from: @from,
          asset: other_asset,
          signed_transaction: @signed_tx
        )

      assert {:ok, enriched} = enricher.(payload, payment_required)
      assert {:ok, info} = ERC20ApprovalGasSponsoring.extract_info(enriched)
      assert info["asset"] == other_asset
    end

    test "passes the payload through when the extension is not advertised" do
      payload = %{"accepted" => @requirements, "payload" => %{}}

      enricher =
        ERC20ApprovalGasSponsoring.enricher(from: @from, signed_transaction: @signed_tx)

      assert enricher.(payload, %{"accepts" => [@requirements]}) == {:ok, payload}
      assert enricher.(payload, nil) == {:ok, payload}
    end

    test "returns structured errors for unusable requirements or fields" do
      payment_required = %{
        "accepts" => [],
        "extensions" => %{
          "erc20ApprovalGasSponsoring" => ERC20ApprovalGasSponsoring.build_extension()
        }
      }

      no_asset = %{"accepted" => Map.delete(@requirements, "asset"), "payload" => %{}}

      enricher =
        ERC20ApprovalGasSponsoring.enricher(from: @from, signed_transaction: @signed_tx)

      assert enricher.(no_asset, payment_required) == {:error, :invalid_requirements}

      bad_tx =
        ERC20ApprovalGasSponsoring.enricher(from: @from, signed_transaction: "not-hex")

      assert bad_tx.(%{"accepted" => @requirements, "payload" => %{}}, payment_required) ==
               {:error, {:invalid_info_field, "signedTransaction"}}
    end
  end
end
