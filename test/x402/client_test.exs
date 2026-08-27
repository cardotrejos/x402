defmodule X402.ClientTest do
  use ExUnit.Case, async: true

  doctest X402.Client

  alias X402.Client
  alias X402.PaymentRequirements
  alias X402.PaymentSignature
  alias X402.Signer.LocalKey

  @receiver "0x2222222222222222222222222222222222222222"
  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

  @evm_requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  @solana_requirements %{
    "scheme" => "exact",
    "network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "amount" => "10000",
    "asset" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "payTo" => "9xQeWvG816bUx9EPfQmQTYnC16hHhV6bQf8kX6y4YB9",
    "maxTimeoutSeconds" => 300,
    "extra" => %{}
  }

  @payment_required %{
    "x402Version" => 2,
    "error" => "PAYMENT-SIGNATURE header is required",
    "resource" => %{"url" => "https://api.example.com/paid", "mimeType" => "application/json"},
    "accepts" => [@evm_requirements],
    "extensions" => %{}
  }

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  describe "select_requirements/2" do
    test "skips unsupported kinds and picks the first signable entry" do
      payment_required = %{
        "x402Version" => 2,
        "accepts" => [
          @solana_requirements,
          Map.put(@evm_requirements, "scheme", "upto"),
          @evm_requirements
        ]
      }

      assert Client.select_requirements(payment_required) == {:ok, @evm_requirements}
    end

    test "skips entries missing the EIP-712 domain fields" do
      no_domain = Map.put(@evm_requirements, "extra", %{})
      payment_required = %{"accepts" => [no_domain, @evm_requirements]}

      assert Client.select_requirements(payment_required) == {:ok, @evm_requirements}
    end

    test "skips structurally invalid entries and non-map entries" do
      invalid = Map.delete(@evm_requirements, "payTo")
      payment_required = %{"accepts" => ["nope", invalid, @evm_requirements]}

      assert Client.select_requirements(payment_required) == {:ok, @evm_requirements}
    end

    test "accepts a bare list of requirements" do
      assert Client.select_requirements([@evm_requirements]) == {:ok, @evm_requirements}
    end

    test "filters by exact and wildcard network" do
      base = Map.put(@evm_requirements, "network", "eip155:8453")
      testnet = @evm_requirements
      payment_required = %{"accepts" => [base, testnet]}

      assert Client.select_requirements(payment_required, network: "eip155:84532") ==
               {:ok, testnet}

      assert Client.select_requirements(payment_required, network: "eip155:*") == {:ok, base}

      assert Client.select_requirements(payment_required, network: "eip155:1") ==
               {:error, :no_acceptable_requirements}
    end

    test "filters by scheme" do
      upto = Map.put(@evm_requirements, "scheme", "upto")
      payment_required = %{"accepts" => [upto, @evm_requirements]}

      assert Client.select_requirements(payment_required, scheme: "exact") ==
               {:ok, @evm_requirements}

      # The only upto entry is filtered in but cannot be signed.
      assert Client.select_requirements(%{"accepts" => [upto]}, scheme: "upto") ==
               {:error, :no_acceptable_requirements}
    end

    test "filters by asset, case-insensitively" do
      assert Client.select_requirements([@evm_requirements],
               asset: String.downcase(@contract)
             ) == {:ok, @evm_requirements}

      assert Client.select_requirements([@evm_requirements], asset: "0xother") ==
               {:error, :no_acceptable_requirements}
    end

    test "filters by max_amount as budget guard" do
      cheap = Map.put(@evm_requirements, "amount", "100")
      payment_required = %{"accepts" => [@evm_requirements, cheap]}

      assert Client.select_requirements(payment_required, max_amount: "500") == {:ok, cheap}
      assert Client.select_requirements(payment_required, max_amount: 500) == {:ok, cheap}

      assert Client.select_requirements(payment_required, max_amount: 10_000) ==
               {:ok, @evm_requirements}

      assert Client.select_requirements(payment_required, max_amount: 50) ==
               {:error, :no_acceptable_requirements}
    end

    test "returns structured errors for malformed input" do
      assert Client.select_requirements(%{"accepts" => "nope"}) ==
               {:error, :invalid_payment_required}

      assert Client.select_requirements("nope") == {:error, :invalid_payment_required}

      assert Client.select_requirements(%{"accepts" => []}) ==
               {:error, :no_acceptable_requirements}
    end

    test "raises on invalid options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        Client.select_requirements(@payment_required, network: 123)
      end
    end
  end

  describe "build_payment/3" do
    test "builds a v2 payload echoing the full requirements, resource, and extensions" do
      payment_required =
        Map.put(@payment_required, "extensions", %{
          "example" => %{"info" => %{"required" => true}, "schema" => %{}}
        })

      signer = signer()

      assert {:ok, payload} = Client.build_payment(payment_required, signer)

      assert payload["x402Version"] == 2
      assert payload["accepted"] == @evm_requirements
      assert payload["resource"] == payment_required["resource"]
      assert payload["extensions"] == payment_required["extensions"]

      assert %{"signature" => "0x" <> _hex, "authorization" => authorization} =
               payload["payload"]

      assert authorization["from"] == signer.address
      assert authorization["to"] == @receiver
      assert authorization["value"] == "10000"
    end

    test "round-trips through the validation side of this library" do
      signer = signer()

      assert {:ok, payload} = Client.build_payment(@payment_required, signer)
      assert {:ok, header} = Client.encode_payment(payload)

      # Prove self-interop: the server-side validator accepts what we built.
      assert {:ok, decoded} = PaymentSignature.decode_and_validate(header, @evm_requirements)
      assert decoded == payload

      # And the extension echo passes the same check the gate applies.
      assert PaymentRequirements.extensions_match?(
               @payment_required["extensions"],
               payload["extensions"]
             )
    end

    test "omits resource and extensions when the server sent none" do
      payment_required = Map.drop(@payment_required, ["resource", "extensions"])

      assert {:ok, payload} = Client.build_payment(payment_required, signer())
      refute Map.has_key?(payload, "resource")
      refute Map.has_key?(payload, "extensions")
    end

    test "accepts a single requirements map, skipping selection" do
      assert {:ok, payload} = Client.build_payment(@evm_requirements, signer())

      assert payload["accepted"] == @evm_requirements
      refute Map.has_key?(payload, "resource")
      refute Map.has_key?(payload, "extensions")
    end

    test "applies selection filters" do
      cheap = Map.put(@evm_requirements, "amount", "100")
      payment_required = Map.put(@payment_required, "accepts", [@evm_requirements, cheap])

      assert {:ok, payload} = Client.build_payment(payment_required, signer(), max_amount: 500)
      assert payload["accepted"] == cheap

      assert Client.build_payment(payment_required, signer(), max_amount: 50) ==
               {:error, :no_acceptable_requirements}
    end

    test "returns unsupported_kind for schemes and networks it cannot sign" do
      upto = Map.put(@evm_requirements, "scheme", "upto")

      assert Client.build_payment(upto, signer()) ==
               {:error, {:unsupported_kind, "upto", "eip155:84532"}}

      assert Client.build_payment(@solana_requirements, signer()) ==
               {:error, {:unsupported_kind, "exact", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}}
    end

    test "propagates signing errors for bare requirements" do
      missing_domain = Map.put(@evm_requirements, "extra", %{})

      assert Client.build_payment(missing_domain, signer()) ==
               {:error, {:missing_extra, "name"}}
    end

    test "rejects malformed input" do
      assert Client.build_payment("nope", signer()) == {:error, :invalid_payment_required}
    end

    test "emits telemetry for select, sign, and build" do
      ref = make_ref()
      test_pid = self()

      events = [
        [:x402, :client, :select],
        [:x402, :client, :sign],
        [:x402, :client, :build]
      ]

      :telemetry.attach_many(
        {__MODULE__, ref},
        events,
        fn event, _measurements, metadata, _config ->
          send(test_pid, {:telemetry, event, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach({__MODULE__, ref}) end)

      assert {:ok, _payload} = Client.build_payment(@payment_required, signer())

      assert_received {:telemetry, [:x402, :client, :select], %{status: :ok}}
      assert_received {:telemetry, [:x402, :client, :sign], %{status: :ok}}
      assert_received {:telemetry, [:x402, :client, :build], %{status: :ok}}

      assert {:error, _reason} = Client.build_payment(%{"accepts" => []}, signer())
      assert_received {:telemetry, [:x402, :client, :build], %{status: :error}}
    end
  end

  describe "encode_payment/1" do
    test "returns invalid_json for unencodable payloads" do
      assert Client.encode_payment(%{"pid" => self()}) == {:error, :invalid_json}
    end
  end
end
