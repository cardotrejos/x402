defmodule X402.ClientTest.BogusSignScheme do
  @moduledoc false
  # A scheme whose sign/3 breaks the contract by returning a bare term.
  @behaviour X402.Scheme

  @impl X402.Scheme
  def scheme, do: "exact"

  @impl X402.Scheme
  def networks, do: ["eip155:*"]

  @impl X402.Scheme
  def signable?(_requirements), do: true

  @impl X402.Scheme
  def sign(_requirements, _signer, _opts), do: :bogus
end

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

    test "filters out entries missing the filtered field" do
      no_network = Map.delete(@evm_requirements, "network")

      assert Client.select_requirements([no_network], network: "eip155:*") ==
               {:error, :no_acceptable_requirements}

      no_asset = Map.delete(@evm_requirements, "asset")

      assert Client.select_requirements([no_asset], asset: @contract) ==
               {:error, :no_acceptable_requirements}

      bad_amount = Map.put(@evm_requirements, "amount", "not-a-number")

      assert Client.select_requirements([bad_amount], max_amount: 10_000) ==
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
      cash = Map.put(@evm_requirements, "scheme", "cash")

      assert Client.build_payment(cash, signer()) ==
               {:error, {:unsupported_kind, "cash", "eip155:84532"}}

      bitcoin = Map.put(@evm_requirements, "network", "bip122:000000000019d6689c085ae165831e93")

      assert Client.build_payment(bitcoin, signer()) ==
               {:error, {:unsupported_kind, "exact", "bip122:000000000019d6689c085ae165831e93"}}
    end

    test "solana requirements without extra.feePayer fail signing" do
      assert Client.build_payment(@solana_requirements, signer()) ==
               {:error, :missing_fee_payer}
    end

    test "signs upto requirements via Permit2 when extra carries facilitatorAddress" do
      upto =
        @evm_requirements
        |> Map.put("scheme", "upto")
        |> put_in(
          ["extra", "facilitatorAddress"],
          "0x2222222222222222222222222222222222222222"
        )

      assert {:ok, payload} = Client.build_payment(upto, signer())
      assert payload["accepted"] == upto

      assert %{"signature" => "0x" <> _, "permit2Authorization" => authorization} =
               payload["payload"]

      assert authorization["permitted"]["amount"] == upto["amount"]

      assert authorization["witness"]["facilitator"] ==
               "0x2222222222222222222222222222222222222222"

      # Without the facilitator address, the upto scheme cannot sign.
      assert Client.build_payment(Map.put(upto, "extra", %{}), signer()) ==
               {:error, {:missing_extra, "facilitatorAddress"}}
    end

    test "propagates signing errors for bare requirements" do
      missing_domain = Map.put(@evm_requirements, "extra", %{})

      assert Client.build_payment(missing_domain, signer()) ==
               {:error, {:missing_extra, "name"}}
    end

    test "rejects malformed input" do
      assert Client.build_payment("nope", signer()) == {:error, :invalid_payment_required}
    end

    test "rejects a scheme module whose sign/3 returns a bare term" do
      assert Client.build_payment(@evm_requirements, signer(),
               schemes: [X402.ClientTest.BogusSignScheme]
             ) == {:error, {:invalid_scheme_payload, :bogus}}
    end

    test "drops non-map resource and extensions echoes" do
      payment_required =
        @payment_required
        |> Map.put("resource", "https://api.example.com/paid")
        |> Map.put("extensions", "nope")

      assert {:ok, payload} = Client.build_payment(payment_required, signer())
      refute Map.has_key?(payload, "resource")
      refute Map.has_key?(payload, "extensions")
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

  describe "build_payment/3 :extensions" do
    test "applies enrichers in order with the original payment_required" do
      test_pid = self()

      first = fn payload, payment_required ->
        send(test_pid, {:first, payment_required})
        {:ok, Map.put(payload, "first", true)}
      end

      second = fn payload, _payment_required ->
        assert payload["first"] == true
        {:ok, Map.put(payload, "second", true)}
      end

      assert {:ok, payload} =
               Client.build_payment(@payment_required, signer(), extensions: [first, second])

      assert payload["first"] == true
      assert payload["second"] == true
      assert_received {:first, @payment_required}
    end

    test "passes nil as payment_required for bare requirements" do
      test_pid = self()

      enricher = fn payload, payment_required ->
        send(test_pid, {:enriched, payment_required})
        {:ok, payload}
      end

      assert {:ok, _payload} =
               Client.build_payment(@evm_requirements, signer(), extensions: [enricher])

      assert_received {:enriched, nil}
    end

    test "propagates enricher errors and rejects invalid returns" do
      failing = fn _payload, _payment_required -> {:error, :nope} end

      assert Client.build_payment(@payment_required, signer(), extensions: [failing]) ==
               {:error, :nope}

      invalid = fn _payload, _payment_required -> :what end

      assert Client.build_payment(@payment_required, signer(), extensions: [invalid]) ==
               {:error, {:invalid_extension_result, :what}}
    end

    test "produces a valid eip2612GasSponsoring extension end to end" do
      alias X402.Extensions.EIP2612GasSponsoring

      signer = signer()

      payment_required =
        Map.put(@payment_required, "extensions", %{
          "eip2612GasSponsoring" => EIP2612GasSponsoring.build_extension()
        })

      assert {:ok, payload} =
               Client.build_payment(payment_required, signer,
                 extensions: [EIP2612GasSponsoring.enricher(signer, nonce: "0")]
               )

      # the scheme payload and echo are untouched
      assert PaymentRequirements.validate(payload["accepted"]) == :ok
      assert %{"signature" => _, "authorization" => _} = payload["payload"]

      extension = payload["extensions"]["eip2612GasSponsoring"]
      assert extension["schema"] == EIP2612GasSponsoring.schema()

      assert {:ok, info} = EIP2612GasSponsoring.extract_info(payload)
      assert EIP2612GasSponsoring.validate_info(info) == :ok
      assert info["from"] == signer.address
      assert info["asset"] == @contract

      # header round-trip keeps the extension intact
      {:ok, header} = Client.encode_payment(payload)
      assert PaymentSignature.decode(header) == {:ok, payload}
    end

    test "eip2612 enricher is a no-op when the server does not advertise it" do
      alias X402.Extensions.EIP2612GasSponsoring

      signer = signer()

      assert {:ok, payload} =
               Client.build_payment(@payment_required, signer,
                 extensions: [EIP2612GasSponsoring.enricher(signer, nonce: "0")]
               )

      assert payload["extensions"] == %{}
    end
  end

  describe "encode_payment/1" do
    test "returns invalid_json for unencodable payloads" do
      assert Client.encode_payment(%{"pid" => self()}) == {:error, :invalid_json}
    end
  end
end
