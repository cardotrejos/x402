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

defmodule X402.ClientTest.ScriptedHooks do
  @moduledoc false
  # Hooks whose behaviour each test scripts through the process dictionary
  # (hooks run in the calling process). Every invocation is reported back.
  @behaviour X402.Client.Hooks

  @impl X402.Client.Hooks
  def before_payment(context, metadata), do: run(:before_payment, context, metadata)

  @impl X402.Client.Hooks
  def after_payment(context, metadata), do: run(:after_payment, context, metadata)

  @impl X402.Client.Hooks
  def on_payment_failure(context, metadata), do: run(:on_payment_failure, context, metadata)

  defp run(callback, context, metadata) do
    send(self(), {:hook, callback, context, metadata})

    case Process.get({:hook_script, callback}) do
      nil -> {:cont, context}
      script -> script.(context, metadata)
    end
  end
end

defmodule X402.ClientTest do
  use ExUnit.Case, async: true

  doctest X402.Client

  alias X402.Client
  alias X402.Client.Hooks.Context
  alias X402.Client.Policy
  alias X402.ClientTest.ScriptedHooks
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

    test "skips entries whose paymentFlow is not recognized" do
      upfront = put_in(@evm_requirements, ["extra", "paymentFlow"], "upfront")
      escrow = put_in(@evm_requirements, ["extra", "paymentFlow"], "escrow")
      bogus = put_in(@evm_requirements, ["extra", "paymentFlow"], 42)
      payment_required = %{"accepts" => [upfront, escrow, bogus, @evm_requirements]}

      assert Client.select_requirements(payment_required) == {:ok, @evm_requirements}

      assert Client.select_requirements([upfront, escrow]) ==
               {:error, :no_acceptable_requirements}
    end

    test "accepts an explicit authorization paymentFlow" do
      explicit = put_in(@evm_requirements, ["extra", "paymentFlow"], "authorization")

      assert Client.select_requirements([explicit]) == {:ok, explicit}
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

    test "policies filter the signable candidates in order" do
      cheap = Map.put(@evm_requirements, "amount", "100")
      payment_required = %{"accepts" => [@evm_requirements, cheap]}
      test_pid = self()

      seen = fn requirements, seen_payment_required ->
        send(test_pid, {:policy, requirements["amount"], seen_payment_required})
        true
      end

      assert Client.select_requirements(payment_required,
               policies: [seen, Policy.max_amount("500")]
             ) == {:ok, cheap}

      assert_received {:policy, "10000", ^payment_required}
      assert_received {:policy, "100", ^payment_required}

      # Bare lists pass nil as the payment_required.
      assert Client.select_requirements([cheap], policies: [seen]) == {:ok, cheap}
      assert_received {:policy, "100", nil}

      assert Client.select_requirements(payment_required,
               policies: [Policy.networks(["solana:*"])]
             ) == {:error, :no_acceptable_requirements}
    end

    test "policies only see entries this client could sign" do
      test_pid = self()

      seen = fn requirements, _payment_required ->
        send(test_pid, {:policy, requirements})
        true
      end

      payment_required = %{"accepts" => [@solana_requirements, @evm_requirements]}

      assert Client.select_requirements(payment_required, policies: [seen]) ==
               {:ok, @evm_requirements}

      assert_received {:policy, @evm_requirements}
      refute_received {:policy, @solana_requirements}
    end

    test "a policy returning {:error, reason} aborts selection with that reason" do
      cheap = Map.put(@evm_requirements, "amount", "100")
      budget = fn _requirements, _payment_required -> {:error, {:budget_exceeded, :daily}} end

      assert Client.select_requirements([@evm_requirements, cheap], policies: [budget]) ==
               {:error, {:budget_exceeded, :daily}}

      invalid = fn _requirements, _payment_required -> :maybe end

      assert Client.select_requirements([@evm_requirements], policies: [invalid]) ==
               {:error, {:invalid_policy_result, :maybe}}

      assert_raise NimbleOptions.ValidationError, fn ->
        Client.select_requirements([@evm_requirements], policies: [fn _one -> true end])
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

    test "produces a spec-format payment-identifier echo end to end" do
      alias X402.Extensions.PaymentIdentifier

      advertised = %{"payment-identifier" => PaymentIdentifier.extension(required: true)}
      payment_required = Map.put(@payment_required, "extensions", advertised)

      assert {:ok, payload} =
               Client.build_payment(payment_required, signer(),
                 extensions: [PaymentIdentifier.enricher()]
               )

      declaration = payload["extensions"]["payment-identifier"]
      assert declaration["schema"] == PaymentIdentifier.schema()
      assert declaration["info"]["required"] == true
      assert {:ok, {:spec, id}} = PaymentIdentifier.extract_id(payload["extensions"])
      assert declaration["info"]["id"] == id
      assert PaymentRequirements.extensions_match?(advertised, payload["extensions"])

      # Not advertised: the payload is untouched.
      assert {:ok, plain} =
               Client.build_payment(@payment_required, signer(),
                 extensions: [PaymentIdentifier.enricher()]
               )

      assert plain["extensions"] == %{}
    end
  end

  describe "build_payment/3 :hooks" do
    setup do
      {:ok, signer: signer()}
    end

    test "runs before and after hooks with the context and metadata", %{signer: signer} do
      assert {:ok, payload} =
               Client.build_payment(@payment_required, signer,
                 hooks: ScriptedHooks,
                 max_amount: "10000"
               )

      assert_received {:hook, :before_payment, %Context{} = before, metadata}
      assert before.payment_required == @payment_required
      assert before.requirements == @evm_requirements
      assert before.opts[:max_amount] == "10000"
      assert before.payload == nil

      assert metadata == %{
               operation: :build_payment,
               hook_module: ScriptedHooks,
               scheme: "exact",
               network: "eip155:84532"
             }

      assert_received {:hook, :after_payment, %Context{payload: ^payload}, _metadata}
      refute_received {:hook, :on_payment_failure, _context, _metadata}
    end

    test "before_payment may replace the selected requirements", %{signer: signer} do
      cheap = Map.put(@evm_requirements, "amount", "100")

      Process.put({:hook_script, :before_payment}, fn context, _metadata ->
        {:cont, %{context | requirements: cheap}}
      end)

      assert {:ok, payload} =
               Client.build_payment(@payment_required, signer, hooks: ScriptedHooks)

      assert payload["accepted"] == cheap
      assert payload["payload"]["authorization"]["value"] == "100"
    end

    test "before_payment may halt", %{signer: signer} do
      Process.put({:hook_script, :before_payment}, fn _context, _metadata ->
        {:halt, :too_expensive}
      end)

      assert Client.build_payment(@payment_required, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_halted, :before_payment, :too_expensive}}

      refute_received {:hook, :after_payment, _context, _metadata}
      refute_received {:hook, :on_payment_failure, _context, _metadata}
    end

    test "after_payment may replace the payload", %{signer: signer} do
      Process.put({:hook_script, :after_payment}, fn context, _metadata ->
        {:cont, %{context | payload: Map.put(context.payload, "tagged", true)}}
      end)

      assert {:ok, payload} =
               Client.build_payment(@payment_required, signer, hooks: ScriptedHooks)

      assert payload["tagged"] == true
    end

    test "on_payment_failure sees the error and may replace it or recover", %{signer: signer} do
      missing_domain = Map.put(@evm_requirements, "extra", %{})

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:error, {:missing_extra, "name"}}

      assert_received {:hook, :on_payment_failure,
                       %Context{error: {:missing_extra, "name"}} = ctx, _}

      assert ctx.payment_required == nil
      refute_received {:hook, :after_payment, _context, _metadata}

      Process.put({:hook_script, :on_payment_failure}, fn context, _metadata ->
        {:cont, %{context | error: :rewritten}}
      end)

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:error, :rewritten}

      recovered = %{"x402Version" => 2, "accepted" => missing_domain, "payload" => %{}}

      Process.put({:hook_script, :on_payment_failure}, fn _context, _metadata ->
        {:recover, recovered}
      end)

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:ok, recovered}
    end

    test "selection failures return before any hook runs", %{signer: signer} do
      assert Client.build_payment(@payment_required, signer,
               hooks: ScriptedHooks,
               max_amount: "1"
             ) == {:error, :no_acceptable_requirements}

      refute_received {:hook, _callback, _context, _metadata}
    end

    test "invalid returns are reported per callback", %{signer: signer} do
      Process.put({:hook_script, :before_payment}, fn _context, _metadata -> :ok end)

      assert Client.build_payment(@payment_required, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_invalid_return, :before_payment, :ok}}

      Process.put({:hook_script, :before_payment}, fn context, _metadata ->
        {:cont, %{context | requirements: "nope"}}
      end)

      assert {:error, {:hook_invalid_return, :before_payment, {:cont, %Context{}}}} =
               Client.build_payment(@payment_required, signer, hooks: ScriptedHooks)

      Process.delete({:hook_script, :before_payment})

      Process.put({:hook_script, :after_payment}, fn context, _metadata ->
        {:cont, %{context | payload: nil}}
      end)

      assert {:error, {:hook_invalid_return, :after_payment, {:cont, %Context{}}}} =
               Client.build_payment(@payment_required, signer, hooks: ScriptedHooks)

      Process.put({:hook_script, :after_payment}, fn _context, _metadata -> {:halt, :no} end)

      assert Client.build_payment(@payment_required, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_invalid_return, :after_payment, {:halt, :no}}}

      Process.delete({:hook_script, :after_payment})
      missing_domain = Map.put(@evm_requirements, "extra", %{})

      Process.put({:hook_script, :on_payment_failure}, fn _context, _metadata ->
        {:recover, "payload"}
      end)

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:error,
                {:hook_invalid_return, :on_payment_failure, {:invalid_recovery_result, "payload"}}}

      Process.put({:hook_script, :on_payment_failure}, fn _context, _metadata -> :ignored end)

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_invalid_return, :on_payment_failure, :ignored}}
    end

    test "exceptions and exits inside hooks become hook_callback_failed", %{signer: signer} do
      Process.put({:hook_script, :before_payment}, fn _context, _metadata ->
        raise ArgumentError, "boom"
      end)

      assert {:error, {:hook_callback_failed, :before_payment, {:exception, %ArgumentError{}}}} =
               Client.build_payment(@payment_required, signer, hooks: ScriptedHooks)

      Process.delete({:hook_script, :before_payment})
      Process.put({:hook_script, :after_payment}, fn _context, _metadata -> throw(:away) end)

      assert Client.build_payment(@payment_required, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_callback_failed, :after_payment, {:throw, :away}}}

      Process.delete({:hook_script, :after_payment})
      missing_domain = Map.put(@evm_requirements, "extra", %{})
      Process.put({:hook_script, :on_payment_failure}, fn _context, _metadata -> exit(:bye) end)

      assert Client.build_payment(missing_domain, signer, hooks: ScriptedHooks) ==
               {:error, {:hook_callback_failed, :on_payment_failure, {:exit, :bye}}}
    end

    test "rejects modules that do not implement the behaviour", %{signer: signer} do
      assert_raise NimbleOptions.ValidationError, ~r/X402.Client.Hooks/, fn ->
        Client.build_payment(@payment_required, signer, hooks: Enum)
      end
    end
  end

  describe "encode_payment/1" do
    test "returns invalid_json for unencodable payloads" do
      assert Client.encode_payment(%{"pid" => self()}) == {:error, :invalid_json}
    end
  end
end
