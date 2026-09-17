defmodule X402.Extensions.HTTPMessageSignatures.AdapterTest do
  use ExUnit.Case, async: true

  @moduletag :capture_log

  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.HTTPMessageSignatures
  alias X402.Extensions.HTTPMessageSignatures.Adapter
  alias X402.Hooks.RequestContext
  alias X402.PaymentRequired
  alias X402.Plug.PaymentGate

  doctest X402.Extensions.HTTPMessageSignatures.Adapter

  @opts [
    registration_url: "https://network.example.com/signature-agents",
    signature_schemes: ["ed25519"],
    tags: ["web-bot-auth"]
  ]

  @route %{
    method: :get,
    path: "/api/resource",
    price: "10000",
    network: "eip155:84532",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    pay_to: "0x1111111111111111111111111111111111111111"
  }

  test "key/0 is the extension key" do
    assert Adapter.key() == HTTPMessageSignatures.extension_key()
  end

  test "init/1 builds the advertisement and reports invalid options" do
    assert {:ok, opts} = Adapter.init(@opts)
    assert opts[:extension] == HTTPMessageSignatures.extension(@opts)

    assert {:ok, opts} = Adapter.init(Keyword.put(@opts, :include_schema, false))
    refute Map.has_key?(opts[:extension], "schema")

    assert {:error, message} = Adapter.init([])
    assert message =~ ":registration_url"

    assert {:error, message} = Adapter.init(Keyword.put(@opts, :signature_schemes, []))
    assert message =~ "signature schemes"

    assert {:error, message} = Adapter.init(Keyword.put(@opts, :nope, 1))
    assert message =~ ":nope"
  end

  test "advertise/2 returns the same declaration for every request" do
    {:ok, opts} = Adapter.init(@opts)

    for context <- [
          RequestContext.new([]),
          RequestContext.new(requirements: [%{}], transport: :mcp)
        ] do
      assert Adapter.advertise(opts, context) == HTTPMessageSignatures.extension(@opts)
    end
  end

  test "advertises through the payment gate and decodes on the client side" do
    options =
      PaymentGate.init(routes: [@route], facilitator: self(), extensions: [{Adapter, @opts}])

    conn = PaymentGate.call(conn(:get, "/api/resource"), options)
    assert conn.status == 402

    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payment_required} = PaymentRequired.decode(header)

    assert payment_required["extensions"]["http-message-signatures"] ==
             HTTPMessageSignatures.extension(@opts)

    assert {:ok,
            %{
              registration_url: "https://network.example.com/signature-agents",
              signature_schemes: ["ed25519"],
              tags: ["web-bot-auth"]
            }} = HTTPMessageSignatures.decode(payment_required)
  end
end
