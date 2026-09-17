defmodule X402.Extensions.AuthHints.AdapterTest do
  use ExUnit.Case, async: true

  @moduletag :capture_log

  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.AuthHints
  alias X402.Extensions.AuthHints.Adapter
  alias X402.Hooks.RequestContext
  alias X402.PaymentRequired
  alias X402.Plug.PaymentGate

  doctest X402.Extensions.AuthHints.Adapter

  @oauth2 AuthHints.oauth2(
            token_type: "DPoP",
            authorization_server: "https://as.example.com",
            token_endpoint: "https://as.example.com/token",
            registration_endpoint: "https://as.example.com/register"
          )

  @route %{
    method: :get,
    path: "/api/resource",
    price: "10000",
    network: "eip155:84532",
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    pay_to: "0x1111111111111111111111111111111111111111"
  }

  test "key/0 is the extension key" do
    assert Adapter.key() == AuthHints.extension_key()
  end

  describe "init/1" do
    test "builds the advertisement once, validating the requirements" do
      assert {:ok, opts} =
               Adapter.init(auth_requirements: [[accept_indexes: [0], methods: [@oauth2]]])

      assert opts[:auth_requirements] ==
               AuthHints.extension([[accept_indexes: [0], methods: [@oauth2]]])
    end

    test "surfaces validation problems as error strings" do
      assert {:error, message} = Adapter.init([])
      assert message =~ ":auth_requirements"

      assert {:error, message} = Adapter.init(auth_requirements: [])
      assert message =~ "non-empty list of auth requirements"

      assert {:error, message} =
               Adapter.init(auth_requirements: [[accept_indexes: [0], methods: [%{"type" => 1}]]])

      assert message =~ ":invalid_method"

      assert {:error, message} =
               Adapter.init(
                 auth_requirements: [[accept_indexes: [0], methods: [@oauth2]]],
                 other: 1
               )

      assert message =~ ":other"
    end
  end

  describe "advertise/2" do
    setup do
      {:ok, opts} =
        Adapter.init(
          auth_requirements: [
            [accept_indexes: [0, 2], methods: [AuthHints.sign_in_with_x()]],
            [accept_indexes: [1], methods: [@oauth2]]
          ]
        )

      %{opts: opts}
    end

    test "keeps every requirement whose indexes fit the offered requirements", %{opts: opts} do
      context = RequestContext.new(requirements: [%{}, %{}, %{}])
      assert Adapter.advertise(opts, context) == opts[:auth_requirements]
    end

    test "drops out-of-range indexes and emptied requirements", %{opts: opts} do
      context = RequestContext.new(requirements: [%{}, %{}])

      assert Adapter.advertise(opts, context)["info"]["authRequirements"] == [
               %{"acceptIndexes" => [0], "methods" => [%{"type" => "sign-in-with-x"}]},
               %{"acceptIndexes" => [1], "methods" => [@oauth2]}
             ]

      context = RequestContext.new(requirements: [%{}])

      assert Adapter.advertise(opts, context)["info"]["authRequirements"] == [
               %{"acceptIndexes" => [0], "methods" => [%{"type" => "sign-in-with-x"}]}
             ]
    end

    test "advertises nothing when no index fits" do
      {:ok, opts} = Adapter.init(auth_requirements: [[accept_indexes: [4], methods: [@oauth2]]])
      assert Adapter.advertise(opts, RequestContext.new(requirements: [%{}])) == nil
    end

    test "advertises the configuration unchanged without requirements", %{opts: opts} do
      assert Adapter.advertise(opts, RequestContext.new([])) == opts[:auth_requirements]
    end
  end

  test "advertises through the payment gate and decodes on the client side" do
    options =
      PaymentGate.init(
        routes: [@route],
        facilitator: self(),
        extensions: [{Adapter, auth_requirements: [[accept_indexes: [0, 3], methods: [@oauth2]]]}]
      )

    conn = PaymentGate.call(conn(:get, "/api/resource"), options)
    assert conn.status == 402

    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payment_required} = PaymentRequired.decode(header)

    assert payment_required["extensions"]["auth-hints"]["info"] == %{
             "authRequirements" => [%{"acceptIndexes" => [0], "methods" => [@oauth2]}]
           }

    assert payment_required["extensions"]["auth-hints"]["schema"] == AuthHints.schema()

    [requirements] = payment_required["accepts"]
    assert AuthHints.methods_for(payment_required, requirements) == [@oauth2]
    assert AuthHints.requires_auth?(payment_required, 0)
  end
end
