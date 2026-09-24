defmodule X402.Extensions.PaymentIdentifier.AdapterTest do
  use ExUnit.Case, async: true
  doctest X402.Extensions.PaymentIdentifier.Adapter

  alias X402.Extensions.PaymentIdentifier
  alias X402.Extensions.PaymentIdentifier.Adapter
  alias X402.Hooks.RequestContext

  test "advertise/2 builds the spec declaration with the configured flag" do
    context = RequestContext.new(transport: :http)

    assert Adapter.advertise([], context) == PaymentIdentifier.extension(required: false)

    assert Adapter.advertise([required: true], context) ==
             PaymentIdentifier.extension(required: true)

    assert PaymentIdentifier.required?(%{
             Adapter.key() => Adapter.advertise([required: true], context)
           })
  end

  test "init/1 rejects unknown options" do
    assert {:error, message} = Adapter.init(nope: 1)
    assert message =~ ":nope"
  end
end
