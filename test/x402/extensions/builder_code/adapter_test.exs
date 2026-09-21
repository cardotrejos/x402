defmodule X402.Extensions.BuilderCode.AdapterTest do
  use ExUnit.Case, async: true
  doctest X402.Extensions.BuilderCode.Adapter

  alias X402.Extensions.BuilderCode
  alias X402.Extensions.BuilderCode.Adapter
  alias X402.Hooks.RequestContext

  test "init/1 requires a well-formed app code and caps service codes" do
    assert {:error, message} = Adapter.init([])
    assert message =~ ":app_code"

    assert {:error, message} =
             Adapter.init(app_code: "app", service_codes: Enum.map(1..6, &"s#{&1}"))

    assert message =~ "too many service codes"

    assert {:ok, opts} = Adapter.init(app_code: "app", service_codes: "sdk")
    assert opts[:service_codes] == ["sdk"]
  end

  test "advertise/2 and validate/3 mirror the extension module" do
    {:ok, opts} = Adapter.init(app_code: "app", service_codes: ["sdk"])
    context = RequestContext.new(transport: :http)

    advertised = Adapter.advertise(opts, context)
    assert advertised == BuilderCode.extension("app", service_codes: ["sdk"])

    assert :ok = Adapter.validate(%{"info" => %{"a" => "app", "s" => ["c"]}}, advertised, opts)

    assert {:error, :builder_code_mismatch} =
             Adapter.validate(%{"a" => "other"}, advertised, opts)

    assert :ok = Adapter.validate(nil, advertised, opts)
  end
end
