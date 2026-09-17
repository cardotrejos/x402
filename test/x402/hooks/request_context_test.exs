defmodule X402.Hooks.RequestContextTest do
  use ExUnit.Case, async: true
  doctest X402.Hooks.RequestContext

  alias X402.Hooks.RequestContext

  test "new/1 defaults every field" do
    assert %RequestContext{
             transport: :http,
             conn: nil,
             request: nil,
             route: nil,
             method: nil,
             path: nil,
             path_params: %{},
             tool: nil,
             requirements: [],
             extensions: %{},
             payload: nil,
             matched_requirements: nil
           } = RequestContext.new([])
  end

  test "valid?/1 requires a non-empty list of requirement maps and an extensions map" do
    valid = RequestContext.new(requirements: [%{"scheme" => "exact"}], extensions: %{})
    assert RequestContext.valid?(valid)

    refute RequestContext.valid?(%{valid | requirements: [%{}, :nope]})
    refute RequestContext.valid?(%{valid | requirements: %{}})
    refute RequestContext.valid?(%{valid | extensions: []})
    refute RequestContext.valid?(nil)
  end
end
