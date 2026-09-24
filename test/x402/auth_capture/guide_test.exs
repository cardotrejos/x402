defmodule X402.AuthCapture.GuideTest do
  use ExUnit.Case, async: true
  alias X402.AuthCapture.Resource
  alias X402.TestAuthCaptureNode, as: Node

  @guide Path.expand("../../../guides/auth-capture.md", __DIR__)
  @external_resource @guide
  @examples Regex.scan(~r/```elixir\n(.*?)\n```/s, File.read!(@guide), capture: :all_but_first)
  setup do: Node.setup(__MODULE__)

  test "guide examples parse and documented construction uses actual APIs", ctx do
    for [example] <- @examples do
      assert {:ok, _ast} = Code.string_to_quoted(example)
    end

    [[construction] | _rest] = @examples

    {{:ok, resource}, bindings} =
      Code.eval_string(construction,
        rpc: ctx.engine.rpc,
        gas_signer: ctx.engine.signer,
        receiver_signer: ctx.authorizer,
        store: ctx.engine.journal.store
      )

    assert %Resource{mode: :sync, max_records: 1000} = resource
    assert bindings[:engine].network == "eip155:8453"
    refute_received {:auth_rpc, _, _}
  end
end
