defmodule FacilitatorExample.Application do
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    engine = FacilitatorExample.engine!()
    port = FacilitatorExample.port()

    children = [
      {Finch,
       name: FacilitatorExample.finch_name(),
       pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}},
      {X402.Facilitator.NonceManager, name: FacilitatorExample.NonceManager},
      {Bandit, plug: {X402.Plug.Facilitator, engine: engine}, port: port}
    ]

    {:ok, address} = X402.Signer.address(engine.signer)
    Logger.info("x402 facilitator listening on http://localhost:#{port} (fee payer #{address})")

    Supervisor.start_link(children, strategy: :one_for_one, name: FacilitatorExample.Supervisor)
  end
end
