defmodule FacilitatorExample do
  @moduledoc """
  Environment-driven configuration for the example facilitator.

  | Variable      | Default                     | Meaning                          |
  | ------------- | --------------------------- | -------------------------------- |
  | `PRIVATE_KEY` | *(required)*                | Fee-payer secp256k1 key (hex)    |
  | `RPC_URL`     | `https://sepolia.base.org`  | JSON-RPC endpoint                |
  | `NETWORK`     | `eip155:84532`              | CAIP-2 network served            |
  | `PORT`        | `4022`                      | HTTP listen port                 |
  """

  @finch_name FacilitatorExample.Finch

  def finch_name, do: @finch_name

  def port, do: String.to_integer(System.get_env("PORT", "4022"))

  def engine! do
    private_key =
      System.get_env("PRIVATE_KEY") ||
        raise "PRIVATE_KEY environment variable is required"

    {:ok, rpc} =
      X402.RPC.new(
        rpc_url: System.get_env("RPC_URL", "https://sepolia.base.org"),
        finch: @finch_name
      )

    {:ok, signer} = X402.Signer.LocalKey.new(private_key)

    {:ok, engine} =
      X402.Facilitator.Engine.new(
        rpc: rpc,
        signer: signer,
        networks: [System.get_env("NETWORK", "eip155:84532")]
      )

    engine
  end
end
