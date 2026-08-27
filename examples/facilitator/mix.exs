defmodule FacilitatorExample.MixProject do
  use Mix.Project

  def project do
    [
      app: :x402_facilitator_example,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: false,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {FacilitatorExample.Application, []}
    ]
  end

  defp deps do
    [
      {:x402, path: "../.."},
      {:bandit, "~> 1.0"},
      {:finch, "~> 0.19"},
      {:jason, "~> 1.2"},
      {:ex_keccak, "~> 0.7.8"},
      {:ex_secp256k1, "~> 0.8.0"}
    ]
  end
end
