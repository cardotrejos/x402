defmodule X402.E2EServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :x402_e2e_server,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: false,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {E2eServer.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:x402, path: "../.."},
      {:bandit, "~> 1.0"},
      {:finch, "~> 0.19"},
      {:jason, "~> 1.2"}
    ]
  end
end
