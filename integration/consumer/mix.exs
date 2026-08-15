defmodule X402.ConsumerSmoke.MixProject do
  use Mix.Project

  def project do
    [
      app: :x402_consumer_smoke,
      version: "0.0.0",
      elixir: "~> 1.19",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:x402, path: "../.."}
    ]
  end
end
