defmodule X402.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/cardotrejos/x402"
  @description "Elixir SDK for the x402 HTTP payment protocol"

  def project do
    [
      app: :x402,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      elixirc_paths: elixirc_paths(Mix.env()),

      # Hex
      description: @description,
      package: package(),

      # Docs
      name: "X402",
      source_url: @source_url,
      homepage_url: "https://x402.org",
      docs: docs(),

      # Testing
      test_coverage: [tool: ExCoveralls, minimum_coverage: 90],

      # Dialyzer
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/project.plt"},
        plt_add_apps: [:mix]
      ]
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        "coveralls.github": :test,
        ci: :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # HTTP client (optional — users can bring their own)
      {:finch, "~> 0.19", optional: true},

      # Plug integration (optional — users can bring their own web stack)
      {:plug, "~> 1.14", optional: true},

      # JSON encoding/decoding
      {:jason, "~> 1.2"},

      # Option validation (Dashbit style)
      {:nimble_options, "~> 1.0"},

      # Documentation
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},

      # Testing
      {:excoveralls, "~> 0.18", only: :test},
      {:bypass, "~> 2.1", only: :test},
      {:mox, "~> 1.2", only: :test},

      # Code quality
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "x402",
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "x402 Protocol" => "https://x402.org",
        "Docs" => "https://docs.x402.org"
      },
      maintainers: ["Ricardo Trejos"],
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: [
        "README.md": [title: "Overview"],
        "CHANGELOG.md": [title: "Changelog"],
        "guides/getting-started.md": [title: "Getting Started"],
        "guides/plug-integration.md": [title: "Plug/Phoenix Integration"]
      ],
      groups_for_extras: [
        Guides: ~r/guides\/.*/
      ],
      groups_for_modules: [
        "Core Protocol": [
          X402,
          X402.PaymentRequired,
          X402.PaymentSignature,
          X402.PaymentResponse
        ],
        "Facilitator Client": [
          X402.Facilitator,
          X402.Facilitator.HTTP
        ],
        "Plug Integration": [
          X402.Plug.PaymentGate
        ],
        Utilities: [
          X402.Wallet
        ]
      ],
      groups_for_docs: [
        "Header Encoding": &(&1[:group] == :headers),
        "Payment Verification": &(&1[:group] == :verification)
      ]
    ]
  end

  defp aliases do
    [
      quality: [
        "compile --warnings-as-errors",
        "format --check-formatted",
        "credo --strict",
        "dialyzer"
      ],
      ci: [
        "compile --warnings-as-errors",
        "format --check-formatted",
        "credo --strict",
        "test --cover"
      ]
    ]
  end
end
