defmodule X402.MixProject do
  use Mix.Project

  @version "0.5.0"
  @source_url "https://github.com/cardotrejos/x402"
  @description "Elixir SDK for the x402 HTTP payment protocol"

  def project do
    [
      app: :x402,
      version: @version,
      elixir: "~> 1.19",
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
      homepage_url: @source_url,
      docs: docs(),

      # Testing
      test_coverage: [tool: ExCoveralls, minimum_coverage: 90],

      # Dialyzer
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/project.plt"},
        plt_add_apps: [:mix, :credo]
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
      extra_applications: [:logger, :crypto, :public_key]
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

      # Runtime instrumentation
      {:telemetry, "~> 1.0"},

      # EVM signature verification (optional — only needed for SIWX)
      {:ex_secp256k1, "~> 0.8.0", optional: true},
      {:ex_keccak, "~> 0.7.8", optional: true},

      # Redis client (optional — only needed for the Redis payment
      # identifier cache adapter; users supervise the connection)
      {:redix, "~> 1.5", optional: true},

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
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "x402 Protocol" => "https://x402.org",
        "Docs" => "https://docs.x402.org"
      },
      maintainers: ["Ricardo Trejos"],
      files: ~w(lib guides .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
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
        LICENSE: [title: "License"],
        "guides/getting-started.md": [title: "Getting Started"],
        "guides/client.md": [title: "Paying for Resources"],
        "guides/plug-integration.md": [title: "Plug/Phoenix Integration"],
        "guides/mcp.md": [title: "Paid MCP Tools"],
        "guides/paywall.md": [title: "Browser Paywall"],
        "guides/live-smoke-tests.md": [title: "Live Smoke Tests"]
      ],
      groups_for_extras: [
        Guides: ~r/guides\/.*/
      ],
      groups_for_modules: [
        "Core Protocol": [
          X402,
          X402.PaymentRequirements,
          X402.PaymentRequired,
          X402.PaymentSignature,
          X402.PaymentResponse
        ],
        "Payer Client": [
          X402.Client,
          X402.Client.Finch,
          X402.Signer,
          X402.Signer.LocalKey,
          X402.EIP3009,
          X402.EIP712
        ],
        "Facilitator Client": [
          X402.Facilitator,
          X402.Facilitator.Auth,
          X402.Facilitator.Auth.CDP,
          X402.Facilitator.HTTP,
          X402.Hooks,
          X402.Hooks.Context,
          X402.Hooks.Default
        ],
        "Plug Integration": [
          X402.Plug.PaymentGate,
          X402.Paywall,
          X402.Paywall.Default
        ],
        "MCP Transport": [
          X402.MCP,
          X402.MCP.Server,
          X402.MCP.Client
        ],
        Utilities: [
          X402.Wallet
        ],
        Extensions: [
          X402.Extensions.Bazaar,
          X402.Extensions.EIP2612GasSponsoring,
          X402.Extensions.ERC20ApprovalGasSponsoring,
          X402.Extensions.PaymentIdentifier,
          X402.Extensions.PaymentIdentifier.Cache,
          X402.Extensions.PaymentIdentifier.ETSCache,
          X402.Extensions.PaymentIdentifier.RedisCache,
          X402.Extensions.PaymentIdentifier.RedisCache.Command,
          X402.Extensions.SIWX,
          X402.Extensions.SIWX.Verifier,
          X402.Extensions.SIWX.Verifier.Default,
          X402.Extensions.SIWX.Storage,
          X402.Extensions.SIWX.ETSStorage
        ]
      ],
      groups_for_docs: [
        "Header Encoding": &(&1[:group] == :headers),
        "Payment Verification": &(&1[:group] == :verification),
        "Payment Settlement": &(&1[:group] == :settlement),
        "Facilitator Discovery": &(&1[:group] == :discovery)
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
        "test --cover",
        "cmd env MIX_ENV=dev mix dialyzer"
      ]
    ]
  end
end
