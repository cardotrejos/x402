defmodule X402.Extensions.HTTPMessageSignatures.Adapter do
  @moduledoc """
  `X402.Extension` adapter advertising the `http-message-signatures`
  extension.

      plug X402.Plug.PaymentGate,
        routes: [...],
        extensions: [
          {X402.Extensions.HTTPMessageSignatures.Adapter,
           registration_url: "https://network.example.com/signature-agents",
           signature_schemes: ["ed25519"],
           tags: ["web-bot-auth"]}
        ]

  Every 402 response then carries
  `X402.Extensions.HTTPMessageSignatures.extension/1` for the given
  options. Verifying the signatures clients send is the application's
  job (`X402.HTTPSignature.verify/2` in a plug ahead of the gate).
  """

  @behaviour X402.Extension

  alias X402.Extensions.HTTPMessageSignatures
  alias X402.Hooks.RequestContext

  @opts_schema [
    registration_url: [
      type: {:custom, HTTPMessageSignatures, :validate_url, []},
      required: true
    ],
    signature_schemes: [
      type: {:custom, HTTPMessageSignatures, :validate_strings, ["signature scheme"]},
      required: true
    ],
    tags: [
      type: {:custom, HTTPMessageSignatures, :validate_strings, ["tag"]},
      default: []
    ],
    include_schema: [
      type: :boolean,
      default: true
    ]
  ]

  @doc since: "0.9.0"
  @doc """
  Returns `"http-message-signatures"`.

  ## Examples

      iex> X402.Extensions.HTTPMessageSignatures.Adapter.key()
      "http-message-signatures"
  """
  @impl X402.Extension
  @spec key() :: String.t()
  def key, do: HTTPMessageSignatures.extension_key()

  @doc since: "0.9.0"
  @doc """
  Validates the adapter options, which are those of
  `X402.Extensions.HTTPMessageSignatures.extension/1`.

  ## Examples

      iex> {:ok, opts} = X402.Extensions.HTTPMessageSignatures.Adapter.init(
      ...>   registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"])
      iex> opts[:extension]["info"]["signatureSchemes"]
      ["ed25519"]

      iex> {:error, message} = X402.Extensions.HTTPMessageSignatures.Adapter.init(signature_schemes: ["ed25519"])
      iex> message =~ ":registration_url"
      true
  """
  @impl X402.Extension
  @spec init(keyword()) :: {:ok, keyword()} | {:error, String.t()}
  def init(opts) when is_list(opts) do
    case NimbleOptions.validate(opts, @opts_schema) do
      {:ok, validated} -> {:ok, [extension: HTTPMessageSignatures.extension(validated)]}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Advertises the configured extension on every 402 response.

  ## Examples

      iex> {:ok, opts} = X402.Extensions.HTTPMessageSignatures.Adapter.init(
      ...>   registration_url: "https://network.example.com/agents", signature_schemes: ["ed25519"], include_schema: false)
      iex> X402.Extensions.HTTPMessageSignatures.Adapter.advertise(opts, X402.Hooks.RequestContext.new([]))
      %{"info" => %{"registrationUrl" => "https://network.example.com/agents", "signatureSchemes" => ["ed25519"], "tags" => []}}
  """
  @impl X402.Extension
  @spec advertise(keyword(), RequestContext.t()) :: map()
  def advertise(opts, %RequestContext{}), do: Keyword.fetch!(opts, :extension)
end
