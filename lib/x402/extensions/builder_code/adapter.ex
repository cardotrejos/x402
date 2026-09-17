defmodule X402.Extensions.BuilderCode.Adapter do
  @moduledoc """
  `X402.Extension` adapter advertising and validating the `builder-code` extension.

      plug X402.Plug.PaymentGate,
        routes: [...],
        extensions: [{X402.Extensions.BuilderCode.Adapter, app_code: "my_app"}]

  Every 402 response advertises
  `X402.Extensions.BuilderCode.extension(app_code, service_codes: ...)` and
  every payment's echo is checked with
  `X402.Extensions.BuilderCode.validate_echo/2` (in addition to the gate's
  built-in check, which covers payloads that echo the extension without an
  adapter configured).
  """

  @behaviour X402.Extension

  alias X402.Extensions.BuilderCode

  @opts_schema [
    app_code: [
      type: {:custom, BuilderCode, :validate_code, []},
      required: true,
      doc: "The application's builder code (`info.a`)."
    ],
    service_codes: [
      type: {:custom, BuilderCode, :validate_codes, [5]},
      default: [],
      doc: "The server's own service code(s) (`info.s`), at most 5."
    ]
  ]

  @doc since: "0.8.0"
  @doc """
  Returns `"builder-code"`.

  ## Examples

      iex> X402.Extensions.BuilderCode.Adapter.key()
      "builder-code"
  """
  @impl X402.Extension
  @spec key() :: String.t()
  def key, do: BuilderCode.extension_key()

  @doc since: "0.8.0"
  @doc """
  Validates the adapter options.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}

  ## Examples

      iex> {:ok, opts} = X402.Extensions.BuilderCode.Adapter.init(app_code: "my_app")
      iex> {opts[:app_code], opts[:service_codes]}
      {"my_app", []}

      iex> {:error, message} = X402.Extensions.BuilderCode.Adapter.init(app_code: "My App")
      iex> message =~ "invalid builder code"
      true
  """
  @impl X402.Extension
  @spec init(keyword()) :: {:ok, keyword()} | {:error, String.t()}
  def init(opts) do
    case NimbleOptions.validate(opts, @opts_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  @doc since: "0.8.0"
  @doc """
  Advertises the configured codes.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new([])
      iex> X402.Extensions.BuilderCode.Adapter.advertise([app_code: "my_app", service_codes: ["sdk"]], context)["info"]
      %{"a" => "my_app", "s" => ["sdk"]}
  """
  @impl X402.Extension
  @spec advertise(keyword(), X402.Hooks.RequestContext.t()) :: map()
  def advertise(opts, _context) do
    BuilderCode.extension(
      Keyword.fetch!(opts, :app_code),
      service_codes: Keyword.get(opts, :service_codes, [])
    )
  end

  @doc since: "0.8.0"
  @doc """
  Validates the echoed value with `X402.Extensions.BuilderCode.validate_echo/2`.

  ## Examples

      iex> advertised = X402.Extensions.BuilderCode.extension("my_app")
      iex> X402.Extensions.BuilderCode.Adapter.validate(%{"a" => "my_app"}, advertised, [])
      :ok
  """
  @impl X402.Extension
  @spec validate(term(), term(), keyword()) :: :ok | {:error, BuilderCode.error()}
  def validate(echoed, advertised, _opts), do: BuilderCode.validate_echo(echoed, advertised)
end
