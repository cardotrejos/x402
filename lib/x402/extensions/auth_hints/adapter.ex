defmodule X402.Extensions.AuthHints.Adapter do
  @moduledoc """
  `X402.Extension` adapter advertising the `auth-hints` extension.

      plug X402.Plug.PaymentGate,
        routes: [...],
        extensions: [
          {X402.Extensions.AuthHints.Adapter,
           auth_requirements: [
             [accept_indexes: [1], methods: [X402.Extensions.AuthHints.oauth2(...)]]
           ]}
        ]

  Every 402 response advertises `X402.Extensions.AuthHints.extension/1`
  for the configured requirements, minus any index that falls outside
  the requirements actually offered to the request (a hook may have
  replaced them); a requirement left without indexes is not advertised,
  and neither is the extension when nothing remains. A context without
  requirements advertises the configuration unchanged.

  The hints only announce what the route expects. Checking the
  credentials a client then presents is the application's job, in the
  handler or in a plug ahead of the gate.
  """

  @behaviour X402.Extension

  alias X402.Extensions.AuthHints
  alias X402.Hooks.RequestContext

  @opts_schema [
    auth_requirements: [
      type: {:custom, __MODULE__, :validate_requirements, []},
      required: true,
      doc: "The requirements, as accepted by `X402.Extensions.AuthHints.extension/1`."
    ]
  ]

  @requirement_opts_schema [
    accept_indexes: [
      type: {:custom, AuthHints, :validate_indexes, []},
      required: true
    ],
    methods: [
      type: {:custom, AuthHints, :validate_methods, []},
      required: true
    ]
  ]

  @doc since: "0.9.0"
  @doc """
  Returns `"auth-hints"`.

  ## Examples

      iex> X402.Extensions.AuthHints.Adapter.key()
      "auth-hints"
  """
  @impl X402.Extension
  @spec key() :: String.t()
  def key, do: AuthHints.extension_key()

  @doc since: "0.9.0"
  @doc """
  Validates the adapter options.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}

  ## Examples

      iex> requirements = [[accept_indexes: [1], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]]
      iex> {:ok, opts} = X402.Extensions.AuthHints.Adapter.init(auth_requirements: requirements)
      iex> opts[:auth_requirements]["info"]["authRequirements"]
      [%{"acceptIndexes" => [1], "methods" => [%{"type" => "sign-in-with-x"}]}]

      iex> {:error, message} = X402.Extensions.AuthHints.Adapter.init(auth_requirements: [[accept_indexes: [], methods: []]])
      iex> message =~ "accept indexes"
      true

      iex> {:error, message} = X402.Extensions.AuthHints.Adapter.init([])
      iex> message =~ ":auth_requirements"
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

  @doc false
  @spec validate_requirements(term()) :: {:ok, map()} | {:error, String.t()}
  def validate_requirements([_ | _] = requirements) do
    requirements
    |> Enum.reduce_while({:ok, []}, fn requirement, {:ok, acc} ->
      case NimbleOptions.validate(requirement, @requirement_opts_schema) do
        {:ok, validated} -> {:cont, {:ok, [validated | acc]}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
    |> case do
      {:ok, validated} -> {:ok, AuthHints.extension(Enum.reverse(validated))}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  def validate_requirements(other),
    do: {:error, "expected a non-empty list of auth requirements, got: #{inspect(other)}"}

  @doc since: "0.9.0"
  @doc """
  Advertises the configured requirements, dropping indexes outside the
  request's requirements.

  ## Examples

      iex> {:ok, opts} = X402.Extensions.AuthHints.Adapter.init(
      ...>   auth_requirements: [[accept_indexes: [0, 1], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]]
      ...> )
      iex> context = X402.Hooks.RequestContext.new(requirements: [%{"scheme" => "exact"}])
      iex> X402.Extensions.AuthHints.Adapter.advertise(opts, context)["info"]
      %{"authRequirements" => [%{"acceptIndexes" => [0], "methods" => [%{"type" => "sign-in-with-x"}]}]}

      iex> {:ok, opts} = X402.Extensions.AuthHints.Adapter.init(
      ...>   auth_requirements: [[accept_indexes: [3], methods: [X402.Extensions.AuthHints.sign_in_with_x()]]]
      ...> )
      iex> context = X402.Hooks.RequestContext.new(requirements: [%{"scheme" => "exact"}])
      iex> X402.Extensions.AuthHints.Adapter.advertise(opts, context)
      nil
  """
  @impl X402.Extension
  @spec advertise(keyword(), RequestContext.t()) :: map() | nil
  def advertise(opts, %RequestContext{requirements: []}),
    do: Keyword.fetch!(opts, :auth_requirements)

  def advertise(opts, %RequestContext{requirements: requirements}) do
    extension = Keyword.fetch!(opts, :auth_requirements)
    count = length(requirements)

    extension["info"]["authRequirements"]
    |> Enum.map(fn requirement ->
      Map.update!(requirement, "acceptIndexes", &Enum.filter(&1, fn index -> index < count end))
    end)
    |> Enum.reject(&(&1["acceptIndexes"] == []))
    |> case do
      [] -> nil
      advertised -> put_in(extension, ["info", "authRequirements"], advertised)
    end
  end
end
