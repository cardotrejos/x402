defmodule X402.Scheme do
  @moduledoc """
  Behaviour for pluggable x402 payment schemes.

  A *scheme* is x402's unit of extension: the pairing of a payment scheme
  name (`"exact"`, `"upto"`, ...) with a family of CAIP-2 networks
  (`"eip155:*"`, `"solana:*"`, ...). Everything scheme-specific this library
  does — deciding whether the client can sign an advertised requirement,
  producing the signed scheme `payload`, structurally validating an incoming
  `PAYMENT-SIGNATURE`, and running cheap local pre-checks before the
  facilitator round-trip — dispatches through this behaviour. Adding support
  for a new chain or scheme means writing **one module** and passing it as
  an option, not editing `X402.Client`, `X402.PaymentSignature`, or
  `X402.Plug.PaymentGate`.

  The built-in schemes are `X402.Scheme.ExactEVM` (`exact` on `eip155:*`
  networks via EIP-3009) and `X402.Scheme.UptoEVM` (`upto` on `eip155:*`
  networks, server-side only). Resolution — including wildcard CAIP-2
  matching and exact-match precedence — is handled by
  `X402.Scheme.Registry`.

  ## Callbacks and the roles they serve

  | Callback               | Role     | Consulted by                                 |
  |------------------------|----------|----------------------------------------------|
  | `c:scheme/0`           | metadata | `X402.Scheme.Registry.resolve/3`             |
  | `c:networks/0`         | metadata | `X402.Scheme.Registry.resolve/3`             |
  | `c:signable?/1`        | client   | `X402.Client.select_requirements/2`          |
  | `c:sign/3`             | client   | `X402.Client.build_payment/3`                |
  | `c:validate_payload/3` | server   | `X402.PaymentSignature.validate/3`           |
  | `c:precheck/3`         | server   | `X402.Plug.PaymentGate` (`:local_prechecks`) |

  Only `c:scheme/0` and `c:networks/0` are required. A scheme module
  implements the callbacks for the roles it plays: a client-only scheme can
  omit `c:validate_payload/3` and `c:precheck/3`; a server-only scheme (like
  `X402.Scheme.UptoEVM`) can omit `c:sign/3`. Missing optional callbacks are
  neutral — signing falls back to the `{:unsupported_kind, scheme, network}`
  error, while validation and pre-checks pass through with `:ok` (the
  facilitator remains the authority).

  ## Adding a chain or scheme in one module

  Implement the behaviour:

      defmodule MyApp.CashScheme do
        @behaviour X402.Scheme

        @impl X402.Scheme
        def scheme, do: "cash"

        @impl X402.Scheme
        def networks, do: ["local:*"]

        # Client side: produce the scheme payload carried as
        # PaymentPayload.payload.
        @impl X402.Scheme
        def sign(requirements, _signer, _opts) do
          {:ok, %{"note" => "IOU " <> requirements["amount"]}}
        end

        # Server side: structural validation of the decoded payload.
        @impl X402.Scheme
        def validate_payload(payload, _requirements, _opts) do
          case get_in(payload, ["payload", "note"]) do
            note when is_binary(note) -> :ok
            _missing -> {:error, {:invalid_scheme_payment, :missing_note}}
          end
        end

        # Server side: cheap local pre-checks before the facilitator call.
        @impl X402.Scheme
        def precheck(payload, _requirements, _opts) do
          case get_in(payload, ["payload", "counterfeit"]) do
            true -> {:error, {:precheck_failed, :counterfeit_note}}
            _other -> :ok
          end
        end
      end

  Then pass it where you use the SDK — every entry point takes a `:schemes`
  option (a list of modules consulted before the built-ins):

      # Resource server: gate routes may now use scheme "cash".
      plug X402.Plug.PaymentGate,
        schemes: [MyApp.CashScheme],
        routes: [
          %{
            method: :get,
            path: "/paid",
            scheme: "cash",
            price: "5",
            network: "local:test",
            asset: "note",
            pay_to: "till"
          }
        ]

      # Payer client: "cash" requirements become selectable and signable.
      X402.Client.build_payment(payment_required, signer, schemes: [MyApp.CashScheme])

      # Standalone header validation.
      X402.PaymentSignature.validate(payload, requirements, schemes: [MyApp.CashScheme])

  There is no global registration and no application environment: scheme
  modules are passed explicitly as options, so two gates (or two clients) in
  the same VM can support different scheme sets. A user module listed in
  `:schemes` is consulted before the built-ins and can override them — see
  `X402.Scheme.Registry` for the exact precedence rules.

  ## Error conventions

  * `c:sign/3` returns `{:ok, scheme_payload}` where `scheme_payload` is the
    map carried as the v2 `PaymentPayload.payload`, or `{:error, reason}`.
  * `c:validate_payload/3` failures should be
    `{:error, {:invalid_scheme_payment, reason}}`, which
    `X402.Plug.PaymentGate` answers with HTTP 400 Invalid Request (the
    built-in `upto` scheme keeps its historical
    `{:invalid_upto_payment, reason}` tuples, mapped the same way).
    Unrecognized error shapes fail closed as HTTP 500.
  * `c:precheck/3` failures should be `{:error, {:precheck_failed, reason}}`
    so the gate answers 402 without a facilitator round-trip. Pre-checks
    must only fail fast on certain mismatch — the facilitator remains the
    authority.
  """

  alias X402.Signer

  @typedoc "A module implementing `X402.Scheme`."
  @type t :: module()

  @doc """
  The x402 scheme name this module implements (for example `"exact"`).
  """
  @callback scheme() :: String.t()

  @doc """
  The CAIP-2 network patterns this module supports.

  A pattern is either an exact CAIP-2 identifier (`"eip155:8453"`) or a
  prefix wildcard ending in `*` (`"eip155:*"`, or `"*"` for every network).
  """
  @callback networks() :: [String.t()]

  @doc """
  Whether the client can sign this specific requirements entry.

  Called during `X402.Client.select_requirements/2` after structural
  validation, letting a scheme reject entries that are missing
  scheme-specific data (for example EIP-712 domain fields in `extra`).
  Optional — when not implemented, every entry for a matching
  scheme/network is considered signable.
  """
  @callback signable?(requirements :: map()) :: boolean()

  @doc """
  Signs the scheme-specific payment `payload` for the given requirements.

  Receives the requirements entry exactly as the server advertised it, the
  `X402.Signer`, and the client's validated build options (schemes that use
  options — such as `:valid_after_buffer` — should `Keyword.take/2` what
  they need). Returns the map carried as `PaymentPayload.payload`.
  Optional — when not implemented, the scheme cannot be selected or signed
  by `X402.Client`.
  """
  @callback sign(requirements :: map(), signer :: Signer.t(), opts :: keyword()) ::
              {:ok, map()} | {:error, term()}

  @doc """
  Structurally validates a decoded `PAYMENT-SIGNATURE` payload.

  Called by `X402.PaymentSignature.validate/3` after envelope validation,
  with the effective requirements (the caller-supplied requirements, or the
  payload's own `accepted` object when none were given). Optional — when
  not implemented, validation passes through with `:ok`.
  """
  @callback validate_payload(payload :: map(), requirements :: map(), opts :: keyword()) ::
              :ok | {:error, term()}

  @doc """
  Cheap local pre-checks run by `X402.Plug.PaymentGate` before the
  facilitator round-trip.

  Failures should be `{:error, {:precheck_failed, reason}}` (answered with
  HTTP 402). Optional — when not implemented, the gate skips straight to
  the facilitator.
  """
  @callback precheck(payload :: map(), requirements :: map(), opts :: keyword()) ::
              :ok | {:error, term()}

  @optional_callbacks signable?: 1, sign: 3, validate_payload: 3, precheck: 3

  @required_callbacks [{:scheme, 0}, {:networks, 0}]

  @doc since: "0.6.0"
  @doc """
  Validates that a term is a module implementing `X402.Scheme`.

  Returns `{:ok, module}` for use as a NimbleOptions `{:custom, ...}`
  validator — this is what backs the `:schemes` option on
  `X402.Client.build_payment/3`, `X402.Plug.PaymentGate`, and
  `X402.PaymentSignature.validate/3`.

  ## Examples

      iex> X402.Scheme.validate_module(X402.Scheme.ExactEVM)
      {:ok, X402.Scheme.ExactEVM}

      iex> X402.Scheme.validate_module(:not_a_scheme)
      {:error, "expected a module implementing X402.Scheme"}
  """
  @spec validate_module(term()) :: {:ok, module()} | {:error, String.t()}
  def validate_module(module) when is_atom(module) do
    case X402.Behaviour.implements?(module, @required_callbacks) do
      true -> {:ok, module}
      false -> {:error, "expected a module implementing X402.Scheme"}
    end
  end

  def validate_module(_invalid), do: {:error, "expected a module implementing X402.Scheme"}

  @doc since: "0.6.0"
  @doc """
  Whether a scheme module implements the client-side `c:sign/3` callback.

  ## Examples

      iex> X402.Scheme.signs?(X402.Scheme.ExactEVM)
      true

      iex> X402.Scheme.signs?(X402.Scheme.UptoEVM)
      false
  """
  @spec signs?(t()) :: boolean()
  def signs?(module), do: Code.ensure_loaded?(module) and function_exported?(module, :sign, 3)

  @doc since: "0.6.0"
  @doc """
  Invokes `c:signable?/1`, defaulting to `true` when not implemented.

  ## Examples

      iex> X402.Scheme.signable?(X402.Scheme.UptoEVM, %{})
      true

      iex> X402.Scheme.signable?(X402.Scheme.ExactEVM, %{})
      false
  """
  @spec signable?(t(), map()) :: boolean()
  def signable?(module, requirements) do
    case Code.ensure_loaded?(module) and function_exported?(module, :signable?, 1) do
      true -> module.signable?(requirements)
      false -> true
    end
  end

  @doc since: "0.6.0"
  @doc """
  Invokes `c:validate_payload/3`, defaulting to `:ok` when not implemented.

  ## Examples

      iex> X402.Scheme.validate_payload(X402.Scheme.ExactEVM, %{}, %{}, [])
      :ok
  """
  @spec validate_payload(t(), map(), map(), keyword()) :: :ok | {:error, term()}
  def validate_payload(module, payload, requirements, opts \\ []) do
    case Code.ensure_loaded?(module) and function_exported?(module, :validate_payload, 3) do
      true -> module.validate_payload(payload, requirements, opts)
      false -> :ok
    end
  end

  @doc since: "0.6.0"
  @doc """
  Invokes `c:precheck/3`, defaulting to `:ok` when not implemented.

  ## Examples

      iex> X402.Scheme.precheck(X402.Scheme.ExactEVM, %{"payload" => %{}}, %{}, [])
      :ok
  """
  @spec precheck(t(), map(), map(), keyword()) :: :ok | {:error, term()}
  def precheck(module, payload, requirements, opts \\ []) do
    case Code.ensure_loaded?(module) and function_exported?(module, :precheck, 3) do
      true -> module.precheck(payload, requirements, opts)
      false -> :ok
    end
  end
end
