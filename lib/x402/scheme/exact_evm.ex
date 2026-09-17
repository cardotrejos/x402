defmodule X402.Scheme.ExactEVM do
  @moduledoc """
  Built-in `X402.Scheme` for `exact` payments on EVM (`eip155:*`) networks.

  The exact-EVM scheme specification defines several **asset transfer
  methods**, selected by the requirements' `extra.assetTransferMethod`:

  | `extra.assetTransferMethod` | Transfer method | Scheme payload                                 |
  | --------------------------- | --------------- | ---------------------------------------------- |
  | absent or `"eip3009"`       | EIP-3009        | `%{"signature", "authorization"}`              |
  | `"permit2"`                 | Permit2         | `%{"signature", "permit2Authorization"}`       |

  Any other value is unsupported (`transfer_method/1`). Both methods are
  implemented for both roles:

  * **Client** — `sign/3` signs an EIP-3009 `TransferWithAuthorization`
    through `X402.EIP3009` for the default method, or a Permit2
    `PermitWitnessTransferFrom` through `X402.Permit2.sign_exact/2` when
    the requirements select `"permit2"` (spender: the `x402ExactPermit2Proxy`,
    witness: `payTo`, permitted amount: the exact `amount`). An entry is
    signable when the selected method's EIP-712 domain can be derived from
    the requirements — `extra.name` / `extra.version` for EIP-3009, an
    `eip155:*` network for Permit2.
  * **Server** — `precheck/3` runs the local pre-checks before the
    facilitator round-trip on whichever authorization object the payload
    carries: for EIP-3009, `to` must equal `payTo`, `value` must equal the
    advertised `amount`, and the `validAfter`/`validBefore` window must
    cover now plus a settlement buffer
    (`X402.Scheme.EVM.authorization_precheck/3`); for Permit2, `witness.to`
    must equal `payTo`, `permitted.amount` must equal `amount`,
    `permitted.token` must equal `asset`, `spender` must be the
    `x402ExactPermit2Proxy`, and the `witness.validAfter`/`deadline`
    window must cover now plus the buffer
    (`X402.Scheme.EVM.permit2_precheck/3`). Payloads carrying neither map
    are skipped.

  Envelope validation of the `PAYMENT-SIGNATURE` payload is handled by
  `X402.PaymentSignature`; this scheme adds no extra structural checks
  (`c:X402.Scheme.validate_payload/3` returns `:ok`).
  """

  @behaviour X402.Scheme

  alias X402.EIP3009
  alias X402.Permit2
  alias X402.Scheme.EVM
  alias X402.Signer
  alias X402.Utils

  @typedoc "An asset transfer method of the exact-EVM scheme."
  @type transfer_method :: :eip3009 | :permit2

  @doc since: "0.6.0"
  @doc """
  Returns `"exact"`.

  ## Examples

      iex> X402.Scheme.ExactEVM.scheme()
      "exact"
  """
  @impl X402.Scheme
  @spec scheme() :: String.t()
  def scheme, do: "exact"

  @doc since: "0.6.0"
  @doc """
  Returns `["eip155:*"]` — every EVM network.

  ## Examples

      iex> X402.Scheme.ExactEVM.networks()
      ["eip155:*"]
  """
  @impl X402.Scheme
  @spec networks() :: [String.t()]
  def networks, do: ["eip155:*"]

  @doc since: "0.8.0"
  @doc """
  Resolves the asset transfer method selected by the requirements.

  Reads `extra.assetTransferMethod`: absent or `"eip3009"` selects
  `:eip3009`, `"permit2"` selects `:permit2`, anything else is
  `{:error, {:unsupported_transfer_method, value}}`.

  ## Examples

      iex> X402.Scheme.ExactEVM.transfer_method(%{"extra" => %{"name" => "USDC"}})
      {:ok, :eip3009}

      iex> X402.Scheme.ExactEVM.transfer_method(%{"extra" => %{"assetTransferMethod" => "permit2"}})
      {:ok, :permit2}

      iex> X402.Scheme.ExactEVM.transfer_method(%{"extra" => %{"assetTransferMethod" => "erc7710"}})
      {:error, {:unsupported_transfer_method, "erc7710"}}

      iex> X402.Scheme.ExactEVM.transfer_method(%{})
      {:ok, :eip3009}
  """
  @spec transfer_method(map()) ::
          {:ok, transfer_method()} | {:error, {:unsupported_transfer_method, term()}}
  def transfer_method(requirements) when is_map(requirements) do
    extra = Utils.map_value(requirements, {"extra", :extra})

    method =
      case is_map(extra) do
        true -> Utils.map_value(extra, {"assetTransferMethod", :assetTransferMethod})
        false -> nil
      end

    case method do
      nil -> {:ok, :eip3009}
      "eip3009" -> {:ok, :eip3009}
      "permit2" -> {:ok, :permit2}
      other -> {:error, {:unsupported_transfer_method, other}}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Whether the selected transfer method's EIP-712 domain can be derived
  from the requirements.

  ## Examples

      iex> X402.Scheme.ExactEVM.signable?(%{
      ...>   "network" => "eip155:84532",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> })
      true

      iex> X402.Scheme.ExactEVM.signable?(%{
      ...>   "network" => "eip155:84532",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "extra" => %{"assetTransferMethod" => "permit2"}
      ...> })
      true

      iex> X402.Scheme.ExactEVM.signable?(%{"extra" => %{}})
      false

      iex> X402.Scheme.ExactEVM.signable?(%{
      ...>   "network" => "eip155:84532",
      ...>   "extra" => %{"assetTransferMethod" => "erc7710"}
      ...> })
      false
  """
  @impl X402.Scheme
  @spec signable?(map()) :: boolean()
  def signable?(requirements) when is_map(requirements) do
    case transfer_method(requirements) do
      {:ok, :eip3009} -> match?({:ok, _domain}, EIP3009.domain(requirements))
      {:ok, :permit2} -> match?({:ok, _domain}, Permit2.domain(requirements))
      {:error, _reason} -> false
    end
  end

  def signable?(_requirements), do: false

  @doc since: "0.6.0"
  @doc """
  Signs the scheme payload for the selected transfer method.

  EIP-3009 requirements sign via `X402.EIP3009.sign/3`, honoring the
  client's `:valid_after_buffer` option; Permit2 requirements sign via
  `X402.Permit2.sign_exact/2` (valid immediately, expiring after
  `maxTimeoutSeconds`). Other options are ignored.
  """
  @impl X402.Scheme
  @spec sign(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(requirements, signer, opts) do
    case transfer_method(requirements) do
      {:ok, :eip3009} ->
        EIP3009.sign(requirements, signer, Keyword.take(opts, [:valid_after_buffer]))

      {:ok, :permit2} ->
        Permit2.sign_exact(requirements, signer)

      {:error, _reason} = error ->
        error
    end
  end

  @doc since: "0.6.0"
  @doc """
  Always `:ok` — envelope validation covers the `exact` payload shape.

  ## Examples

      iex> X402.Scheme.ExactEVM.validate_payload(%{}, %{}, [])
      :ok
  """
  @impl X402.Scheme
  @spec validate_payload(map(), map(), keyword()) :: :ok
  def validate_payload(_payload, _requirements, _opts), do: :ok

  @doc since: "0.6.0"
  @doc """
  Runs the local pre-checks with exact-amount equality enforced.

  Dispatches on the payload shape: `payload.authorization` runs
  `X402.Scheme.EVM.authorization_precheck/3`, `payload.permit2Authorization`
  runs `X402.Scheme.EVM.permit2_precheck/3` against the
  `x402ExactPermit2Proxy` spender. Both run when both maps are present;
  neither present passes.
  """
  @impl X402.Scheme
  @spec precheck(map(), map(), keyword()) ::
          :ok | {:error, {:precheck_failed, EVM.precheck_failure()}}
  def precheck(payload, requirements, _opts) do
    with :ok <- EVM.authorization_precheck(payload, requirements, enforce_exact_amount: true) do
      EVM.permit2_precheck(payload, requirements,
        enforce_exact_amount: true,
        spender: Permit2.exact_proxy_address()
      )
    end
  end
end
