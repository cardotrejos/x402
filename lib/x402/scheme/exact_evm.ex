defmodule X402.Scheme.ExactEVM do
  @moduledoc """
  Built-in `X402.Scheme` for `exact` payments on EVM (`eip155:*`) networks.

  Implements both roles:

  * **Client** — signs an EIP-3009 `TransferWithAuthorization` through
    `X402.EIP3009`, producing the
    `%{"signature" => ..., "authorization" => ...}` scheme payload. An
    entry is signable when its EIP-712 domain can be derived from the
    requirements (`extra.name` / `extra.version` present, default `eip3009`
    transfer method).
  * **Server** — runs the local pre-checks on the EIP-3009 authorization
    object before the facilitator round-trip: `to` must equal the
    requirements' `payTo`, `value` must equal the advertised `amount`, and
    the `validAfter`/`validBefore` window must cover now plus a settlement
    buffer (`X402.Scheme.EVM.time_buffer_seconds/0`). Payloads without a
    `payload.authorization` map are skipped.

  Envelope validation of the `PAYMENT-SIGNATURE` payload is handled by
  `X402.PaymentSignature`; this scheme adds no extra structural checks
  (`c:X402.Scheme.validate_payload/3` returns `:ok`).
  """

  @behaviour X402.Scheme

  alias X402.EIP3009
  alias X402.Scheme.EVM
  alias X402.Signer

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

  @doc since: "0.6.0"
  @doc """
  Whether the EIP-712 domain can be derived from the requirements.

  ## Examples

      iex> X402.Scheme.ExactEVM.signable?(%{
      ...>   "network" => "eip155:84532",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "extra" => %{"name" => "USDC", "version" => "2"}
      ...> })
      true

      iex> X402.Scheme.ExactEVM.signable?(%{"extra" => %{}})
      false
  """
  @impl X402.Scheme
  @spec signable?(map()) :: boolean()
  def signable?(requirements) when is_map(requirements) do
    match?({:ok, _domain}, EIP3009.domain(requirements))
  end

  def signable?(_requirements), do: false

  @doc since: "0.6.0"
  @doc """
  Signs the EIP-3009 scheme payload via `X402.EIP3009.sign/3`.

  Honors the client's `:valid_after_buffer` option; other options are
  ignored.
  """
  @impl X402.Scheme
  @spec sign(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(requirements, signer, opts) do
    EIP3009.sign(requirements, signer, Keyword.take(opts, [:valid_after_buffer]))
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
  Runs `X402.Scheme.EVM.authorization_precheck/3` with exact-amount
  equality enforced.
  """
  @impl X402.Scheme
  @spec precheck(map(), map(), keyword()) ::
          :ok | {:error, {:precheck_failed, EVM.precheck_failure()}}
  def precheck(payload, requirements, _opts) do
    EVM.authorization_precheck(payload, requirements, enforce_exact_amount: true)
  end
end
