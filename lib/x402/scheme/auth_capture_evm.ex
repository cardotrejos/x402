defmodule X402.Scheme.AuthCaptureEVM do
  @moduledoc """
  Built-in `X402.Scheme` for `auth-capture` payments on EVM (`eip155:*`)
  networks.

  Implements both roles:

  * **Client** — signs the single token authorization the scheme needs:
    an EIP-3009 `ReceiveWithAuthorization` toward the deployment's
    EIP-3009 token collector (default), or a witness-less Permit2
    `PermitTransferFrom` toward its Permit2 collector when
    `extra.assetTransferMethod` is `"permit2"`. The authorization's nonce
    is the payment's `signatureNonce`, which commits to every
    `PaymentInfo` field the facilitator reconstructs; `salt` (and, when
    the bind is on, `saltNonce`) ride alongside. The payload is identical
    under both payment flows — `extra.paymentFlow` only decides whether
    the facilitator settles it as `authorize` or `charge`.
  * **Server** — `c:X402.Scheme.validate_payload/3` runs the offline shape
    guard and `c:X402.Scheme.precheck/3` the full structural checklist
    (`X402.Verify.AuthCaptureEVM` at level `:structural`). Both report
    `{:error, {:invalid_auth_capture_payment, reason}}`.

  `reclaim_transaction/2` builds the payer's own `reclaim` call for a hold
  the server never captured; the escrow restricts it to the payer, so it
  is never relayed by a facilitator.
  """

  @behaviour X402.Scheme

  alias X402.AuthCapture
  alias X402.AuthCapture.EVM
  alias X402.EIP712
  alias X402.Permit2
  alias X402.Signer
  alias X402.Utils
  alias X402.Verify.AuthCaptureEVM, as: Verify

  @sign_opts_schema [
    now: [
      type: :non_neg_integer,
      doc: "Unix seconds the authorization window starts from (default: current time)."
    ],
    salt: [
      type: :string,
      doc: "Unbound `salt` (32-byte `0x` hex). Defaults to fresh random bytes."
    ],
    salt_nonce: [
      type: :string,
      doc: "Bound `saltNonce` (32-byte `0x` hex). Defaults to fresh random bytes."
    ]
  ]

  @doc false
  @spec validate_options(term()) :: {:ok, keyword()} | {:error, String.t()}
  def validate_options(opts) when is_list(opts) do
    case NimbleOptions.validate(opts, @sign_opts_schema) do
      {:ok, options} -> {:ok, options}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  def validate_options(_opts), do: {:error, "expected auth-capture signing options"}

  @doc since: "0.9.0"
  @doc """
  Returns `"auth-capture"`.

  ## Examples

      iex> X402.Scheme.AuthCaptureEVM.scheme()
      "auth-capture"
  """
  @impl X402.Scheme
  @spec scheme() :: String.t()
  def scheme, do: AuthCapture.scheme()

  @doc since: "0.9.0"
  @doc """
  Returns `["eip155:*"]` — every EVM network.

  ## Examples

      iex> X402.Scheme.AuthCaptureEVM.networks()
      ["eip155:*"]
  """
  @impl X402.Scheme
  @spec networks() :: [String.t()]
  def networks, do: ["eip155:*"]

  @doc since: "0.9.0"
  @doc """
  Whether the client can sign this requirements entry: an EVM network, a
  resolvable deployment, a supported transfer method and payment flow, and
  the `extra` fields `PaymentInfo` needs.

  ## Examples

      iex> X402.Scheme.AuthCaptureEVM.signable?(%{
      ...>   "scheme" => "auth-capture",
      ...>   "network" => "eip155:84532",
      ...>   "amount" => "10000",
      ...>   "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>   "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   "maxTimeoutSeconds" => 600,
      ...>   "extra" => %{
      ...>     "name" => "USDC",
      ...>     "version" => "2",
      ...>     "captureMode" => "deferred",
      ...>     "captureAuthorizer" => "0x1563915e194d8cfba1943570603f7606a3115508",
      ...>     "feeRecipient" => "0x0000000000000000000000000000000000000000",
      ...>     "captureDeadline" => 1_800_000_000,
      ...>     "refundDeadline" => 1_800_100_000,
      ...>     "minFeeBps" => 0,
      ...>     "maxFeeBps" => 0
      ...>   }
      ...> })
      true

      iex> X402.Scheme.AuthCaptureEVM.signable?(%{"network" => "eip155:84532", "extra" => %{}})
      false
  """
  @impl X402.Scheme
  @spec signable?(map()) :: boolean()
  def signable?(requirements) when is_map(requirements) do
    Verify.validate_requirements(requirements) == :ok
  end

  def signable?(_requirements), do: false

  @doc since: "0.9.0"
  @doc """
  Signs the `auth-capture` scheme payload for the selected transfer method.

  The authorization is valid immediately (`validAfter` `"0"`) and expires
  at `now + maxTimeoutSeconds`, which is also `PaymentInfo.preApprovalExpiry`.

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}
  """
  @impl X402.Scheme
  @spec sign(map(), Signer.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign(requirements, signer, opts \\ []) when is_map(requirements) and is_list(opts) do
    opts = Keyword.get(opts, :auth_capture, opts)

    with {:ok, opts} <- validate_opts(opts),
         :ok <- Verify.validate_requirements(requirements),
         :ok <- AuthCapture.check_deadlines(requirements, Keyword.take(opts, [:now])),
         {:ok, method} <- AuthCapture.asset_transfer_method(requirements),
         {:ok, _flow} <- AuthCapture.payment_flow(requirements),
         {:ok, deployment} <- EVM.resolve_deployment(requirements),
         {:ok, chain_id} <-
           EIP712.chain_id_from_caip2(Utils.map_value(requirements, {"network", :network})),
         {:ok, domain} <- domain(method, requirements),
         {:ok, from} <- Signer.address(signer),
         {:ok, max_timeout} <- max_timeout(requirements),
         {:ok, salt, salt_nonce} <- salts(requirements, opts),
         expiry = Keyword.get_lazy(opts, :now, fn -> System.os_time(:second) end) + max_timeout,
         :ok <-
           AuthCapture.check_authorization_window(
             nil,
             expiry,
             Utils.nested_map_value(requirements, [
               {"extra", :extra},
               {"captureDeadline", :captureDeadline}
             ]),
             Keyword.take(opts, [:now])
           ),
         {:ok, info} <- EVM.payment_info(requirements, from, expiry, salt),
         {:ok, nonce} <- EVM.signature_nonce(chain_id, deployment.escrow, info),
         {:ok, key, authorization, digest} <-
           authorization(method, requirements, deployment, from, expiry, nonce, domain),
         {:ok, signature} <-
           Signer.sign_eip712(
             signer,
             digest,
             EVM.authorization_typed_data(method, domain, authorization)
           ) do
      payload = %{
        key => authorization,
        "signature" => "0x" <> Base.encode16(signature, case: :lower),
        "salt" => salt
      }

      {:ok, maybe_put(payload, "saltNonce", salt_nonce)}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Runs the offline shape guard (`X402.Verify.AuthCaptureEVM.validate_shape/2`).

  ## Examples

      iex> X402.Scheme.AuthCaptureEVM.validate_payload(
      ...>   %{"payload" => %{"salt" => "0x00"}},
      ...>   %{"extra" => %{}},
      ...>   []
      ...> )
      {:error, {:invalid_auth_capture_payment, :payload_format}}
  """
  @impl X402.Scheme
  @spec validate_payload(map(), map(), keyword()) ::
          :ok | {:error, {:invalid_auth_capture_payment, AuthCapture.reason()}}
  def validate_payload(payload, requirements, _opts) do
    case Verify.validate_shape(payload, requirements) do
      :ok -> :ok
      {:error, {:invalid, reason}} -> {:error, {:invalid_auth_capture_payment, reason}}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Runs the structural verification checklist locally (level `:structural`).

  Honors `:now` and `:skew_seconds` from `opts` for the deadline checks.
  """
  @impl X402.Scheme
  @spec precheck(map(), map(), keyword()) ::
          :ok | {:error, {:invalid_auth_capture_payment, AuthCapture.reason() | term()}}
  def precheck(payload, requirements, opts) do
    verify_opts = [level: :structural] ++ Keyword.take(opts, [:now, :skew_seconds])

    case Verify.verify(payload, requirements, verify_opts) do
      {:ok, _verification} -> :ok
      {:error, {:invalid, reason}} -> {:error, {:invalid_auth_capture_payment, reason}}
      {:error, reason} -> {:error, {:invalid_auth_capture_payment, reason}}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Builds the payer's `reclaim(PaymentInfo)` transaction for an escrowed
  hold whose capture deadline has passed.

  Accepts the signed payment payload (v2 envelope or inner payload) and the
  requirements it was signed for, and returns the call the payer submits
  from its own account: `%{to: escrow, data: "0x...", value: 0}`.
  """
  @spec reclaim_transaction(map(), map()) ::
          {:ok, %{to: String.t(), data: String.t(), value: 0}} | {:error, term()}
  def reclaim_transaction(payload, requirements) when is_map(payload) and is_map(requirements) do
    with {:ok, deployment} <- EVM.resolve_deployment(requirements),
         {:ok, info} <- EVM.payment_info_from_payload(payload, requirements),
         {:ok, calldata} <- EVM.reclaim_calldata(info) do
      {:ok,
       %{
         to: deployment.escrow,
         data: "0x" <> Base.encode16(calldata, case: :lower),
         value: 0
       }}
    end
  end

  # -- Internals --------------------------------------------------------------

  @spec validate_opts(keyword()) :: {:ok, keyword()} | {:error, term()}
  defp validate_opts(opts) do
    case NimbleOptions.validate(opts, @sign_opts_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, error} -> {:error, {:invalid_options, Exception.message(error)}}
    end
  end

  @spec domain(:eip3009 | :permit2, map()) :: {:ok, map()} | {:error, term()}
  defp domain(:eip3009, requirements), do: EIP712.domain(requirements)
  defp domain(:permit2, requirements), do: Permit2.domain(requirements)

  @spec max_timeout(map()) :: {:ok, non_neg_integer()} | {:error, :invalid_requirements}
  defp max_timeout(requirements) do
    case Utils.map_value(requirements, {"maxTimeoutSeconds", :maxTimeoutSeconds}) do
      seconds when is_integer(seconds) and seconds >= 0 -> {:ok, seconds}
      _other -> {:error, :invalid_requirements}
    end
  end

  @spec salts(map(), keyword()) :: {:ok, String.t(), String.t() | nil} | {:error, term()}
  defp salts(requirements, opts) do
    case EVM.bound?(requirements) do
      false ->
        with {:ok, salt} <- EVM.bytes32_hex(opts[:salt] || EVM.random_bytes32()) do
          {:ok, salt, nil}
        end

      true ->
        extra = Utils.map_value(requirements, {"extra", :extra}) || %{}

        with {:ok, salt_nonce} <- EVM.bytes32_hex(opts[:salt_nonce] || EVM.random_bytes32()),
             {:ok, salt} <-
               EVM.bound_salt(
                 Utils.map_value(extra, {"receiverAuthorizer", :receiverAuthorizer}),
                 Utils.map_value(extra, {"policy", :policy}),
                 salt_nonce
               ) do
          {:ok, salt, salt_nonce}
        end
    end
  end

  @spec authorization(
          :eip3009 | :permit2,
          map(),
          EVM.deployment(),
          String.t(),
          non_neg_integer(),
          String.t(),
          map()
        ) :: {:ok, String.t(), map(), binary()} | {:error, term()}
  defp authorization(:eip3009, requirements, deployment, from, expiry, nonce, domain) do
    authorization = %{
      "from" => from,
      "to" => deployment.eip3009_collector,
      "value" => to_string(Utils.map_value(requirements, {"amount", :amount})),
      "validAfter" => "0",
      "validBefore" => Integer.to_string(expiry),
      "nonce" => nonce
    }

    with {:ok, digest} <- EVM.receive_authorization_digest(domain, authorization) do
      {:ok, "authorization", authorization, digest}
    end
  end

  defp authorization(:permit2, requirements, deployment, from, expiry, nonce, domain) do
    with {:ok, decimal_nonce} <- EVM.permit2_nonce(nonce) do
      authorization = %{
        "from" => from,
        "permitted" => %{
          "token" => Utils.map_value(requirements, {"asset", :asset}),
          "amount" => to_string(Utils.map_value(requirements, {"amount", :amount}))
        },
        "spender" => deployment.permit2_collector,
        "nonce" => decimal_nonce,
        "deadline" => Integer.to_string(expiry)
      }

      with {:ok, digest} <- EVM.permit_transfer_digest(domain, authorization) do
        {:ok, "permit2Authorization", authorization, digest}
      end
    end
  end

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
