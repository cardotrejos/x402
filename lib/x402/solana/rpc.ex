defmodule X402.Solana.RPC do
  @moduledoc """
  Minimal Solana JSON-RPC calls over an `X402.RPC` endpoint.

  Provides exactly the RPC surface the SVM facilitator engine needs —
  `getLatestBlockhash`, `simulateTransaction`, `sendTransaction`, and
  `getSignatureStatuses` — as thin wrappers around the generic
  `X402.RPC.request/3`, unwrapping Solana's `%{"context", "value"}` response
  envelope where present. It is not a general-purpose Solana client: there is
  no account fetching, no address-lookup-table resolution, and no WebSocket
  subscription support.

      {:ok, rpc} =
        X402.RPC.new(
          rpc_url: "https://api.devnet.solana.com",
          finch: MyApp.Finch
        )

      {:ok, %{blockhash: blockhash}} = X402.Solana.RPC.get_latest_blockhash(rpc)

  All transport, TLS, and telemetry behaviour is inherited from `X402.RPC`
  (events carry the Solana method name as `:method` metadata), and errors are
  `t:X402.RPC.error/0` values — node-side failures come back as
  `{:error, {:jsonrpc_error, %{code: _, message: _, data: _}}}`.
  """

  alias X402.RPC

  @typedoc "The unwrapped `getLatestBlockhash` value."
  @type latest_blockhash :: %{
          blockhash: String.t(),
          last_valid_block_height: non_neg_integer()
        }

  @typedoc """
  The unwrapped `simulateTransaction` value.

  `err` is `nil` when the simulated transaction would succeed; otherwise the
  node's error term (a string or a map, passed through as decoded JSON).
  """
  @type simulation :: %{err: term() | nil, logs: [String.t()] | nil}

  @typedoc """
  One `getSignatureStatuses` entry: `nil` for an unknown signature, or the
  status with its `confirmationStatus` (`"processed"`, `"confirmed"`,
  `"finalized"`, or `nil`) and error term.
  """
  @type signature_status :: nil | %{confirmation_status: String.t() | nil, err: term() | nil}

  @commitment_schema [
    commitment: [
      type: :string,
      default: "confirmed",
      doc: "The commitment level for the request."
    ]
  ]

  @doc since: "0.6.0"
  @doc """
  Fetches the latest blockhash via `getLatestBlockhash`.

  Returns the blockhash (Base58) and the last block height at which a
  transaction using it is still valid.

  ## Options

  #{NimbleOptions.docs(@commitment_schema)}
  """
  @spec get_latest_blockhash(RPC.t(), keyword()) ::
          {:ok, latest_blockhash()} | {:error, RPC.error()}
  def get_latest_blockhash(%RPC{} = rpc, opts \\ []) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @commitment_schema)
    params = [%{"commitment" => Keyword.fetch!(opts, :commitment)}]

    with {:ok, result} <- RPC.request(rpc, "getLatestBlockhash", params),
         {:ok, value} <- unwrap_value(result) do
      decode_latest_blockhash(value)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Simulates a Base64-encoded wire transaction via `simulateTransaction`.

  The simulation runs with `sigVerify: false` and
  `replaceRecentBlockhash: false`, matching the reference facilitators: the
  fee-payer slot is unsigned until settlement, so required signatures must be
  verified locally instead (see `X402.Verify.SVM`), and the embedded
  blockhash is part of what is being validated.

  Returns the node's simulation verdict — `err: nil` means the transaction
  would succeed.

  ## Options

  #{NimbleOptions.docs(@commitment_schema)}
  """
  @spec simulate_transaction(RPC.t(), String.t(), keyword()) ::
          {:ok, simulation()} | {:error, RPC.error()}
  def simulate_transaction(%RPC{} = rpc, transaction_base64, opts \\ [])
      when is_binary(transaction_base64) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @commitment_schema)

    config = %{
      "sigVerify" => false,
      "replaceRecentBlockhash" => false,
      "commitment" => Keyword.fetch!(opts, :commitment),
      "encoding" => "base64"
    }

    with {:ok, result} <- RPC.request(rpc, "simulateTransaction", [transaction_base64, config]),
         {:ok, value} <- unwrap_value(result) do
      decode_simulation(value)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Broadcasts a Base64-encoded wire transaction via `sendTransaction`.

  Sends with `skipPreflight: true`, matching the reference facilitators —
  verification already simulated, and a preflight failure here would be
  indistinguishable from a node-side rejection. Returns the Base58
  transaction signature acknowledged by the node.

  ## Options

  #{NimbleOptions.docs(@commitment_schema)}
  """
  @spec send_transaction(RPC.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, RPC.error()}
  def send_transaction(%RPC{} = rpc, transaction_base64, opts \\ [])
      when is_binary(transaction_base64) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @commitment_schema)

    config = %{
      "encoding" => "base64",
      "skipPreflight" => true,
      "preflightCommitment" => Keyword.fetch!(opts, :commitment)
    }

    case RPC.request(rpc, "sendTransaction", [transaction_base64, config]) do
      {:ok, signature} when is_binary(signature) -> {:ok, signature}
      {:ok, other} -> {:error, {:invalid_response, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Fetches confirmation statuses for Base58 signatures via
  `getSignatureStatuses`.

  Returns one entry per requested signature, **in request order**: `nil` for
  a signature the node does not know, or a map with its
  `confirmation_status` and `err` (non-`nil` when the transaction was
  included but failed on chain).

  The request is issued with `searchTransactionHistory: true`. The node's
  in-memory status cache only retains recent signatures, so pending-store
  retries that arrive after a confirmed transaction ages out would otherwise
  see `nil` and never observe the successful payment.
  """
  @spec get_signature_statuses(RPC.t(), [String.t()]) ::
          {:ok, [signature_status()]} | {:error, RPC.error()}
  def get_signature_statuses(%RPC{} = rpc, signatures) when is_list(signatures) do
    config = %{"searchTransactionHistory" => true}

    with {:ok, result} <- RPC.request(rpc, "getSignatureStatuses", [signatures, config]),
         {:ok, value} <- unwrap_value(result) do
      decode_statuses(value)
    end
  end

  # -- Response decoding ------------------------------------------------------

  # Most Solana query responses wrap the payload as {"context", "value"}.
  @spec unwrap_value(term()) :: {:ok, term()} | {:error, {:invalid_response, term()}}
  defp unwrap_value(%{"value" => value}), do: {:ok, value}
  defp unwrap_value(other), do: {:error, {:invalid_response, other}}

  @spec decode_latest_blockhash(term()) ::
          {:ok, latest_blockhash()} | {:error, {:invalid_response, term()}}
  defp decode_latest_blockhash(
         %{"blockhash" => blockhash, "lastValidBlockHeight" => height} = value
       ) do
    case is_binary(blockhash) and is_integer(height) and height >= 0 do
      true -> {:ok, %{blockhash: blockhash, last_valid_block_height: height}}
      false -> {:error, {:invalid_response, value}}
    end
  end

  defp decode_latest_blockhash(other), do: {:error, {:invalid_response, other}}

  @spec decode_simulation(term()) :: {:ok, simulation()} | {:error, {:invalid_response, term()}}
  defp decode_simulation(%{} = value) do
    {:ok, %{err: Map.get(value, "err"), logs: decode_logs(Map.get(value, "logs"))}}
  end

  defp decode_simulation(other), do: {:error, {:invalid_response, other}}

  @spec decode_logs(term()) :: [String.t()] | nil
  defp decode_logs(logs) when is_list(logs), do: Enum.filter(logs, &is_binary/1)
  defp decode_logs(_logs), do: nil

  @spec decode_statuses(term()) ::
          {:ok, [signature_status()]} | {:error, {:invalid_response, term()}}
  defp decode_statuses(value) when is_list(value) do
    {:ok, Enum.map(value, &decode_status/1)}
  end

  defp decode_statuses(other), do: {:error, {:invalid_response, other}}

  @spec decode_status(term()) :: signature_status()
  defp decode_status(%{} = status) do
    %{
      confirmation_status: string_or_nil(Map.get(status, "confirmationStatus")),
      err: Map.get(status, "err")
    }
  end

  defp decode_status(_status), do: nil

  @spec string_or_nil(term()) :: String.t() | nil
  defp string_or_nil(value) when is_binary(value), do: value
  defp string_or_nil(_value), do: nil
end
