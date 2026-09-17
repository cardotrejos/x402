defmodule X402.RateLimiter.ETS do
  @sweep_every 1_000

  @moduledoc """
  Per-node fixed-window rate limiter backed by a lazily created ETS table.

  Each key owns one counter per window: the first hit opens a window of
  `window_ms` and every hit until it closes increments the counter, so a
  key may make at most `limit` hits per window. Once the window closes the
  next hit opens a fresh one. Fixed windows admit up to `2 × limit` hits
  across a window boundary; pick `limit`/`window_ms` with that in mind.

  The table is created on first use and needs no process in your
  supervision tree. Stale windows are swept opportunistically (every
  #{@sweep_every} hits) and can be swept explicitly with `sweep/1`.

  > #### Per-node only {: .warning}
  >
  > Counters live on the local node. In a clustered deployment each node
  > limits independently, so a wallet load-balanced across `n` nodes gets
  > up to `n × limit` hits per window. Use a shared-store implementation of
  > `X402.RateLimiter` when that matters.
  """

  @behaviour X402.RateLimiter

  alias X402.ETSTable

  @default_table __MODULE__
  @hits_key :"$x402_hits"
  @max_cas_attempts 16

  @typedoc "ETS table name holding the counters."
  @type table :: atom()

  @doc since: "0.9.0"
  @doc """
  Records a hit for `key` in the fixed window of `window_ms` milliseconds.

  `table` is the ETS table name; `nil` selects the default table.

  ## Examples

      iex> table = String.to_atom("rate_limiter_doctest_#{System.unique_integer([:positive])}")
      iex> X402.RateLimiter.ETS.hit(table, {:payer, "0xabc"}, 2, 60_000)
      {:allow, 1}
      iex> X402.RateLimiter.ETS.hit(table, {:payer, "0xabc"}, 2, 60_000)
      {:allow, 0}
      iex> {:deny, retry_after_ms} = X402.RateLimiter.ETS.hit(table, {:payer, "0xabc"}, 2, 60_000)
      iex> retry_after_ms in 1..60_000
      true
  """
  @impl X402.RateLimiter
  @spec hit(table() | nil, X402.RateLimiter.key(), pos_integer(), pos_integer()) ::
          X402.RateLimiter.result()
  def hit(table, key, limit, window_ms)
      when is_integer(limit) and limit > 0 and is_integer(window_ms) and window_ms > 0 do
    table = ensure_table(table)
    maybe_sweep(table)
    # Binary keys bind directly in match heads without interpreting arbitrary
    # user terms as match-spec variables or colliding with the sweep counter.
    key = :erlang.term_to_binary(key, [:deterministic])
    do_hit(table, key, limit, window_ms, 0)
  end

  @doc since: "0.9.0"
  @doc """
  Removes windows that have already closed.

  Returns the number of rows removed.
  """
  @spec sweep(table() | nil) :: non_neg_integer()
  def sweep(table \\ nil) do
    table = ensure_table(table)
    now = now_ms()

    :ets.select_delete(table, [
      {{:"$1", :"$2", :"$3", :"$4"}, [{:<, :"$4", now}], [true]}
    ])
  end

  @doc since: "0.9.0"
  @doc """
  Clears every counter in the table.
  """
  @spec reset(table() | nil) :: :ok
  def reset(table \\ nil) do
    table = ensure_table(table)

    :ets.select_delete(table, [{{:"$1", :"$2", :"$3", :"$4"}, [], [true]}])
    :ets.delete(table, @hits_key)
    :ok
  end

  defp do_hit(_table, _key, _limit, _window_ms, @max_cas_attempts),
    do: {:error, :contention}

  defp do_hit(table, key, limit, window_ms, attempts) do
    now = now_ms()

    # Increment and read the window atomically; the default row also handles
    # a concurrent sweep without a lookup/update race that could fail open.
    [count, window_end] =
      :ets.update_counter(table, key, [{2, 1}, {4, 0}], {key, 0, now, now + window_ms})

    if now < window_end do
      result(count, limit, window_end - now)
    else
      # Only one hit replaces the expired window. Counts in that expired
      # window no longer matter; a losing hit retries against the new one.
      replaced =
        :ets.select_replace(table, [
          {{key, :_, :_, window_end}, [], [{:const, {key, 1, now, now + window_ms}}]}
        ])

      case replaced do
        1 -> {:allow, limit - 1}
        0 -> do_hit(table, key, limit, window_ms, attempts + 1)
      end
    end
  end

  defp result(count, limit, _retry_after_ms) when count <= limit, do: {:allow, limit - count}
  defp result(_count, _limit, retry_after_ms), do: {:deny, retry_after_ms}

  defp maybe_sweep(table) do
    case :ets.update_counter(table, @hits_key, {2, 1, @sweep_every, 0}, {@hits_key, 0}) do
      0 -> sweep(table)
      _count -> :ok
    end
  end

  defp ensure_table(nil), do: ensure_table(@default_table)

  defp ensure_table(table) when is_atom(table),
    do: ETSTable.ensure(table, [:set, read_concurrency: true, write_concurrency: true])

  defp now_ms, do: System.monotonic_time(:millisecond)
end
