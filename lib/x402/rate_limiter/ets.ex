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

      iex> table = :"rate_limiter_doctest_#{System.unique_integer([:positive])}"
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
    do_hit(table, key, limit, window_ms, now_ms(), 0)
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

  # Two hits racing on the same closed window must not both open a new one
  # (the second would reset the count), so replacement is a compare-and-swap
  # on the exact row that was read; the loser re-reads and retries.
  defp do_hit(_table, _key, _limit, _window_ms, _now, @max_cas_attempts),
    do: {:error, :contention}

  defp do_hit(table, key, limit, window_ms, now, attempts) do
    case :ets.lookup(table, key) do
      [{^key, _count, _window_start, window_end}] when now < window_end ->
        count = :ets.update_counter(table, key, {2, 1})
        result(table, key, count, limit, window_end, now)

      [{^key, count, window_start, window_end}] ->
        replaced =
          :ets.select_replace(table, [
            {
              {:"$1", :"$2", :"$3", :"$4"},
              [
                {:"=:=", :"$1", {:const, key}},
                {:"=:=", :"$2", count},
                {:"=:=", :"$3", window_start},
                {:"=:=", :"$4", window_end}
              ],
              [{{:"$1", 1, now, now + window_ms}}]
            }
          ])

        case replaced do
          1 -> {:allow, limit - 1}
          0 -> do_hit(table, key, limit, window_ms, now, attempts + 1)
        end

      [] ->
        case :ets.insert_new(table, {key, 1, now, now + window_ms}) do
          true -> {:allow, limit - 1}
          false -> do_hit(table, key, limit, window_ms, now, attempts + 1)
        end
    end
  end

  defp result(_table, _key, count, limit, _window_end, _now) when count <= limit,
    do: {:allow, limit - count}

  # The window may have rolled over between the lookup and the increment,
  # in which case the increment landed in the new window and the fresh
  # row's end is the one to report.
  defp result(table, key, _count, _limit, window_end, now) do
    current_end =
      case :ets.lookup(table, key) do
        [{^key, _count, _start, current_end}] -> current_end
        [] -> window_end
      end

    {:deny, max(current_end - now, 1)}
  end

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
