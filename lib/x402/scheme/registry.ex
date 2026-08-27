defmodule X402.Scheme.Registry do
  @moduledoc """
  Resolves (scheme, network) pairs to `X402.Scheme` modules.

  The default mapping is seeded with the built-in schemes —
  `X402.Scheme.ExactEVM` (`"exact"` on `"eip155:*"`),
  `X402.Scheme.ExactSVM` (`"exact"` on `"solana:*"`), and
  `X402.Scheme.UptoEVM` (`"upto"` on `"eip155:*"`). There is no global
  registration and no application environment: callers pass additional
  scheme modules explicitly (the `:schemes` option on
  `X402.Client.build_payment/3`, `X402.Plug.PaymentGate`, and
  `X402.PaymentSignature.validate/3`), and those are consulted **before**
  the built-ins, so a user module can override a built-in kind.

  ## Resolution semantics

  Candidate modules are the extra schemes followed by the built-ins,
  filtered to those whose `c:X402.Scheme.scheme/0` equals the requested
  scheme. Among candidates, the network decides:

  1. An **exact** CAIP-2 match in `c:X402.Scheme.networks/0` always wins
     over any wildcard match; ties go to the earlier module in the list.
  2. Otherwise the **wildcard** patterns (trailing `*`, matched as a
     prefix — `"eip155:*"`, or `"*"` for any network) are consulted; the
     longest (most specific) matching pattern wins, and ties go to the
     earlier module in the list.

  Kinds that resolve to no module return `:error`; callers treat that as
  "no scheme module registered" and fall back to their historical neutral
  behavior (pass-through validation, skipped pre-checks, or the client's
  `{:unsupported_kind, scheme, network}` error).

  ## Examples

      iex> X402.Scheme.Registry.resolve("exact", "eip155:8453")
      {:ok, X402.Scheme.ExactEVM}

      iex> X402.Scheme.Registry.resolve("upto", "eip155:84532")
      {:ok, X402.Scheme.UptoEVM}

      iex> X402.Scheme.Registry.resolve("exact", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      {:ok, X402.Scheme.ExactSVM}
  """

  @builtins [X402.Scheme.ExactEVM, X402.Scheme.ExactSVM, X402.Scheme.UptoEVM]

  @doc since: "0.6.0"
  @doc """
  Returns the built-in scheme modules, in consultation order.

  ## Examples

      iex> X402.Scheme.Registry.builtins()
      [X402.Scheme.ExactEVM, X402.Scheme.ExactSVM, X402.Scheme.UptoEVM]
  """
  @spec builtins() :: [module()]
  def builtins, do: @builtins

  @doc since: "0.6.0"
  @doc """
  Resolves a (scheme, network) pair to a scheme module.

  `extra_schemes` are consulted before the built-ins. Non-binary scheme or
  network values resolve to `:error`.

  ## Examples

      iex> X402.Scheme.Registry.resolve([], "exact", "eip155:1")
      {:ok, X402.Scheme.ExactEVM}

      iex> X402.Scheme.Registry.resolve([], "cash", "eip155:1")
      :error

      iex> X402.Scheme.Registry.resolve([], nil, "eip155:1")
      :error
  """
  @spec resolve([module()], term(), term()) :: {:ok, module()} | :error
  def resolve(extra_schemes \\ [], scheme, network)

  def resolve(extra_schemes, scheme, network)
      when is_list(extra_schemes) and is_binary(scheme) and is_binary(network) do
    candidates =
      (extra_schemes ++ @builtins)
      |> Enum.uniq()
      |> Enum.filter(&(&1.scheme() == scheme))

    with :error <- exact_match(candidates, network) do
      wildcard_match(candidates, network)
    end
  end

  def resolve(_extra_schemes, _scheme, _network), do: :error

  @doc since: "0.6.0"
  @doc """
  Returns whether a CAIP-2 network matches a network pattern.

  A pattern ending in `*` matches any network starting with the prefix
  before it; any other pattern must match exactly.

  ## Examples

      iex> X402.Scheme.Registry.network_matches?("eip155:*", "eip155:8453")
      true

      iex> X402.Scheme.Registry.network_matches?("eip155:8453", "eip155:1")
      false

      iex> X402.Scheme.Registry.network_matches?("*", "solana:mainnet")
      true
  """
  @spec network_matches?(String.t(), String.t()) :: boolean()
  def network_matches?(pattern, network) when is_binary(pattern) and is_binary(network) do
    case String.split_at(pattern, -1) do
      {prefix, "*"} -> String.starts_with?(network, prefix)
      _exact -> pattern == network
    end
  end

  def network_matches?(_pattern, _network), do: false

  @spec exact_match([module()], String.t()) :: {:ok, module()} | :error
  defp exact_match(candidates, network) do
    case Enum.find(candidates, &(network in &1.networks())) do
      nil -> :error
      module -> {:ok, module}
    end
  end

  @spec wildcard_match([module()], String.t()) :: {:ok, module()} | :error
  defp wildcard_match(candidates, network) do
    candidates
    |> Enum.with_index()
    |> Enum.flat_map(fn {module, index} ->
      for pattern <- module.networks(),
          String.ends_with?(pattern, "*"),
          network_matches?(pattern, network),
          do: {byte_size(pattern), index, module}
    end)
    |> most_specific()
  end

  # Longest pattern (most specific prefix) wins; ties go to list order.
  @spec most_specific([{non_neg_integer(), non_neg_integer(), module()}]) ::
          {:ok, module()} | :error
  defp most_specific([]), do: :error

  defp most_specific(matches) do
    {_size, _index, module} =
      Enum.min_by(matches, fn {size, index, _module} -> {-size, index} end)

    {:ok, module}
  end
end
