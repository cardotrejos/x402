defmodule X402.Client.Policy do
  @moduledoc """
  Ready-made selection policies for `X402.Client.select_requirements/2`.

  A policy is a 2-arity function receiving a candidate requirements entry
  and the decoded `PaymentRequired` map it came from (`nil` when selecting
  from a bare list). It returns `true` to accept the entry, `false` to skip
  it, or `{:error, reason}` to abort selection with that error. Policies are
  passed with the `:policies` option and every one of them must accept an
  entry for it to be selected:

      X402.Client.Finch.request(MyApp.Finch, url,
        signer: signer,
        policies: [
          X402.Client.Policy.max_amount("1000000"),
          X402.Client.Policy.networks(["eip155:8453", "solana:*"]),
          X402.Client.Policy.assets(["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"])
        ]
      )

  Custom policies are plain functions and compose the same way:

      fn requirements, _payment_required ->
        requirements["payTo"] in MyApp.trusted_receivers()
      end
  """

  alias X402.Utils

  @typedoc "A selection policy."
  @type t :: (map(), map() | nil -> boolean() | {:error, term()})

  @doc since: "0.8.0"
  @doc """
  Accepts entries whose `amount` (atomic units) does not exceed `limit`.

  Entries with a missing or unparsable amount are skipped.

  ## Examples

      iex> policy = X402.Client.Policy.max_amount("10000")
      iex> policy.(%{"amount" => "10000"}, nil)
      true
      iex> policy.(%{"amount" => "10001"}, nil)
      false
      iex> policy.(%{"amount" => "lots"}, nil)
      false

      iex> X402.Client.Policy.max_amount(500).(%{"amount" => "499"}, nil)
      true
  """
  @spec max_amount(String.t() | non_neg_integer()) :: t()
  def max_amount(limit) when is_binary(limit) or (is_integer(limit) and limit >= 0) do
    fn requirements, _payment_required ->
      with {:ok, amount} <-
             Utils.parse_decimal(Utils.map_value(requirements, {"amount", :amount})),
           {:ok, max} <- Utils.parse_decimal(limit) do
        Utils.compare_decimal(amount, max) != :gt
      else
        :error -> false
      end
    end
  end

  @doc since: "0.8.0"
  @doc """
  Accepts entries on one of the given CAIP-2 networks.

  A trailing `*` acts as a prefix wildcard (for example `"eip155:*"`).

  ## Examples

      iex> policy = X402.Client.Policy.networks(["eip155:8453", "solana:*"])
      iex> policy.(%{"network" => "eip155:8453"}, nil)
      true
      iex> policy.(%{"network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}, nil)
      true
      iex> policy.(%{"network" => "eip155:1"}, nil)
      false
  """
  @spec networks([String.t()]) :: t()
  def networks(patterns) when is_list(patterns) do
    fn requirements, _payment_required ->
      case Utils.map_value(requirements, {"network", :network}) do
        network when is_binary(network) -> Enum.any?(patterns, &network_matches?(&1, network))
        _network -> false
      end
    end
  end

  @doc since: "0.8.0"
  @doc """
  Accepts entries paying with one of the given assets (compared
  case-insensitively).

  ## Examples

      iex> policy = X402.Client.Policy.assets(["0x036CbD53842c5426634e7929541eC2318f3dCF7e"])
      iex> policy.(%{"asset" => "0x036cbd53842c5426634e7929541ec2318f3dcf7e"}, nil)
      true
      iex> policy.(%{"asset" => "0x0000000000000000000000000000000000000000"}, nil)
      false
  """
  @spec assets([String.t()]) :: t()
  def assets(assets) when is_list(assets) do
    allowed = MapSet.new(assets, &String.downcase/1)

    fn requirements, _payment_required ->
      case Utils.map_value(requirements, {"asset", :asset}) do
        asset when is_binary(asset) -> MapSet.member?(allowed, String.downcase(asset))
        _asset -> false
      end
    end
  end

  @doc since: "0.8.0"
  @doc """
  Accepts entries using one of the given schemes.

  ## Examples

      iex> policy = X402.Client.Policy.schemes(["exact"])
      iex> policy.(%{"scheme" => "exact"}, nil)
      true
      iex> policy.(%{"scheme" => "upto"}, nil)
      false
  """
  @spec schemes([String.t()]) :: t()
  def schemes(schemes) when is_list(schemes) do
    fn requirements, _payment_required ->
      Utils.map_value(requirements, {"scheme", :scheme}) in schemes
    end
  end

  @spec network_matches?(String.t(), String.t()) :: boolean()
  defp network_matches?(pattern, network) do
    case String.split_at(pattern, -1) do
      {prefix, "*"} -> String.starts_with?(network, prefix)
      _exact -> pattern == network
    end
  end
end
