defmodule X402.Extensions.SIWX.Message do
  @moduledoc """
  CAIP-122 message text for Sign-In-With-X challenges.

  Builds the exact text a wallet signs for a SIWX proof, routed by the
  CAIP-2 namespace of `chainId`:

  * `eip155:*` — [EIP-4361 (Sign-In With Ethereum)](https://eips.ethereum.org/EIPS/eip-4361),
    whose `Chain ID` line carries the numeric chain reference. When no
    statement is present the address is followed by two blank lines, as the
    EIP-4361 ABNF (and the reference `siwe` library) produce.
  * `solana:*` — [Sign-In With Solana](https://github.com/phantom/sign-in-with-solana),
    identical apart from the `Solana account` header and the genesis-hash
    chain reference. Without a statement the address is followed by a single
    blank line, matching the reference x402 implementation.

  Field values are read from the wire (camelCase string) keys or their
  snake_case atom equivalents, so both a decoded `SIGN-IN-WITH-X` payload
  and a locally built map work.
  """

  alias X402.Utils

  @evm_suffix " wants you to sign in with your Ethereum account:"
  @solana_suffix " wants you to sign in with your Solana account:"

  @typedoc "Chain family derived from a CAIP-2 chain id."
  @type family :: :eip155 | :solana

  @typedoc "Errors returned by `build/1`."
  @type build_error :: :invalid_fields | :invalid_chain_id | :unsupported_chain

  @doc since: "0.7.0"
  @doc """
  Returns the chain family of a CAIP-2 chain id.

  ## Examples

      iex> X402.Extensions.SIWX.Message.family("eip155:8453")
      {:ok, :eip155}

      iex> X402.Extensions.SIWX.Message.family("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      {:ok, :solana}

      iex> X402.Extensions.SIWX.Message.family("eip155:base")
      {:error, :invalid_chain_id}

      iex> X402.Extensions.SIWX.Message.family("cosmos:hub")
      {:error, :unsupported_chain}
  """
  @spec family(term()) :: {:ok, family()} | {:error, :invalid_chain_id | :unsupported_chain}
  def family("eip155:" <> reference) do
    case reference =~ ~r/\A[1-9][0-9]*\z/ do
      true -> {:ok, :eip155}
      false -> {:error, :invalid_chain_id}
    end
  end

  def family("solana:" <> reference) do
    case reference =~ ~r/\A[1-9A-HJ-NP-Za-km-z]{1,44}\z/ do
      true -> {:ok, :solana}
      false -> {:error, :invalid_chain_id}
    end
  end

  def family(_chain_id), do: {:error, :unsupported_chain}

  @doc since: "0.7.0"
  @doc """
  Returns the signature `type` a chain family authenticates with.

  ## Examples

      iex> X402.Extensions.SIWX.Message.signature_type(:eip155)
      "eip191"

      iex> X402.Extensions.SIWX.Message.signature_type(:solana)
      "ed25519"
  """
  @spec signature_type(family()) :: String.t()
  def signature_type(:eip155), do: "eip191"
  def signature_type(:solana), do: "ed25519"

  @doc since: "0.7.0"
  @doc """
  Builds the CAIP-122 message text for a fields map.

  Requires `domain`, `address`, `uri`, `version`, `chainId`, `nonce`, and
  `issuedAt`; `statement`, `expirationTime`, `notBefore`, `requestId`, and
  `resources` are optional and omitted from the text when absent (an empty
  `resources` list is treated as absent).

  ## Examples

      iex> {:ok, text} = X402.Extensions.SIWX.Message.build(%{
      ...>   "domain" => "api.example.com",
      ...>   "address" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   "statement" => "Sign in to access premium data",
      ...>   "uri" => "https://api.example.com/premium-data",
      ...>   "version" => "1",
      ...>   "chainId" => "eip155:8453",
      ...>   "nonce" => "a1b2c3d4e5f67890a1b2c3d4e5f67890",
      ...>   "issuedAt" => "2024-01-15T10:30:00.000Z",
      ...>   "expirationTime" => "2024-01-15T10:35:00.000Z",
      ...>   "resources" => ["https://api.example.com/premium-data"]
      ...> })
      iex> String.split(text, "\\n")
      [
        "api.example.com wants you to sign in with your Ethereum account:",
        "0x857b06519E91e3A54538791bDbb0E22373e36b66",
        "",
        "Sign in to access premium data",
        "",
        "URI: https://api.example.com/premium-data",
        "Version: 1",
        "Chain ID: 8453",
        "Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "Issued At: 2024-01-15T10:30:00.000Z",
        "Expiration Time: 2024-01-15T10:35:00.000Z",
        "Resources:",
        "- https://api.example.com/premium-data"
      ]

      iex> X402.Extensions.SIWX.Message.build(%{"domain" => "api.example.com"})
      {:error, :invalid_fields}
  """
  @spec build(map()) :: {:ok, String.t()} | {:error, build_error()}
  def build(fields) when is_map(fields) do
    with {:ok, required} <- required_fields(fields),
         {:ok, family} <- family(required.chain_id) do
      {:ok, render(family, required, optional_fields(fields))}
    end
  end

  def build(_fields), do: {:error, :invalid_fields}

  @spec render(family(), map(), map()) :: String.t()
  defp render(family, required, optional) do
    header = [required.domain <> header_suffix(family), required.address]
    body = statement_lines(family, optional[:statement])

    suffix =
      [
        "URI: " <> required.uri,
        "Version: " <> required.version,
        "Chain ID: " <> chain_reference(required.chain_id),
        "Nonce: " <> required.nonce,
        "Issued At: " <> required.issued_at
      ] ++
        optional_line("Expiration Time: ", optional[:expiration_time]) ++
        optional_line("Not Before: ", optional[:not_before]) ++
        optional_line("Request ID: ", optional[:request_id]) ++
        resource_lines(optional[:resources])

    Enum.join(header ++ body ++ suffix, "\n")
  end

  @spec header_suffix(family()) :: String.t()
  defp header_suffix(:eip155), do: @evm_suffix
  defp header_suffix(:solana), do: @solana_suffix

  # With a statement both formats emit `"", statement, ""`. Without one the
  # EIP-4361 ABNF keeps two empty lines while SIWS keeps one.
  @spec statement_lines(family(), String.t() | nil) :: [String.t()]
  defp statement_lines(_family, statement) when is_binary(statement), do: ["", statement, ""]
  defp statement_lines(:eip155, nil), do: ["", ""]
  defp statement_lines(:solana, nil), do: [""]

  @spec optional_line(String.t(), String.t() | nil) :: [String.t()]
  defp optional_line(_prefix, nil), do: []
  defp optional_line(prefix, value), do: [prefix <> value]

  @spec resource_lines([String.t()] | nil) :: [String.t()]
  defp resource_lines(nil), do: []
  defp resource_lines([]), do: []
  defp resource_lines(resources), do: ["Resources:" | Enum.map(resources, &("- " <> &1))]

  @doc since: "0.7.0"
  @doc """
  Returns the chain reference rendered on the `Chain ID` line.

  ## Examples

      iex> X402.Extensions.SIWX.Message.chain_reference("eip155:8453")
      "8453"

      iex> X402.Extensions.SIWX.Message.chain_reference("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  """
  @spec chain_reference(String.t()) :: String.t()
  def chain_reference(chain_id) when is_binary(chain_id) do
    case String.split(chain_id, ":", parts: 2) do
      [_namespace, reference] -> reference
      [reference] -> reference
    end
  end

  @required [
    {:domain, {"domain", :domain}},
    {:address, {"address", :address}},
    {:uri, {"uri", :uri}},
    {:version, {"version", :version}},
    {:chain_id, {"chainId", :chain_id}},
    {:nonce, {"nonce", :nonce}},
    {:issued_at, {"issuedAt", :issued_at}}
  ]

  @optional [
    {:statement, {"statement", :statement}},
    {:expiration_time, {"expirationTime", :expiration_time}},
    {:not_before, {"notBefore", :not_before}},
    {:request_id, {"requestId", :request_id}}
  ]

  @spec required_fields(map()) :: {:ok, map()} | {:error, :invalid_fields}
  defp required_fields(fields) do
    Enum.reduce_while(@required, {:ok, %{}}, fn {name, keys}, {:ok, acc} ->
      case Utils.map_value(fields, keys) do
        value when is_binary(value) and value != "" -> {:cont, {:ok, Map.put(acc, name, value)}}
        _other -> {:halt, {:error, :invalid_fields}}
      end
    end)
  end

  @spec optional_fields(map()) :: map()
  defp optional_fields(fields) do
    optional =
      Map.new(@optional, fn {name, keys} ->
        case Utils.map_value(fields, keys) do
          value when is_binary(value) and value != "" -> {name, value}
          _other -> {name, nil}
        end
      end)

    resources =
      case Utils.map_value(fields, {"resources", :resources}) do
        list when is_list(list) -> Enum.filter(list, &is_binary/1)
        _other -> nil
      end

    Map.put(optional, :resources, resources)
  end
end
