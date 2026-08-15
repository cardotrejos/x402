defmodule X402.PaymentRequirements do
  @moduledoc """
  Validation and matching helpers for x402 v2 payment requirements.

  A client's `PaymentPayload.accepted` value must preserve every core field
  advertised by the resource server. Server-declared `extra` values are matched
  as a recursive subset so clients may append scheme-specific metadata without
  changing the server's payment terms.
  """

  @required_string_fields ~w(scheme network amount asset payTo)

  @type validation_error ::
          {:missing_fields, [String.t()]}
          | {:invalid_fields, [String.t()]}

  @doc since: "0.4.0"
  @doc """
  Validates the required x402 v2 `PaymentRequirements` fields.

  ## Examples

      iex> requirements = %{
      ...>   "scheme" => "exact",
      ...>   "network" => "eip155:84532",
      ...>   "amount" => "10000",
      ...>   "asset" => "0xasset",
      ...>   "payTo" => "0xreceiver",
      ...>   "maxTimeoutSeconds" => 60,
      ...>   "extra" => %{}
      ...> }
      iex> X402.PaymentRequirements.validate(requirements)
      :ok

      iex> X402.PaymentRequirements.validate(%{})
      {:error, {:missing_fields, ["amount", "asset", "extra", "maxTimeoutSeconds", "network", "payTo", "scheme"]}}
  """
  @spec validate(term()) :: :ok | {:error, validation_error() | :invalid_payment_requirements}
  def validate(requirements) when is_map(requirements) do
    normalized = normalize(requirements)
    missing = missing_fields(normalized)
    invalid = invalid_fields(normalized)

    cond do
      missing != [] ->
        {:error, {:missing_fields, missing}}

      invalid != [] ->
        {:error, {:invalid_fields, invalid}}

      true ->
        :ok
    end
  end

  def validate(_requirements), do: {:error, :invalid_payment_requirements}

  @doc since: "0.4.0"
  @doc """
  Returns whether a client-selected requirement preserves the server requirement.

  Core fields must be equal. The client may add fields under `extra`, but it
  cannot remove or change values advertised by the server.

  ## Examples

      iex> required = %{"scheme" => "exact", "extra" => %{"name" => "USDC"}}
      iex> accepted = %{"scheme" => "exact", "extra" => %{"name" => "USDC", "version" => "2"}}
      iex> X402.PaymentRequirements.match?(required, accepted)
      true

      iex> required = %{"scheme" => "exact", "extra" => %{"name" => "USDC"}}
      iex> X402.PaymentRequirements.match?(required, %{"scheme" => "exact", "extra" => %{}})
      false
  """
  @spec match?(term(), term()) :: boolean()
  def match?(required, accepted) when is_map(required) and is_map(accepted) do
    required = normalize(required)
    accepted = normalize(accepted)
    required_extra = Map.get(required, "extra", %{})
    accepted_extra = Map.get(accepted, "extra", %{})

    accepted_preserves_extra =
      not Map.has_key?(required, "extra") or
        (Map.has_key?(accepted, "extra") and subset?(required_extra, accepted_extra))

    Map.delete(required, "extra") == Map.delete(accepted, "extra") and
      accepted_preserves_extra
  end

  def match?(_required, _accepted), do: false

  @doc since: "0.4.0"
  @doc """
  Returns whether client extension echoes preserve advertised extension values.

  Omitting extensions is accepted for compatibility with the reference SDK.
  When the client echoes an advertised extension, every server-provided value
  must be retained.

  ## Examples

      iex> advertised = %{"example" => %{"info" => %{"required" => true}}}
      iex> echoed = %{"example" => %{"info" => %{"required" => true, "client" => "value"}}}
      iex> X402.PaymentRequirements.extensions_match?(advertised, echoed)
      true
  """
  @spec extensions_match?(term(), term()) :: boolean()
  def extensions_match?(advertised, echoed) when is_map(advertised) do
    advertised = normalize(advertised)

    case normalize_optional_map(echoed) do
      {:ok, client_extensions} when map_size(client_extensions) == 0 ->
        true

      {:ok, client_extensions} ->
        Enum.all?(client_extensions, &extension_matches?(advertised, &1))

      :error ->
        false
    end
  end

  def extensions_match?(_advertised, _echoed), do: false

  @spec extension_matches?(map(), {term(), term()}) :: boolean()
  defp extension_matches?(advertised, {key, client_value}) do
    case Map.fetch(advertised, key) do
      {:ok, advertised_value} ->
        subset?(extension_info(advertised_value), extension_info(client_value))

      :error ->
        true
    end
  end

  @doc false
  @spec normalize(term()) :: term()
  def normalize(value) when is_map(value) do
    Map.new(value, fn {key, nested_value} ->
      {normalize_key(key), normalize(nested_value)}
    end)
  end

  def normalize(value) when is_list(value), do: Enum.map(value, &normalize/1)
  def normalize(value), do: value

  @spec normalize_optional_map(term()) :: {:ok, map()} | :error
  defp normalize_optional_map(nil), do: {:ok, %{}}
  defp normalize_optional_map(value) when is_map(value), do: {:ok, normalize(value)}
  defp normalize_optional_map(_value), do: :error

  @spec extension_info(term()) :: term()
  defp extension_info(value) when is_map(value) do
    case Map.fetch(value, "info") do
      {:ok, info} -> info
      :error -> value
    end
  end

  defp extension_info(value), do: value

  @spec normalize_key(term()) :: term()
  defp normalize_key(key) when is_atom(key), do: Atom.to_string(key)
  defp normalize_key(key), do: key

  @spec missing_fields(map()) :: [String.t()]
  defp missing_fields(requirements) do
    required_fields = @required_string_fields ++ ["extra", "maxTimeoutSeconds"]

    required_fields
    |> Enum.reject(&Map.has_key?(requirements, &1))
    |> Enum.sort()
  end

  @spec invalid_fields(map()) :: [String.t()]
  defp invalid_fields(requirements) do
    string_errors =
      Enum.reject(@required_string_fields, fn field ->
        valid_string_field?(field, Map.get(requirements, field))
      end)

    timeout_errors =
      case Map.get(requirements, "maxTimeoutSeconds") do
        value when is_integer(value) and value > 0 -> []
        _value -> ["maxTimeoutSeconds"]
      end

    extra_errors =
      case Map.fetch(requirements, "extra") do
        :error -> []
        {:ok, value} when is_map(value) -> []
        {:ok, _value} -> ["extra"]
      end

    (string_errors ++ timeout_errors ++ extra_errors)
    |> Enum.uniq()
    |> Enum.sort()
  end

  @spec valid_string_field?(String.t(), term()) :: boolean()
  defp valid_string_field?("amount", value) when is_binary(value),
    do: Regex.match?(~r/^\d+$/, value)

  defp valid_string_field?(_field, value), do: is_binary(value) and value != ""

  @spec subset?(term(), term()) :: boolean()
  defp subset?(expected, actual) when is_map(expected) and is_map(actual) do
    Enum.all?(expected, fn {key, expected_value} ->
      case Map.fetch(actual, key) do
        {:ok, actual_value} -> subset?(expected_value, actual_value)
        :error -> false
      end
    end)
  end

  defp subset?(expected, actual), do: expected == actual
end
