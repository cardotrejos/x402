defmodule X402.TestAuthCapture do
  @moduledoc false

  alias X402.Signer.LocalKey

  @fixture_path Path.expand("../fixtures/auth_capture.json", __DIR__)
  @external_resource @fixture_path
  @fixture @fixture_path |> File.read!() |> Jason.decode!()

  @spec fixture() :: map()
  def fixture, do: @fixture

  @spec vector(String.t()) :: map()
  def vector(id \\ "v1_1_bound_eip3009"),
    do: Enum.find(@fixture["vectors"], &(&1["id"] == id))

  @spec envelope(map()) :: map()
  def envelope(vector),
    do: %{
      "x402Version" => 2,
      "accepted" => vector["requirements"],
      "payload" => vector["payload"]
    }

  @spec lifecycle(map(), String.t()) :: map()
  def lifecycle(vector, operation) do
    consent = vector["consents"][operation]

    payload =
      consent["params"]
      |> Map.drop(["paymentInfoHash", "tokenCollector", "collectorDataHash"])
      |> Map.merge(%{
        "type" => operation,
        "paymentInfo" => vector["info"],
        "saltNonce" => vector["salt_nonce"],
        "authorizerSignature" => consent["signature"]
      })

    Map.put(envelope(vector), "payload", payload)
  end

  @spec charge(map()) :: map()
  def charge(vector) do
    requirements =
      update_in(vector["requirements"], ["extra"], fn extra ->
        extra |> Map.put("paymentFlow", "authorization") |> Map.delete("captureMode")
      end)

    completion =
      vector["consents"]["charge"]["params"]
      |> Map.drop(["paymentInfoHash", "tokenCollector", "collectorDataHash"])
      |> Map.put("authorizerSignature", vector["consents"]["charge"]["signature"])

    envelope(vector)
    |> Map.put("accepted", requirements)
    |> Map.update!("payload", &Map.merge(&1, completion))
  end

  @spec bytes(String.t()) :: binary()
  def bytes("0x" <> hex), do: Base.decode16!(hex, case: :mixed)

  @spec hex(binary()) :: String.t()
  def hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)

  @spec normalize_typed_data(map()) :: map()
  def normalize_typed_data(data) do
    data
    |> Jason.encode!()
    |> Jason.decode!()
    |> Map.update!("domain", fn domain ->
      domain
      |> Map.update!("chainId", &chain_id/1)
      |> normalize_addresses()
    end)
    |> Map.update!("message", &normalize_addresses/1)
  end

  @spec chain_id(term()) :: term()
  defp chain_id("0x" <> hex), do: String.to_integer(hex, 16)
  defp chain_id(value), do: value

  @spec normalize_addresses(term()) :: term()
  defp normalize_addresses(map) when is_map(map),
    do: Map.new(map, fn {key, value} -> {key, normalize_addresses(value)} end)

  defp normalize_addresses("0x" <> hex = value) when byte_size(hex) == 40,
    do: String.downcase(value)

  defp normalize_addresses(value), do: value

  defmodule RecordingSigner do
    @moduledoc false
    @behaviour X402.Signer
    defstruct [:owner, :inner]

    @impl true
    @spec address(struct()) :: {:ok, String.t()}
    def address(%{inner: inner}), do: LocalKey.address(inner)

    @impl true
    @spec sign_eip712(struct(), binary(), map()) :: {:ok, binary()} | {:error, term()}
    def sign_eip712(%{owner: owner, inner: inner}, digest, typed_data) do
      send(owner, {:signed, digest, typed_data})
      LocalKey.sign_eip712(inner, digest, typed_data)
    end
  end
end
