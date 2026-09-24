defmodule X402.Extensions.Bazaar.Metadata do
  @moduledoc """
  Validation rules for bazaar service metadata and `routeTemplate` values.

  The bazaar extension lets resource servers publish provider-level metadata
  on the `PaymentRequired.resource` object (`serviceName`, `tags`,
  `iconUrl`) and, for dynamic routes, a top-level `routeTemplate` on the
  extension. Clients echo the `resource` block back to the facilitator, so
  a hostile client could try to poison a discovery catalog through it. The
  extension spec therefore defines *soft-drop* rules every SDK applies
  identically: a field that fails its rule is discarded and the rest of the
  metadata is kept.

  These helpers mirror the reference SDKs' `isValidServiceName`,
  `sanitizeTags`, `isValidIconUrl`, `sanitizeResourceServiceMetadata`, and
  `isValidRouteTemplate`. `X402.Plug.PaymentGate` applies them to its own
  route configuration at init (rejecting invalid values outright, since a
  misconfigured server is a programmer error), and facilitators apply the
  soft-drop form through `sanitize_resource/1` and `extract_route_template/1`
  when cataloging.

  One deliberate deviation: the spec asks for UTS #46 (IDNA) host
  normalization before the loopback / IP-literal checks on `iconUrl`. This
  library carries no IDNA dependency, so any host still containing
  non-ASCII characters after percent-decoding is rejected (fail closed)
  rather than normalized.

  See the
  [bazaar extension spec](https://github.com/x402-foundation/x402/blob/main/specs/extensions/bazaar.md).
  """

  @max_text_length 32
  @max_tags 5
  @max_icon_url_length 2048
  @icon_url_schemes ["http", "https"]
  @loopback_hosts ["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"]
  @route_template_regex ~r"^/[a-zA-Z0-9_/:.\-~%]+$"

  defguardp is_hex(char) when char in ?0..?9 or char in ?a..?f or char in ?A..?F

  @typedoc "A string-keyed `ResourceInfo` map as carried on the wire."
  @type resource :: %{optional(String.t()) => term()}

  @doc since: "0.9.0"
  @doc """
  Checks a `serviceName` value.

  Valid names are non-empty, at most 32 characters long, and made of
  printable ASCII (`U+0020`–`U+007E`) only.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.valid_service_name?("Example Weather")
      true

      iex> X402.Extensions.Bazaar.Metadata.valid_service_name?("")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_service_name?("Wetter für alle")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_service_name?(String.duplicate("a", 33))
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_service_name?(:weather)
      false
  """
  @spec valid_service_name?(term()) :: boolean()
  def valid_service_name?(name), do: printable_ascii_text?(name)

  @doc since: "0.9.0"
  @doc """
  Sanitizes a `tags` value.

  Keeps the entries that pass the `serviceName` rules (non-empty printable
  ASCII, at most 32 characters), drops duplicates case-insensitively
  (first occurrence wins), and truncates the result to the first five
  entries. Anything that is not a list sanitizes to `[]`.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.sanitize_tags(["weather", "Weather", "", "forecast", 42])
      ["weather", "forecast"]

      iex> X402.Extensions.Bazaar.Metadata.sanitize_tags(~w(a b c d e f g))
      ["a", "b", "c", "d", "e"]

      iex> X402.Extensions.Bazaar.Metadata.sanitize_tags("weather")
      []
  """
  @spec sanitize_tags(term()) :: [String.t()]
  def sanitize_tags(tags) when is_list(tags) do
    tags
    |> Enum.filter(&printable_ascii_text?/1)
    |> Enum.uniq_by(&String.downcase/1)
    |> Enum.take(@max_tags)
  end

  def sanitize_tags(_tags), do: []

  @doc since: "0.9.0"
  @doc """
  Checks an `iconUrl` value.

  Valid values are at most 2048 characters, contain no control characters,
  and parse as an absolute `http://` or `https://` URL without userinfo.
  After percent-decoding, the host must not be an IP literal (v4 or v6), a
  loopback name (`localhost`, `localhost.localdomain`, `ip6-localhost`,
  `ip6-loopback`), an all-digit name (a decimal IP encoding such as
  `2130706433`), a hex literal (`0x7f000001`), or contain non-ASCII
  characters.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("https://api.example.com/icon.png")
      true

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("data:image/png;base64,AAAA")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("https://user@api.example.com/icon.png")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("http://127.0.0.1/icon.png")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("http://[::1]/icon.png")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("http://%6cocalhost/icon.png")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("http://2130706433/icon.png")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_icon_url?("http://0x7f000001/icon.png")
      false
  """
  @spec valid_icon_url?(term()) :: boolean()
  def valid_icon_url?(url) when is_binary(url) do
    String.length(url) <= @max_icon_url_length and not contains_control_chars?(url) and
      valid_icon_uri?(URI.new(url))
  end

  def valid_icon_url?(_url), do: false

  @doc since: "0.9.0"
  @doc """
  Applies the soft-drop rules to a string-keyed `ResourceInfo` map.

  Drops `serviceName` and `iconUrl` when they fail their rules, replaces
  `tags` with its sanitized form (dropping the key when nothing valid is
  left), and leaves every other key untouched.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.sanitize_resource(%{
      ...>   "url" => "https://api.example.com/weather",
      ...>   "serviceName" => "Example Weather",
      ...>   "tags" => ["weather", "WEATHER", "forecast"],
      ...>   "iconUrl" => "http://localhost/icon.png"
      ...> })
      %{
        "url" => "https://api.example.com/weather",
        "serviceName" => "Example Weather",
        "tags" => ["weather", "forecast"]
      }

      iex> X402.Extensions.Bazaar.Metadata.sanitize_resource(%{"url" => "https://a.example", "tags" => "nope"})
      %{"url" => "https://a.example"}
  """
  @spec sanitize_resource(resource()) :: resource()
  def sanitize_resource(resource) when is_map(resource) do
    resource
    |> drop_unless("serviceName", &valid_service_name?/1)
    |> drop_unless("iconUrl", &valid_icon_url?/1)
    |> sanitize_tags_field()
  end

  @doc since: "0.9.0"
  @doc """
  Checks a `routeTemplate` value.

  Valid templates are non-empty, start with `/`, match
  `^/[a-zA-Z0-9_/:.\\-~%]+$`, and contain neither `..` nor `://` once
  percent-encoding is decoded.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.valid_route_template?("/users/:userId")
      true

      iex> X402.Extensions.Bazaar.Metadata.valid_route_template?("/users/../admin")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_route_template?("/users/%2e%2e/admin")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_route_template?("/redirect/http://evil.example")
      false

      iex> X402.Extensions.Bazaar.Metadata.valid_route_template?("users/:userId")
      false
  """
  @spec valid_route_template?(term()) :: boolean()
  def valid_route_template?(template) when is_binary(template) do
    Regex.match?(@route_template_regex, template) and
      case percent_decode(template) do
        {:ok, decoded} -> not String.contains?(decoded, ["..", "://"])
        :error -> false
      end
  end

  def valid_route_template?(_template), do: false

  @doc since: "0.9.0"
  @doc """
  Returns the validated `routeTemplate` of a bazaar extension map, or `nil`.

  A facilitator falls back to the concrete URL path when this returns
  `nil`, as the spec requires for absent or invalid templates.

  ## Examples

      iex> X402.Extensions.Bazaar.Metadata.extract_route_template(%{"routeTemplate" => "/users/:userId"})
      "/users/:userId"

      iex> X402.Extensions.Bazaar.Metadata.extract_route_template(%{"routeTemplate" => "../etc"})
      nil

      iex> X402.Extensions.Bazaar.Metadata.extract_route_template(%{"info" => %{}})
      nil
  """
  @spec extract_route_template(term()) :: String.t() | nil
  def extract_route_template(%{"routeTemplate" => template}) do
    if valid_route_template?(template), do: template, else: nil
  end

  def extract_route_template(_extension), do: nil

  @spec printable_ascii_text?(term()) :: boolean()
  defp printable_ascii_text?(text) when is_binary(text) do
    byte_size(text) in 1..@max_text_length and printable_ascii?(text)
  end

  defp printable_ascii_text?(_text), do: false

  @spec printable_ascii?(binary()) :: boolean()
  defp printable_ascii?(<<byte, rest::binary>>) when byte in 0x20..0x7E,
    do: printable_ascii?(rest)

  defp printable_ascii?(<<>>), do: true
  defp printable_ascii?(_other), do: false

  @spec contains_control_chars?(binary()) :: boolean()
  defp contains_control_chars?(<<byte, _rest::binary>>) when byte < 0x20 or byte == 0x7F,
    do: true

  defp contains_control_chars?(<<_byte, rest::binary>>), do: contains_control_chars?(rest)
  defp contains_control_chars?(<<>>), do: false

  @spec valid_icon_uri?({:ok, URI.t()} | {:error, term()}) :: boolean()
  defp valid_icon_uri?({:ok, %URI{scheme: scheme, userinfo: nil, host: host}})
       when scheme in @icon_url_schemes and is_binary(host) and host != "" do
    case percent_decode(host) do
      {:ok, decoded} -> safe_host?(String.downcase(decoded))
      :error -> false
    end
  end

  defp valid_icon_uri?(_uri), do: false

  @spec safe_host?(String.t()) :: boolean()
  defp safe_host?(host) do
    printable_ascii?(host) and host not in @loopback_hosts and
      not Regex.match?(~r/^\d+$/, host) and
      not Regex.match?(~r/^0x[0-9a-f]+$/, host) and
      not ip_literal?(host)
  end

  @spec ip_literal?(String.t()) :: boolean()
  defp ip_literal?(host) do
    match?({:ok, _address}, :inet.parse_address(String.to_charlist(host)))
  end

  # Strict percent-decoding: a `%` not followed by two hex digits makes the
  # whole value invalid, matching the reference SDKs (whose decoders throw
  # on malformed escapes) rather than `URI.decode/1`, which passes them
  # through untouched.
  @spec percent_decode(binary()) :: {:ok, binary()} | :error
  defp percent_decode(value), do: percent_decode(value, <<>>)

  defp percent_decode(<<>>, acc), do: {:ok, acc}

  defp percent_decode(<<?%, hi, lo, rest::binary>>, acc) when is_hex(hi) and is_hex(lo),
    do: percent_decode(rest, <<acc::binary, String.to_integer(<<hi, lo>>, 16)>>)

  defp percent_decode(<<?%, _rest::binary>>, _acc), do: :error

  defp percent_decode(<<byte, rest::binary>>, acc),
    do: percent_decode(rest, <<acc::binary, byte>>)

  @spec drop_unless(resource(), String.t(), (term() -> boolean())) :: resource()
  defp drop_unless(resource, key, valid?) do
    case Map.fetch(resource, key) do
      {:ok, value} -> if valid?.(value), do: resource, else: Map.delete(resource, key)
      :error -> resource
    end
  end

  @spec sanitize_tags_field(resource()) :: resource()
  defp sanitize_tags_field(resource) do
    case Map.fetch(resource, "tags") do
      {:ok, tags} ->
        case sanitize_tags(tags) do
          [] -> Map.delete(resource, "tags")
          sanitized -> Map.put(resource, "tags", sanitized)
        end

      :error ->
        resource
    end
  end
end
