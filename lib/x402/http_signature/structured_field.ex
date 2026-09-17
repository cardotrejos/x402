defmodule X402.HTTPSignature.StructuredField do
  @moduledoc """
  The RFC 8941 Structured Field subset used by HTTP Message Signatures.

  `Signature-Input` and `Signature` (RFC 9421 §4) are Dictionary fields
  whose members are a parameterized Inner List of Strings and a Byte
  Sequence respectively. This module serializes and parses exactly the
  grammar those fields need, using the strict rules of RFC 8941 §4 so
  that a value parsed and re-serialized reproduces the bytes a signer
  hashed.

  ## Representation

  | Wire type     | Elixir value                                   |
  | ------------- | ---------------------------------------------- |
  | String        | `binary`                                       |
  | Integer       | `integer`                                      |
  | Decimal       | `float`                                        |
  | Boolean       | `boolean`                                      |
  | Token         | `{:token, binary}`                             |
  | Byte Sequence | `{:bytes, binary}`                             |
  | Item          | `{bare_item, params}`                          |
  | Inner List    | `{:inner_list, [item], params}`                |
  | Parameters    | `[{key, bare_item}]` (ordered)                 |
  | Dictionary    | `[{key, item | inner_list}]` (ordered)         |

  Strings and Tokens are distinct wire types, so a bare `binary` always
  serializes as a quoted String.
  """

  @typedoc "A bare item value."
  @type bare ::
          binary() | integer() | float() | boolean() | {:token, binary()} | {:bytes, binary()}

  @typedoc "Ordered parameters."
  @type params :: [{binary(), bare()}]

  @typedoc "An item with its parameters."
  @type item :: {bare(), params()}

  @typedoc "An inner list with its parameters."
  @type inner_list :: {:inner_list, [item()], params()}

  @typedoc "A dictionary member value."
  @type member :: item() | inner_list()

  @typedoc "An ordered dictionary."
  @type dictionary :: [{binary(), member()}]

  @type error :: :invalid_structured_field | :duplicate_key

  @max_integer 999_999_999_999_999

  # -- Serialization ----------------------------------------------------------

  @doc since: "0.9.0"
  @doc """
  Serializes a dictionary (RFC 8941 §4.1.2).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.serialize_dictionary([
      ...>   {"sig1", {:inner_list, [{"@method", []}], [{"created", 1_618_884_473}]}}
      ...> ])
      {:ok, ~S|sig1=("@method");created=1618884473|}

      iex> X402.HTTPSignature.StructuredField.serialize_dictionary([{"sig1", {{:bytes, "abc"}, []}}])
      {:ok, "sig1=:YWJj:"}

      iex> X402.HTTPSignature.StructuredField.serialize_dictionary([{"Sig", {1, []}}])
      {:error, :invalid_structured_field}
  """
  @spec serialize_dictionary(dictionary()) :: {:ok, binary()} | {:error, error()}
  def serialize_dictionary(members) when is_list(members) do
    with {:ok, parts} <- map_all(members, &serialize_member/1) do
      {:ok, Enum.join(parts, ", ")}
    end
  end

  @spec serialize_member({binary(), member()}) :: {:ok, binary()} | {:error, error()}
  defp serialize_member({key, {true, params}}) do
    with {:ok, key} <- serialize_key(key),
         {:ok, params} <- serialize_params(params) do
      {:ok, key <> params}
    end
  end

  defp serialize_member({key, value}) do
    with {:ok, key} <- serialize_key(key),
         {:ok, value} <- serialize_member_value(value) do
      {:ok, key <> "=" <> value}
    end
  end

  @spec serialize_member_value(member()) :: {:ok, binary()} | {:error, error()}
  defp serialize_member_value({:inner_list, _items, _params} = list),
    do: serialize_inner_list(list)

  defp serialize_member_value({_bare, _params} = item), do: serialize_item(item)

  @doc since: "0.9.0"
  @doc """
  Serializes an inner list with parameters (RFC 8941 §4.1.1.1).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.serialize_inner_list(
      ...>   {:inner_list, [{"@query-param", [{"name", "Pet"}]}, {"@path", [{"req", true}]}], [{"tag", "x"}]}
      ...> )
      {:ok, ~S|("@query-param";name="Pet" "@path";req);tag="x"|}

      iex> X402.HTTPSignature.StructuredField.serialize_inner_list({:inner_list, [], []})
      {:ok, "()"}
  """
  @spec serialize_inner_list(inner_list()) :: {:ok, binary()} | {:error, error()}
  def serialize_inner_list({:inner_list, items, params})
      when is_list(items) and is_list(params) do
    with {:ok, items} <- map_all(items, &serialize_item/1),
         {:ok, params} <- serialize_params(params) do
      {:ok, "(" <> Enum.join(items, " ") <> ")" <> params}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Serializes an item with parameters (RFC 8941 §4.1.3).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.serialize_item({"content-type", []})
      {:ok, ~S|"content-type"|}

      iex> X402.HTTPSignature.StructuredField.serialize_item({{:token, "a"}, [{"x", 1}, {"y", true}]})
      {:ok, "a;x=1;y"}

      iex> X402.HTTPSignature.StructuredField.serialize_item({"caf\\u00e9", []})
      {:error, :invalid_structured_field}
  """
  @spec serialize_item(item()) :: {:ok, binary()} | {:error, error()}
  def serialize_item({bare, params}) when is_list(params) do
    with {:ok, bare} <- serialize_bare(bare),
         {:ok, params} <- serialize_params(params) do
      {:ok, bare <> params}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Serializes a bare item (RFC 8941 §4.1.3.1).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.serialize_bare("say \\"hi\\" \\\\")
      {:ok, "\\"say \\\\\\"hi\\\\\\" \\\\\\\\\\""}

      iex> X402.HTTPSignature.StructuredField.serialize_bare(-42)
      {:ok, "-42"}

      iex> X402.HTTPSignature.StructuredField.serialize_bare(1.5)
      {:ok, "1.5"}

      iex> X402.HTTPSignature.StructuredField.serialize_bare(false)
      {:ok, "?0"}

      iex> X402.HTTPSignature.StructuredField.serialize_bare({:bytes, <<1, 2, 3>>})
      {:ok, ":AQID:"}

      iex> X402.HTTPSignature.StructuredField.serialize_bare(1_000_000_000_000_000)
      {:error, :invalid_structured_field}
  """
  @spec serialize_bare(bare()) :: {:ok, binary()} | {:error, error()}
  def serialize_bare(value) when is_binary(value) do
    case printable_ascii?(value) do
      true -> {:ok, "\"" <> escape_string(value) <> "\""}
      false -> {:error, :invalid_structured_field}
    end
  end

  def serialize_bare(value) when is_integer(value) and abs(value) <= @max_integer,
    do: {:ok, Integer.to_string(value)}

  def serialize_bare(value) when is_float(value), do: serialize_decimal(value)
  def serialize_bare(true), do: {:ok, "?1"}
  def serialize_bare(false), do: {:ok, "?0"}

  def serialize_bare({:token, token}) when is_binary(token) do
    case Regex.match?(~r/\A[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:\/]*\z/, token) do
      true -> {:ok, token}
      false -> {:error, :invalid_structured_field}
    end
  end

  def serialize_bare({:bytes, bytes}) when is_binary(bytes),
    do: {:ok, ":" <> Base.encode64(bytes) <> ":"}

  def serialize_bare(_value), do: {:error, :invalid_structured_field}

  @spec serialize_decimal(float()) :: {:ok, binary()} | {:error, error()}
  defp serialize_decimal(value) do
    rounded = Float.round(value, 3)

    case abs(trunc(rounded)) <= 999_999_999_999 do
      true ->
        [integer_digits, fraction] =
          rounded |> :erlang.float_to_binary(decimals: 3) |> String.split(".")

        fraction =
          case String.trim_trailing(fraction, "0") do
            "" -> "0"
            digits -> digits
          end

        {:ok, integer_digits <> "." <> fraction}

      false ->
        {:error, :invalid_structured_field}
    end
  end

  @spec serialize_params(params()) :: {:ok, binary()} | {:error, error()}
  defp serialize_params(params) do
    with {:ok, parts} <- map_all(params, &serialize_param/1) do
      {:ok, Enum.join(parts)}
    end
  end

  @spec serialize_param({binary(), bare()}) :: {:ok, binary()} | {:error, error()}
  defp serialize_param({key, true}) do
    with {:ok, key} <- serialize_key(key), do: {:ok, ";" <> key}
  end

  defp serialize_param({key, value}) do
    with {:ok, key} <- serialize_key(key),
         {:ok, value} <- serialize_bare(value) do
      {:ok, ";" <> key <> "=" <> value}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Serializes a dictionary or parameter key (RFC 8941 §4.1.1.3).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.serialize_key("sig-b26")
      {:ok, "sig-b26"}

      iex> X402.HTTPSignature.StructuredField.serialize_key("Sig1")
      {:error, :invalid_structured_field}
  """
  @spec serialize_key(binary()) :: {:ok, binary()} | {:error, error()}
  def serialize_key(key) when is_binary(key) do
    case Regex.match?(~r/\A[a-z*][a-z0-9_\-.*]*\z/, key) do
      true -> {:ok, key}
      false -> {:error, :invalid_structured_field}
    end
  end

  def serialize_key(_key), do: {:error, :invalid_structured_field}

  @spec escape_string(binary()) :: binary()
  defp escape_string(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  @spec printable_ascii?(binary()) :: boolean()
  defp printable_ascii?(value), do: Regex.match?(~r/\A[\x20-\x7E]*\z/, value)

  # -- Parsing ----------------------------------------------------------------

  @doc since: "0.9.0"
  @doc """
  Parses a dictionary (RFC 8941 §4.2.2).

  ## Examples

      iex> X402.HTTPSignature.StructuredField.parse_dictionary(
      ...>   ~S|sig1=("@method" "@path";req);created=1618884473;keyid="k", sig2=:AQID:|
      ...> )
      {:ok, [
        {"sig1", {:inner_list, [{"@method", []}, {"@path", [{"req", true}]}], [{"created", 1618884473}, {"keyid", "k"}]}},
        {"sig2", {{:bytes, <<1, 2, 3>>}, []}}
      ]}

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("a, b;x=?0")
      {:ok, [{"a", {true, []}}, {"b", {true, [{"x", false}]}}]}

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("sig1=(")
      {:error, :invalid_structured_field}

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("a=1,")
      {:error, :invalid_structured_field}

  A repeated key (in the dictionary or in any parameter list) overwrites
  the earlier value as RFC 8941 §4.2.2 prescribes; pass
  `duplicate_keys: :error` to reject the field instead, which is what a
  signature verifier wants:

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("a=1, a=2")
      {:ok, [{"a", {2, []}}]}

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("a=1, a=2", duplicate_keys: :error)
      {:error, :duplicate_key}

      iex> X402.HTTPSignature.StructuredField.parse_dictionary("a=1;x=1;x=2", duplicate_keys: :error)
      {:error, :duplicate_key}
  """
  @spec parse_dictionary(binary(), [{:duplicate_keys, :overwrite | :error}]) ::
          {:ok, dictionary()} | {:error, error()}
  def parse_dictionary(input, opts \\ [])

  def parse_dictionary(input, opts) when is_binary(input) and is_list(opts) do
    strict? = Keyword.get(opts, :duplicate_keys, :overwrite) == :error

    case parse_dictionary_members(String.trim_leading(input, " "), [], strict?) do
      {:ok, members} -> {:ok, members}
      :duplicate -> {:error, :duplicate_key}
      :error -> {:error, :invalid_structured_field}
    end
  end

  def parse_dictionary(_input, _opts), do: {:error, :invalid_structured_field}

  @spec parse_dictionary_members(binary(), [{binary(), member()}], boolean()) ::
          {:ok, dictionary()} | :duplicate | :error
  defp parse_dictionary_members("", acc, _strict?), do: {:ok, acc}

  defp parse_dictionary_members(input, acc, strict?) do
    with {:ok, key, rest} <- parse_key(input),
         {:ok, value, rest} <- parse_member_value(rest, strict?),
         {:ok, acc} <- store(acc, key, value, strict?) do
      case discard_ows(rest) do
        "" -> {:ok, acc}
        "," <> rest -> parse_next_member(discard_ows(rest), acc, strict?)
        _other -> :error
      end
    end
  end

  # RFC 8941 §4.2.2: a repeated key overwrites the earlier member in place.
  @spec store([{binary(), term()}], binary(), term(), boolean()) ::
          {:ok, [{binary(), term()}]} | :duplicate
  defp store(acc, key, value, strict?) do
    case {List.keymember?(acc, key, 0), strict?} do
      {true, true} -> :duplicate
      _other -> {:ok, List.keystore(acc, key, 0, {key, value})}
    end
  end

  @spec discard_ows(binary()) :: binary()
  defp discard_ows(input), do: String.replace(input, ~r/\A[ \t]+/, "")

  @spec parse_next_member(binary(), [{binary(), member()}], boolean()) ::
          {:ok, dictionary()} | :duplicate | :error
  defp parse_next_member("", _acc, _strict?), do: :error
  defp parse_next_member(rest, acc, strict?), do: parse_dictionary_members(rest, acc, strict?)

  @spec parse_member_value(binary(), boolean()) :: {:ok, member(), binary()} | :duplicate | :error
  defp parse_member_value("=" <> rest, strict?), do: parse_item_or_inner_list(rest, strict?)

  defp parse_member_value(rest, strict?) do
    with {:ok, params, rest} <- parse_params(rest, [], strict?), do: {:ok, {true, params}, rest}
  end

  @spec parse_item_or_inner_list(binary(), boolean()) ::
          {:ok, member(), binary()} | :duplicate | :error
  defp parse_item_or_inner_list("(" <> rest, strict?),
    do: parse_inner_list_items(rest, [], strict?)

  defp parse_item_or_inner_list(rest, strict?), do: parse_item(rest, strict?)

  @spec parse_inner_list_items(binary(), [item()], boolean()) ::
          {:ok, inner_list(), binary()} | :duplicate | :error
  defp parse_inner_list_items(input, acc, strict?) do
    case String.trim_leading(input, " ") do
      ")" <> rest ->
        with {:ok, params, rest} <- parse_params(rest, [], strict?) do
          {:ok, {:inner_list, Enum.reverse(acc), params}, rest}
        end

      "" ->
        :error

      rest ->
        with {:ok, item, rest} <- parse_item(rest, strict?),
             true <- inner_list_boundary?(rest) do
          parse_inner_list_items(rest, [item | acc], strict?)
        else
          :duplicate -> :duplicate
          _error -> :error
        end
    end
  end

  @spec inner_list_boundary?(binary()) :: boolean()
  defp inner_list_boundary?(" " <> _rest), do: true
  defp inner_list_boundary?(")" <> _rest), do: true
  defp inner_list_boundary?(_rest), do: false

  @doc since: "0.9.0"
  @doc """
  Parses an item with parameters (RFC 8941 §4.2.3), returning the rest of
  the input.

  ## Examples

      iex> X402.HTTPSignature.StructuredField.parse_item(~S|"@authority";req rest|)
      {:ok, {"@authority", [{"req", true}]}, " rest"}

      iex> X402.HTTPSignature.StructuredField.parse_item("token;n=1.25;b=?1")
      {:ok, {{:token, "token"}, [{"n", 1.25}, {"b", true}]}, ""}

      iex> X402.HTTPSignature.StructuredField.parse_item(~S|"unterminated|)
      :error
  """
  @spec parse_item(binary()) :: {:ok, item(), binary()} | :error
  def parse_item(input) when is_binary(input), do: parse_item(input, false)

  @spec parse_item(binary(), boolean()) :: {:ok, item(), binary()} | :duplicate | :error
  defp parse_item(input, strict?) do
    with {:ok, bare, rest} <- parse_bare(input),
         {:ok, params, rest} <- parse_params(rest, [], strict?) do
      {:ok, {bare, params}, rest}
    end
  end

  @spec parse_params(binary(), params(), boolean()) ::
          {:ok, params(), binary()} | :duplicate | :error
  defp parse_params(";" <> rest, acc, strict?) do
    with {:ok, key, rest} <- parse_key(String.trim_leading(rest, " ")),
         {:ok, value, rest} <- parse_param_value(rest),
         {:ok, acc} <- store(acc, key, value, strict?) do
      parse_params(rest, acc, strict?)
    end
  end

  defp parse_params(rest, acc, _strict?), do: {:ok, acc, rest}

  @spec parse_param_value(binary()) :: {:ok, bare(), binary()} | :error
  defp parse_param_value("=" <> rest), do: parse_bare(rest)
  defp parse_param_value(rest), do: {:ok, true, rest}

  @spec parse_key(binary()) :: {:ok, binary(), binary()} | :error
  defp parse_key(input) do
    case Regex.run(~r/\A[a-z*][a-z0-9_\-.*]*/, input) do
      [key] -> {:ok, key, binary_part(input, byte_size(key), byte_size(input) - byte_size(key))}
      nil -> :error
    end
  end

  @spec parse_bare(binary()) :: {:ok, bare(), binary()} | :error
  defp parse_bare("\"" <> rest), do: parse_string(rest, [])
  defp parse_bare(":" <> rest), do: parse_bytes(rest)
  defp parse_bare("?1" <> rest), do: {:ok, true, rest}
  defp parse_bare("?0" <> rest), do: {:ok, false, rest}

  defp parse_bare(<<char, _::binary>> = input) when char in ?0..?9 or char == ?-,
    do: parse_number(input)

  defp parse_bare(<<char, _::binary>> = input)
       when char in ?A..?Z or char in ?a..?z or char == ?* do
    [token] = Regex.run(~r/\A[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:\/]*/, input)

    {:ok, {:token, token},
     binary_part(input, byte_size(token), byte_size(input) - byte_size(token))}
  end

  defp parse_bare(_input), do: :error

  @spec parse_string(binary(), [binary()]) :: {:ok, binary(), binary()} | :error
  defp parse_string("\"" <> rest, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp parse_string("\\\"" <> rest, acc), do: parse_string(rest, ["\"" | acc])
  defp parse_string("\\\\" <> rest, acc), do: parse_string(rest, ["\\" | acc])
  defp parse_string("\\" <> _rest, _acc), do: :error

  defp parse_string(<<char, rest::binary>>, acc) when char in 0x20..0x7E,
    do: parse_string(rest, [<<char>> | acc])

  defp parse_string(_input, _acc), do: :error

  @spec parse_bytes(binary()) :: {:ok, {:bytes, binary()}, binary()} | :error
  defp parse_bytes(input) do
    case Regex.run(~r/\A([A-Za-z0-9+\/=]*):/, input) do
      [match, encoded] ->
        with {:ok, bytes} <- decode_base64(encoded) do
          {:ok, {:bytes, bytes},
           binary_part(input, byte_size(match), byte_size(input) - byte_size(match))}
        end

      nil ->
        :error
    end
  end

  @spec decode_base64(binary()) :: {:ok, binary()} | :error
  defp decode_base64(encoded) do
    case Base.decode64(encoded) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> Base.decode64(encoded, padding: false)
    end
  end

  @spec parse_number(binary()) :: {:ok, integer() | float(), binary()} | :error
  defp parse_number(input) do
    case Regex.run(~r/\A(-?)(\d{1,15})(?:\.(\d{1,3}))?/, input) do
      [match, sign, integer_digits, fraction] when byte_size(integer_digits) <= 12 ->
        rest = binary_part(input, byte_size(match), byte_size(input) - byte_size(match))
        {:ok, String.to_float(sign <> integer_digits <> "." <> fraction), rest}

      [match, sign, integer_digits] ->
        rest = binary_part(input, byte_size(match), byte_size(input) - byte_size(match))
        {:ok, String.to_integer(sign <> integer_digits), rest}

      _other ->
        :error
    end
  end

  @spec map_all([term()], (term() -> {:ok, binary()} | {:error, error()})) ::
          {:ok, [binary()]} | {:error, error()}
  defp map_all(values, fun) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case fun.(value) do
        {:ok, serialized} -> {:cont, {:ok, [serialized | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end
end
