defmodule DiodeClient.ABI do
  @moduledoc false
  alias DiodeClient.{Hash, Wallet, Base16}
  require Logger
  import Wallet

  def encode_args(types, values) when is_list(types) and is_list(values) do
    encode_data(types, values)
    |> :erlang.iolist_to_binary()
  end

  def decode_call(name, types, encoded_call) do
    types = Enum.map(types, &encode_sub_spec/1)
    signature = encode_spec(name, types)

    case encoded_call do
      <<^signature::binary-size(4), rest::binary>> ->
        {:ok, decode_args(types, rest)}

      _ ->
        {:error, "Invalid signature"}
    end
  end

  @deprecated "Use decode_args/2 instead"
  def decode_types(types, encoded_args) do
    decode_args(types, encoded_args)
  end

  def decode_args(types, data) do
    {ret, _rest} =
      Enum.reduce(types, {[], data}, fn type, {ret, rest} ->
        {value, rest} =
          if is_dynamic(type) do
            decode_value("uint256", rest)
          else
            decode_value(type, rest)
          end

        {ret ++ [value], rest}
      end)

    Enum.zip(types, ret)
    |> Enum.map(fn {type, value} ->
      if is_dynamic(type) do
        decode_dynamic_type(type, data, value)
      else
        value
      end
    end)
  end

  defp decode_dynamic_type(type, data, value) do
    # for dynamic types the decoded value in the header is the offset of the data
    base = binary_part(data, value, byte_size(data) - value)

    cond do
      type in ["string", "bytes"] ->
        {len, rest} = decode("uint256", base)
        binary_part(rest, 0, len)

      String.ends_with?(type, "[]") ->
        {slots, rest} = decode_value("uint256", base)
        element_type = String.replace_trailing(type, "[]", "")

        {acc, _rest} =
          List.duplicate(element_type, slots)
          |> Enum.reduce({[], rest}, fn element_type, {acc, rest} ->
            {value, rest} =
              if String.starts_with?(element_type, "(") do
                # For tuple types, we need to decode using the tuple logic
                "(" <> tuple_def = element_type
                types = tuple_types(tuple_def)
                decoded_tuple = decode_args(types, rest)
                # Calculate how many bytes were consumed
                consumed_bytes = length(types) * 32

                remaining_rest =
                  binary_part(rest, consumed_bytes, byte_size(rest) - consumed_bytes)

                {decoded_tuple, remaining_rest}
              else
                decode_value(element_type, rest)
              end

            {acc ++ [value], rest}
          end)

        acc

      String.starts_with?(type, "(") ->
        "(" <> tuple_def = type
        decode_types(tuple_types(tuple_def), base)
    end
  end

  defp is_dynamic("string"), do: true
  defp is_dynamic("bytes"), do: true

  defp is_dynamic(other) do
    cond do
      String.ends_with?(other, "[]") ->
        true

      String.starts_with?(other, "(") ->
        "(" <> tuple_def = other
        Enum.any?(tuple_types(tuple_def), &is_dynamic/1)

      true ->
        false
    end
  end

  def decode_revert(<<"">>) do
    {:evmc_revert, ""}
  end

  # Decoding "Error(string)" type revert messages
  # <<8, 195, 121, 160>> = ABI.encode_spec("Error", ["string"])
  def decode_revert(
        <<8, 195, 121, 160, 32::unsigned-size(256), length::unsigned-size(256), rest::binary>>
      ) do
    {:evmc_revert, binary_part(rest, 0, length)}
  end

  def decode_revert(other) do
    Logger.debug("decode_revert(#{inspect(other)})")
    {:evmc_revert, "blubb"}
  end

  def encode_spec(name, types \\ []) do
    signature =
      "#{name}#{encode_sub_spec(types)}"
      |> String.replace(" ", "")

    binary_part(Hash.keccak_256(signature), 0, 4)
  end

  defp encode_sub_spec(type) do
    case type do
      name when is_binary(name) -> name
      list when is_list(list) -> "(" <> Enum.map_join(list, ",", &encode_sub_spec/1) <> ")"
    end
  end

  def encode_call(name, types \\ [], values \\ []) do
    fun = encode_spec(name, types)
    args = encode_args(types, values)
    fun <> args
  end

  def do_encode_data(type, value) do
    if is_dynamic(type) do
      {types, values, len} = dynamic(type, value)
      ret = encode_data(types, values)
      {"", [len, ret]}
    else
      {encode(type, value), ""}
    end
  end

  defp encode_data(subtypes, values) do
    values =
      Enum.zip([subtypes, values])
      |> Enum.map(fn {type, entry} ->
        do_encode_data(type, entry)
      end)

    {head, body, _} =
      Enum.reduce(values, {[], [], 32 * length(subtypes)}, fn
        {"", body}, {h, b, o} ->
          {h ++ [encode("uint", o)], b ++ [body], o + :erlang.iolist_size(body)}

        {head, _}, {h, b, o} ->
          {h ++ [head], b, o}
      end)

    [head, body]
  end

  defp dynamic(type, {:call, name, types, args}) do
    dynamic(type, encode_call(name, types, args))
  end

  defp dynamic(type, values) when is_list(values) do
    cond do
      String.ends_with?(type, "[]") ->
        n = length(values)
        {List.duplicate(String.replace_trailing(type, "[]", ""), n), values, encode("uint", n)}

      String.starts_with?(type, "(") ->
        {tuple_types(String.trim_leading(type, "(")), values, ""}
    end
  end

  defp dynamic(type, value) when is_binary(value) and type in ["string", "bytes"] do
    values = value <> <<0::unsigned-size(248)>>

    values =
      binary_part(values, 0, div(byte_size(values), 32) * 32)
      |> :erlang.binary_to_list()
      |> Enum.chunk_every(32)
      |> Enum.map(&:erlang.iolist_to_binary/1)

    {List.duplicate("bytes32", length(values)), values, encode("uint", byte_size(value))}
  end

  def optimal_type_size(type) do
    case type do
      "bytes" -> nil
      "bytes" <> size -> String.to_integer(size)
      "address" -> 20
      _ -> nil
    end
  end

  def encode(format, value) when is_binary(format) do
    if is_dynamic(format) do
      encode_args([format], [value])
    else
      encode_value(format, value)
    end
  end

  def encode_value(format, nil), do: encode(format, 0)

  # uint<M>: unsigned integer type of M bits, 0 < M <= 256, M % 8 == 0. e.g. uint32, uint8, uint256.
  # int<M>: two's complement signed integer type of M bits, 0 < M <= 256, M % 8 == 0.
  # address: equivalent to uint160, except for the assumed interpretation and language typing. For computing the function selector, address is used.
  # uint, int: synonyms for uint256, int256 respectively. For computing the function selector, uint256 and int256 have to be used.
  # bool: equivalent to uint8 restricted to the values 0 and 1. For computing the function selector, bool is used.
  # fixed<M>x<N>: signed fixed-point decimal number of M bits, 8 <= M <= 256, M % 8 ==0, and 0 < N <= 80, which denotes the value v as v / (10 ** N).
  # ufixed<M>x<N>: unsigned variant of fixed<M>x<N>.
  # fixed, ufixed: synonyms for fixed128x18, ufixed128x18 respectively. For computing the function selector, fixed128x18 and ufixed128x18 have to be used.
  # bytes<M>: binary type of M bytes, 0 < M <= 32.
  # function: an address (20 bytes) followed by a function selector (4 bytes). Encoded identical to bytes24.
  for bit <- 1..32 do
    Module.eval_quoted(
      __MODULE__,
      Code.string_to_quoted("""
        def encode_value("uint#{bit * 8}", value), do: <<value :: unsigned-size(256)>>
        def encode_value("int#{bit * 8}", value), do: <<value :: signed-size(256)>>
        def encode_value("bytes#{bit}", <<value :: binary>>) when byte_size(value) <= #{bit}, do: <<:binary.decode_unsigned(value) :: unsigned-size(256)>>
        def encode_value("bytes#{bit}", value) when is_integer(value), do: <<value :: unsigned-size(256)>>
      """)
    )
  end

  def encode_value("uint", value), do: encode_value("uint256", value)
  def encode_value("int", value), do: encode_value("int256", value)
  def encode_value("address", value) when is_integer(value), do: encode_value("uint160", value)

  def encode_value("address", value) when is_binary(value) and byte_size(value) <= 20,
    do: encode_value("bytes20", value)

  def encode_value("address", value = wallet()),
    do: encode_value("bytes20", Wallet.address!(value))

  def encode_value("bool", true), do: encode_value("uint8", 1)
  def encode_value("bool", false), do: encode_value("uint8", 0)
  def encode_value("bool", value), do: encode_value("uint8", value)

  def encode_value("function", {address, name}),
    do: encode_value("bytes24", encode_value("address", address) <> encode_spec(name))

  def encode_value("function", {address, name, types}),
    do: encode_value("bytes24", encode_value("address", address) <> encode_spec(name, types))

  def encode_value("function", value), do: encode_value("bytes24", value)

  def encode_value("(" <> tuple_def, values) do
    types = tuple_types(tuple_def)
    encode_args(types, values)
  end

  def encode_value(type, value) do
    raise "Invalid type #{type}: #{inspect(value)}"
  end

  defp tuple_types(tuple_def) do
    len = byte_size(tuple_def) - 1

    case tuple_def do
      <<tuple_def::binary-size(len), ")">> ->
        String.split(tuple_def, ",")
        |> Enum.map(&String.trim/1)

      _ ->
        raise "Invalid tuple definition (#{tuple_def}"
    end
  end

  @doc """
  Decode a value from a binary. Returns a tuple with the decoded value and the rest of the binary.

  ## Examples

  iex> DiodeClient.ABI.decode("uint256", DiodeClient.Base16.decode("0x0000000000000000000000000000000000000000000000000000000000000001"))
  {1, ""}

  """
  def decode(format, value) when is_binary(format) do
    if is_dynamic(format) do
      [result] = decode_args([format], value)
      {result, ""}
    else
      decode_value(format, value)
    end
  end

  for bit <- 1..32 do
    Module.eval_quoted(
      __MODULE__,
      Code.string_to_quoted("""
        def decode_value("uint#{bit * 8}", <<value :: unsigned-size(256), rest :: binary>>), do: {value, rest}
        def decode_value("int#{bit * 8}", <<value :: signed-size(256), rest :: binary>>), do: {value, rest}
        def decode_value("bytes#{bit}", <<value :: binary-size(#{bit}), _ :: binary-size(#{32 - bit}), rest :: binary>>), do: {value, rest}
      """)
    )
  end

  def decode_value("uint", value), do: decode_value("uint256", value)
  def decode_value("int", value), do: decode_value("int256", value)
  def decode_value("bool", value), do: decode_value("uint8", value)

  def decode_value("address", <<_::binary-size(12), address::binary-size(20), rest::binary>>),
    do: {address, rest}

  def decode_value("address[]", value), do: decode_value("uint256", value)
  def decode_value("string", value), do: decode_value("uint256", value)
  def decode_value("bytes", value), do: decode_value("uint256", value)

  def decode_value("(" <> tuple_def, value) do
    types = tuple_types(tuple_def)
    {decode_args(types, value), ""}
  end

  def decode_value(other, value) do
    raise "Invalid value for type #{other}: #{inspect(Base16.encode(value))}"
  end
end
