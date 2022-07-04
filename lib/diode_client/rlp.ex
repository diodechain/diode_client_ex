defmodule DiodeClient.Rlp do
  alias DiodeClient.Rlpx
  @compile :inline_list_funcs
  @type rlp() :: binary() | [rlp()]
  @moduledoc """
    Encoding and Decoding of Recursive Length Prefix (RLP) https://eth.wiki/fundamentals/rlp

    RLP is easy to decode and encode and has only two types of data:
    list() and binaries() for small binaries and lists there is
    very space efficient encoding. But primarily it allows native
    storing of binary data which is the main reason it's used within the
    Diode Network.

    By convention maps are stored like keyword lists in Erlang as a list of
    key, value pairs such as:
    `[[key1, value1], [key2, value2]]`

    To ease working with maps they are automatically encoded to a keyword list
    and there is the `Rlpx.list2map` to convert them back:

    ```
      iex> alias DiodeClient.{Rlp, Rlpx}
      iex> Rlp.encode!(%{key: "value"})
      <<203, 202, 131, 107, 101, 121, 133, 118, 97, 108, 117, 101>>
      iex> Rlp.encode!(%{key: "value"}) |> Rlp.decode!()
      [["key", "value"]]
      iex> Rlp.encode!(%{key: "value"}) |> Rlp.decode!()
      [["key", "value"]]
      iex> Rlp.encode!(%{key: "value"}) |> Rlp.decode! |> Rlpx.list2map
      %{"key" => "value"}
    ```


  """

  @doc """
    Encode an Elixir term to RLP. Integers are converted
    to binaries using `:binary.encode_unsigned/1`

    If you want to encode integers as signed values pass
    `encode!(term, unsigned: false)`
  """
  def encode!(term, opts \\ []) do
    do_encode!(term, opts)
    |> :erlang.iolist_to_binary()
  end

  def encode_to_iolist!(term, opts \\ []) do
    do_encode!(term, opts)
  end

  def do_encode!(<<x>>, _opts) when x < 0x80, do: <<x>>

  def do_encode!(x, _opts) when is_binary(x) do
    with_length!(0x80, x)
  end

  def do_encode!(list, opts) when is_list(list) do
    with_length!(0xC0, :lists.map(&do_encode!(&1, opts), list))
  end

  def do_encode!(other, opts) do
    encode_other!(other, opts)
    |> do_encode!(opts)
  end

  defp with_length!(offset, data) do
    size = :erlang.iolist_size(data)

    if size <= 55 do
      [offset + size, data]
    else
      bin = :binary.encode_unsigned(size)
      [byte_size(bin) + offset + 55, bin, data]
    end
  end

  @spec decode!(binary()) :: rlp()
  def decode!(bin) do
    {term, ""} = do_decode!(bin)
    term
  end

  @spec decode(binary()) :: {rlp(), binary()}
  def decode(bin) do
    do_decode!(bin)
  end

  defp encode_other!(nil, _opts) do
    ""
  end

  defp encode_other!(struct, _opts) when is_struct(struct) do
    Map.from_struct(struct)
    |> Enum.map(fn {key, value} -> [Atom.to_string(key), value] end)
  end

  defp encode_other!(map, _opts) when is_map(map) do
    Map.to_list(map)
    |> Enum.map(fn {key, value} ->
      [if(is_atom(key), do: Atom.to_string(key), else: key), value]
    end)
  end

  defp encode_other!(tuple, _opts) when is_tuple(tuple) do
    :erlang.tuple_to_list(tuple)
  end

  defp encode_other!(bits, _opts) when is_bitstring(bits) do
    for <<x::size(1) <- bits>>, do: if(x == 1, do: "1", else: "0"), into: ""
  end

  defp encode_other!(0, _opts) do
    # Sucks but this is the quasi standard by Go and Node.js
    # This is why we have bin2uint
    ""
  end

  defp encode_other!(num, %{unsigned: false}) when is_integer(num) do
    Rlpx.int2bin(num)
  end

  defp encode_other!(num, _opts) when is_integer(num) do
    Rlpx.uint2bin(num)
  end

  defp do_decode!(<<x::unsigned-size(8), rest::binary>>) when x <= 0x7F do
    {<<x::unsigned>>, rest}
  end

  defp do_decode!(<<head::unsigned-size(8), rest::binary>>) when head <= 0xB7 do
    size = head - 0x80
    <<item::binary-size(size), rest::binary>> = rest
    {item, rest}
  end

  defp do_decode!(<<head::unsigned-size(8), rest::binary>>) when head <= 0xBF do
    length_size = (head - 0xB7) * 8
    <<size::unsigned-size(length_size), item::binary-size(size), rest::binary>> = rest
    {item, rest}
  end

  defp do_decode!(<<head::unsigned-size(8), rest::binary>>) when head <= 0xF7 do
    size = head - 0xC0
    <<list::binary-size(size), rest::binary>> = rest
    {do_decode_list!([], list), rest}
  end

  defp do_decode!(<<head::unsigned-size(8), rest::binary>>) when head <= 0xFF do
    length_size = (head - 0xF7) * 8
    <<size::unsigned-size(length_size), list::binary-size(size), rest::binary>> = rest
    {do_decode_list!([], list), rest}
  end

  defp do_decode_list!(list, "") do
    Enum.reverse(list)
  end

  defp do_decode_list!(list, rest) do
    {item, rest} = do_decode!(rest)
    do_decode_list!([item | list], rest)
  end

  def test_perf() do
    # req_id = 1
    size = 1
    index = 0
    frag = :rand.bytes(8000)
    # data = [[<<>>, req_id], size, index, frag]

    :timer.tc(fn ->
      for req_id <- 1..1_000_000 do
        encode_to_iolist!([[<<>>, req_id], size, index, frag])
      end

      nil
    end)
  end
end
