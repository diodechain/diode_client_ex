defmodule DiodeClient.Oasis.OrderedMap do
  @moduledoc """
  Helper module for Saphhire CBOR encoding to enforce canonical order of elements
  when CBOR encoding maps.
  """
  defstruct [:elements, :size]

  def new(list_of_tuples) when is_list(list_of_tuples) do
    %__MODULE__{elements: list_of_tuples, size: length(list_of_tuples)}
  end
end

defimpl CBOR.Encoder, for: DiodeClient.Oasis.OrderedMap do
  def encode_into(map, acc) when map.size == 0, do: <<acc::binary, 0xA0>>

  def encode_into(map, acc) when map.size < 0x10000000000000000 do
    Enum.reduce(map.elements, CBOR.Utils.encode_head(5, map.size, acc), fn {k, v}, subacc ->
      CBOR.Encoder.encode_into(v, CBOR.Encoder.encode_into(k, subacc))
    end)
  end

  def encode_into(map, acc) do
    Enum.reduce(map.elements, <<acc::binary, 0xBF>>, fn {k, v}, subacc ->
      CBOR.Encoder.encode_into(v, CBOR.Encoder.encode_into(k, subacc))
    end) <> <<0xFF>>
  end
end
