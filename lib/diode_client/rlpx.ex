defmodule DiodeClient.Rlpx do
  alias DiodeClient.Base16

  @moduledoc """
  Rlpx defines helepr method for converting RLP encoded values back and forth.
  """
  @type rlp() :: binary() | [rlp()]

  @spec hex2uint(binary()) :: non_neg_integer()
  def hex2uint("") do
    0
  end

  def hex2uint(bin) when is_binary(bin) do
    bin2uint(Base16.decode(bin))
  end

  @spec uint2bin(non_neg_integer) :: binary
  def uint2bin(0) do
    ""
  end

  def uint2bin(num) when is_integer(num) do
    :binary.encode_unsigned(num)
  end

  @spec bin2uint(binary()) :: non_neg_integer()
  def bin2uint("") do
    0
  end

  def bin2uint(bin) when is_binary(bin) do
    :binary.decode_unsigned(bin)
  end

  @spec bin2int(binary) :: integer
  def bin2int(bin) when is_binary(bin) do
    num = bin2uint(bin)

    case rem(num, 2) do
      0 -> div(num, 2)
      1 -> -div(num - 1, 2)
    end
  end

  def int2bin(int) when is_integer(int) do
    if int < 0 do
      -(int * 2) + 1
    else
      int * 2
    end
    |> :binary.encode_unsigned()
  end

  @spec hex2addr(binary()) :: nil | binary()
  def hex2addr("") do
    nil
  end

  def hex2addr(bin) when is_binary(bin) do
    bin2addr(Base16.decode(bin))
  end

  @spec bin2addr(binary()) :: nil | binary()
  def bin2addr("") do
    nil
  end

  def bin2addr(bin) when is_binary(bin) do
    bin
  end

  def list2map(list) do
    Enum.map(list, fn [key, value] -> {key, value} end)
    |> Map.new()
  end
end
