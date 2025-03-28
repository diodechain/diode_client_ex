defmodule DiodeClient.Base16 do
  @moduledoc false
  @spec encode(binary() | non_neg_integer(), any()) :: <<_::16, _::_*8>>
  def encode(int, bigX \\ true)

  def encode(nil, _bigX) do
    "nil"
  end

  def encode(int, true) when is_integer(int) do
    "0X#{Base.encode16(:binary.encode_unsigned(int), case: :lower)}"
  end

  def encode(int, false) when is_integer(int) do
    "0x#{Base.encode16(:binary.encode_unsigned(int), case: :lower)}"
  end

  def encode(hex, _bigX) do
    "0x#{Base.encode16(hex, case: :lower)}"
  end

  def prefix(some, length) do
    case encode(some, false) do
      <<"0x", head::binary-size(length), _::binary>> ->
        head

      <<"0x", rest::binary>> ->
        rest
    end
  end

  @spec decode(<<_::16, _::_*8>>) :: binary() | non_neg_integer()
  def decode("nil") do
    nil
  end

  def decode(<<"0x", hex::binary>>) do
    do_decode(hex)
  end

  def decode(<<"0X", hex::binary>>) do
    :binary.decode_unsigned(do_decode(hex))
  end

  def decode_int(int) when is_integer(int) do
    int
  end

  def decode_int(<<"0x", hex::binary>>) do
    :binary.decode_unsigned(do_decode(hex))
  end

  defp do_decode("0") do
    "\0"
  end

  defp do_decode(bin) do
    case rem(String.length(bin), 2) do
      0 ->
        Base.decode16!(bin, case: :mixed)

      1 ->
        Base.decode16!("0" <> bin, case: :mixed)
    end
  end
end
