defmodule DiodeClient.Hash do
  @moduledoc false
  alias DiodeClient.{Base16, Rlp}
  @spec integer(binary()) :: non_neg_integer()
  def integer(hash) do
    :binary.decode_unsigned(hash)
  end

  def to_bytes32(hash = <<_::256>>) do
    hash
  end

  def to_bytes32(hash = <<_::160>>) do
    <<0::96, hash::binary-size(20)>>
  end

  def to_bytes32(hash) when is_integer(hash) do
    <<hash::unsigned-big-size(256)>>
  end

  def printable(nil) do
    "nil"
  end

  def printable(binary) do
    Base16.encode(binary)
  end

  def to_address(hash) when is_integer(hash) do
    <<hash::unsigned-big-size(160)>>
  end

  def to_address(hash = <<_::160>>) do
    hash
  end

  def to_address(hash = <<"0x", _::320>>) do
    Base16.decode(hash)
  end

  def to_address(hash = <<_::256>>) do
    binary_part(hash, 12, 20)
  end

  def keccak_256(string) do
    DiodeClient.ETSLru.fetch(DiodeClient.HashCache, string, fn ->
      ExSha3.keccak_256(string)
    end)
  end

  def sha3_256(string) do
    :crypto.hash(:sha256, string)
  end

  def ripemd160(string) do
    :crypto.hash(:ripemd160, string)
  end

  def create(address = <<_::160>>, nonce) when is_integer(nonce) do
    Rlp.encode!([address, nonce])
    |> keccak_256()
    |> to_address()
  end

  def create2(address = <<_::160>>, code_hash = <<_::256>>, salt = <<_::256>>) do
    <<0xFF, address::binary-size(20), salt::binary-size(32), code_hash::binary>>
    |> keccak_256()
    |> to_address()
  end
end
