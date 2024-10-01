defmodule DiodeClient.Contracts.Utils do
  @moduledoc false
  alias DiodeClient.Hash

  defmacro __using__({address, shell}) do
    quote do
      import DiodeClient.Contracts.Utils
      @address unquote(address)
      @shell unquote(shell)
      def shell(), do: @shell
      def storage_root(), do: @shell.get_account_root(@address)
      def address(slot, block), do: address(@shell, @address, slot, block)
      def number(slot, block), do: number(@shell, @address, slot, block)
      def string(slot, block), do: string(@shell, @address, slot, block)

      def value(slot, block, default, filter),
        do: value(@shell, @address, slot, block, default, filter)
    end
  end

  def add(bin, delta) when is_binary(bin) and is_integer(delta) do
    num = :binary.decode_unsigned(bin) + delta
    <<num::unsigned-big-size(256)>>
  end

  def value(shell, address, slot, block, default, filter) do
    block = block || shell.peak()

    shell.get_account_value(Hash.to_address(address), Hash.to_bytes32(slot), block)
    |> case do
      :undefined -> default
      other when is_nil(filter) -> other
      other -> filter.(other)
    end
  end

  def values(shell, address, slots, block) do
    shell.get_account_values(address, Enum.map(slots, &Hash.to_bytes32/1), block || shell.peak())
  end

  def number(shell, address, slot, block) do
    value(shell, address, slot, block, 0, &:binary.decode_unsigned/1)
  end

  def address(shell, address, slot, block) do
    value(shell, address, slot, block, nil, &Hash.to_address/1)
  end

  def string(shell, address, slot, block) do
    block = block || shell.peak()

    with str = <<prefix::binary-size(30), len::unsigned-size(16)>> <-
           value(shell, address, slot, block, nil, nil) do
      if rem(len, 2) == 0 do
        len = div(len, 2)
        binary_part(prefix, 0, len)
      else
        len = div(:binary.decode_unsigned(str) - 1, 2)
        slots = div(len - 1, 32) + 1

        Enum.map_join(1..slots, fn idx ->
          value(shell, address, add(slot, idx), block, <<0::256>>, nil)
        end)
        |> binary_part(0, len)
      end
    end
  end

  def list_at(shell, address, list_slot, block) do
    block = block || PeakBlock.number(shell)
    <<number::256>> = value(shell, address, list_slot, block, <<0::256>>, nil)

    if number > 0 do
      array_start =
        Hash.keccak_256(Hash.to_bytes32(list_slot))
        |> :binary.decode_unsigned()

      slots = Enum.map(0..(number - 1), fn index -> array_start + index end)
      values(shell, address, slots, block) |> Enum.map(&Hash.to_address/1)
    else
      []
    end
  end

  # function for getting the value of a hash at a given string or binaries key
  def hash_at(shell, address, hash_slot, key_string, block) do
    hash_at_binary(shell, address, hash_slot, Hash.keccak_256(key_string), block)
  end

  def hash_at_binary(shell, address, hash_slot, key, block) do
    block = block || PeakBlock.number(shell)
    hash_slot = hash_slot_binary(hash_slot, key)
    value(shell, address, hash_slot, block, <<0::256>>, nil)
  end

  def hash_slot_binary(hash_slot, key) do
    key = Hash.to_bytes32(key)
    base = Hash.to_bytes32(hash_slot)
    Hash.keccak_256(key <> base)
  end
end
