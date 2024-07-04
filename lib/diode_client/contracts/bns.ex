defmodule DiodeClient.Contracts.BNS do
  @moduledoc """
  Wrapper for BNS smart contract to register and resolve names.
  """
  import DiodeClient.Contracts.Utils
  alias DiodeClient.{Hash}
  @slot_names 1
  @slot_reverse_names 2

  def is_bns(address) do
    DiodeClient.Contracts.DiodeBNS.is_bns(address) || DiodeClient.Contracts.M1BNS.is_bns(address)
  end

  def register(name, destination) do
    {impl, name} = name_to_impl(name)
    cast(impl, "Register", ["string", "address"], [name, destination])
  end

  def unregister(name) do
    {impl, name} = name_to_impl(name)
    cast(impl, "Unregister", ["string"], [name])
  end

  def register_multiple(name, destinations) do
    {impl, name} = name_to_impl(name)
    cast(impl, "RegisterMultiple", ["string", "address[]"], [name, destinations])
  end

  def register_reverse(destination, name) do
    {impl, name} = name_to_impl(name)
    cast(impl, "RegisterReverse", ["address", "string"], [destination, name])
  end

  def resolve_name(name, block \\ nil)

  def resolve_name("", _block) do
    nil
  end

  def resolve_name(name, block) do
    {impl, name} = name_to_impl(name)

    name_hash = Hash.keccak_256(name)
    base = Hash.to_bytes32(@slot_names)

    Hash.keccak_256(name_hash <> base)
    |> impl.address(block)
  end

  def resolve_name_owner(name, block \\ nil) do
    {_shell, addr} = resolve_name_owner_ext(name, block)
    addr
  end

  def resolve_name_owner_ext(name, block \\ nil) do
    {impl, name} = name_to_impl(name)
    name_hash = Hash.keccak_256(name)
    base = Hash.to_bytes32(@slot_names)

    addr =
      Hash.keccak_256(name_hash <> base)
      |> add(1)
      |> impl.address(block)

    {impl.shell(), addr}
  end

  def resolve_name_all(orig_name, block \\ nil) do
    {impl, name} = name_to_impl(orig_name)
    name_hash = Hash.keccak_256(name)
    base = Hash.to_bytes32(@slot_names)

    array_slot = Hash.keccak_256(name_hash <> base) |> add(3)
    size = impl.number(array_slot, block)

    if size == 0 do
      name = resolve_name(orig_name)

      if name == nil do
        []
      else
        [name]
      end
    else
      array_start = Hash.keccak_256(array_slot)

      Enum.map(1..size, fn idx ->
        impl.address(add(array_start, idx - 1), block)
      end)
    end
  end

  def resolve_address(address, block \\ nil) do
    base = Hash.to_bytes32(@slot_reverse_names)
    slot = Hash.keccak_256(Hash.to_bytes32(address) <> base)

    # either(:string, [slot, block])

    if DiodeClient.Contracts.DiodeBNS.storage_root() != nil do
      maybe_extend(DiodeClient.Contracts.DiodeBNS.string(slot, block), ".diode")
    end ||
      if DiodeClient.Contracts.M1BNS.storage_root() != nil do
        maybe_extend(DiodeClient.Contracts.M1BNS.string(slot, block), ".m1")
      end
  end

  defp maybe_extend("", _), do: nil
  defp maybe_extend(nil, _), do: nil
  defp maybe_extend(str, postfix), do: str <> postfix

  defp cast(impl, method, types, args) do
    impl.send_transaction(method, types, args)
  end

  defp name_to_impl(name) do
    case String.split(name, ".") do
      [name, "diode"] -> {DiodeClient.Contracts.DiodeBNS, name}
      [name, "m1"] -> {DiodeClient.Contracts.M1BNS, name}
    end
  end

  def name_to_shell(name) do
    case String.split(name, ".") do
      [_name, "glmr"] -> DiodeClient.Shell.Moonbeam
      [_name, "diode"] -> DiodeClient.Shell
      [_name, "m1"] -> DiodeClient.Shell.MoonbaseAlpha
      _ -> nil
    end
  end
end
