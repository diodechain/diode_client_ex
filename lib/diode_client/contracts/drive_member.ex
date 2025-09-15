defmodule DiodeClient.Contracts.DriveMember do
  @moduledoc """
  Imported contract to read group memberships. Useful to recursively resolve
  BNS names to individual devices.
  """
  alias DiodeClient.{Base16, Hash}
  alias DiodeClient.Contracts, as: Contract

  @slot_owner 51
  @slot_members_list 53
  @slot_drive_address 54
  @slot_addtl_drive_addresses 55

  @slot_target 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
  @slot_factory 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103

  def transfer_ownership(shell, address, new_owner) do
    cast(shell, address, "transferOwnership", ["address"], [new_owner])
  end

  # def set_drive(address, drive_address) do
  #   cast(address, "SetDrive", ["address"], [drive_address])
  # end

  def add_drive(shell, address, drive_address) do
    cast(shell, address, "AddDrive", ["address"], [drive_address])
  end

  def add_member(shell, address, member) do
    cast(shell, address, "AddMember", ["address"], [member])
  end

  def remove_member(shell, address, member) do
    cast(shell, address, "RemoveMember", ["address"], [member])
  end

  # todo
  def submit_transaction(shell, address, drive_address = <<_::160>>, tx) do
    cast(shell, address, "SubmitTransaction", ["address", "bytes"], [drive_address, tx])
  end

  def owner(shell, address, block) do
    case owner?(shell, address, block) do
      false ->
        raise(
          "DriveMember: owner=nil invalid for member contract #{Base16.encode(address)} in block: #{inspect(block)}"
        )

      owner ->
        Hash.to_address(owner)
    end
  end

  def owner?(shell, address, block) do
    Contract.Utils.address(shell, address, @slot_owner, block) || false
  end

  def drive_address(shell, address, block) do
    Contract.Utils.address(shell, address, @slot_drive_address, block) || <<0::256>>
  end

  def addtl_drive_addresses(shell, address, block) do
    Contract.Utils.list_at(shell, address, @slot_addtl_drive_addresses, block)
  end

  def proxy_factory(shell, address, block) do
    Contract.Utils.address(shell, address, @slot_factory, block)
  end

  def proxy_target(shell, address, block) do
    Contract.Utils.address(shell, address, @slot_target, block)
  end

  def members(shell, address, block) when shell == DiodeClient.Shell do
    block = block || shell.peak()

    case owner?(shell, address, block) do
      false ->
        []

      owner ->
        members = Contract.Utils.list_at(shell, address, @slot_members_list, block)

        if Enum.member?(members, owner) do
          members
        else
          [owner | members]
        end
    end
  end

  def members(shell, address, block) do
    block = block || shell.peak()
    Contract.Utils.call(shell, address, "Members", [], [], "address[]", block)
  end

  def member(shell, address, index, block) do
    array_start =
      Hash.keccak_256(Hash.to_bytes32(@slot_members_list))
      |> :binary.decode_unsigned()

    Contract.Utils.value(shell, address, array_start + index, block, :undefined, nil)
    |> Hash.to_address()
  end

  # helpful to track changes to the contract state
  def root(shell, address, block) do
    shell.get_account_root(address, block)
  end

  defp cast(shell, address, name, types, args) do
    shell.send_transaction(address, name, types, args)
  end
end
