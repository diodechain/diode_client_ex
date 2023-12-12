defmodule DiodeClient.Contracts.DriveMember do
  alias DiodeClient.Hash

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
    DiodeClient.Contracts.Utils.value(shell, address, @slot_owner, block, :undefined, nil)
    |> Hash.to_address()
  end

  def owner?(shell, address, block) do
    DiodeClient.Contracts.Utils.address(shell, address, @slot_owner, block) || false
  end

  def drive_address(shell, address, block) do
    DiodeClient.Contracts.Utils.address(shell, address, @slot_drive_address, block) || <<0::256>>
  end

  def addtl_drive_addresses(shell, address, block) do
    block = block || shell.peak()

    <<number::256>> =
      DiodeClient.Contracts.Utils.value(shell, address, @slot_addtl_drive_addresses, block, <<0::256>>, nil)

    array_start =
      Hash.keccak_256(Hash.to_bytes32(@slot_addtl_drive_addresses))
      |> :binary.decode_unsigned()

    range = if number > 0, do: 0..(number - 1), else: []

    Enum.map(range, fn index ->
      DiodeClient.Contracts.Utils.address(shell, address, array_start + index, block)
    end)
  end

  def proxy_factory(shell, address, block) do
    DiodeClient.Contracts.Utils.address(shell, address, @slot_factory, block)
  end

  def proxy_target(shell, address, block) do
    DiodeClient.Contracts.Utils.address(shell, address, @slot_target, block)
  end

  def members(shell, address, block) do
    [owner, member_list] =
      DiodeClient.Contracts.Utils.values(shell, address, [@slot_owner, @slot_members_list], block)

    case owner do
      :undefined ->
        []

      owner ->
        owner = Hash.to_address(owner)
        <<number::256>> = if is_binary(member_list), do: member_list, else: <<0::256>>

        if number > 0 do
          array_start =
            Hash.keccak_256(Hash.to_bytes32(@slot_members_list))
            |> :binary.decode_unsigned()

          list = Enum.map(0..(number - 1), fn index -> array_start + index end)

          DiodeClient.Contracts.Utils.values(shell, address, list, block)
          |> Enum.map(&Hash.to_address/1)
        else
          []
        end ++
          [owner]
    end
  end

  def member(shell, address, index, block) do
    array_start =
      Hash.keccak_256(Hash.to_bytes32(@slot_members_list))
      |> :binary.decode_unsigned()

      DiodeClient.Contracts.Utils.value(shell, address, array_start + index, block, :undefined, nil)
    |> Hash.to_address()
  end

  # helpfull to track changes to the contract state
  def root(shell, address, block) do
    shell.get_account(address, block || shell.peak()).storage_root
  end

  defp cast(shell, address, name, types, args) do
    Model.App.send_transaction(shell, address, name, types, args)
  end
end
