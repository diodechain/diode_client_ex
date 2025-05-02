defmodule DiodeClient.Contracts.Zone do
  @moduledoc false
  alias DiodeClient.{Base16, Hash}
  import DiodeClient.Contracts.Utils

  @slot_owner 51
  @slot_members_list 53
  @slot_members_hash 54
  @slot_data Hash.keccak_256("DATA_SLOT")

  def transfer_ownership(shell, address, new_owner) do
    cast(shell, address, "transferOwnership", ["address"], [new_owner])
  end

  def set_role_value(shell, address, role, key, value)
      when is_atom(role) and is_binary(key) and is_binary(value) do
    role = role_to_int(role)

    cast(shell, address, "SetRoleValue", ["uint256", "uint256", "uint256"], [
      role,
      :binary.decode_unsigned(key),
      :binary.decode_unsigned(value)
    ])
  end

  def add_member(shell, address, member) do
    cast(shell, address, "AddMember", ["address"], [member])
  end

  def add_backup(shell, address, member) do
    cast(shell, address, "AddBackup", ["address"], [member])
  end

  def add_reader(shell, address, member) do
    cast(shell, address, "AddReader", ["address"], [member])
  end

  @doc """
  This function can only be called from the drive owner. It's adds a new member
  with the given role OR updates the role of an existing member.
  """
  def add_member(shell, address, member, role) do
    cast(shell, address, "AddMember", ["address", "uint256"], [member, role_to_int(role)])
  end

  def remove_member(shell, address, member) do
    cast(shell, address, "RemoveMember", ["address"], [member])
  end

  def remove_self(shell, address) do
    cast(shell, address, "RemoveSelf", [], [])
  end

  def owner(shell, address, block) do
    case value(shell, address, @slot_owner, block, :undefined, nil) do
      :undefined -> raise "Contract owner for #{Base16.encode(address)} not found"
      hash -> Hash.to_address(hash)
    end
  end

  def owner?(shell, address, block) do
    value(shell, address, @slot_owner, block, :undefined, nil)
    |> case do
      nil -> {:error, "Contract owner for #{Base16.encode(address)} not found"}
      hash -> Hash.to_address(hash)
    end
  end

  def members(shell, address, block) do
    block = block || shell.peak()
    members = list_at(shell, address, @slot_members_list, block)
    role_base = Hash.to_bytes32(@slot_members_hash)

    slots =
      Enum.map(members, fn member_address ->
        Hash.keccak_256(Hash.to_bytes32(member_address) <> role_base)
      end)

    roles =
      values(shell, address, slots, block)
      |> Enum.map(fn bin ->
        if bin == :undefined do
          raise "Shell #{shell} at #{Base16.encode(address)} returned :undefined as role value at block #{inspect(block)}."
        end

        :binary.decode_unsigned(bin)
        |> int_to_role()
      end)

    owner = owner(shell, address, block)

    Enum.zip([members, roles])
    |> Map.new()
    |> Map.put(owner, Role.Owner)
    |> Map.to_list()
  end

  def member(shell, address, index, block) do
    array_start =
      Hash.keccak_256(Hash.to_bytes32(@slot_members_list))
      |> :binary.decode_unsigned()

    value(shell, address, array_start + index, block, :undefined, nil)
    |> Hash.to_address()
  end

  def role(shell, address, member_address, block) do
    block = block || shell.peak()

    if owner(shell, address, block) == member_address do
      Role.Owner
    else
      base = Hash.to_bytes32(@slot_members_hash)
      slot = Hash.keccak_256(Hash.to_bytes32(member_address) <> base)

      value(shell, address, slot, block, "", nil)
      |> :binary.decode_unsigned()
      |> int_to_role()
    end
  end

  def role_to_int(role) do
    case role do
      Role.None -> 0
      Role.BackupBot -> 100
      Role.Reader -> 200
      Role.Member -> 300
      Role.Admin -> 400
      Role.Owner -> 500
    end
  end

  def int_to_role(int) do
    case int do
      000 -> Role.None
      100 -> Role.BackupBot
      200 -> Role.Reader
      300 -> Role.Member
      400 -> Role.Admin
      500 -> Role.Owner
    end
  end

  def max_role(r1, r2), do: max_role([r1, r2])

  def max_role(roles) do
    [Role.None | roles]
    |> Enum.map(fn
      nil -> role_to_int(Role.None)
      role -> role_to_int(role)
    end)
    |> Enum.max()
    |> int_to_role()
  end

  def role_value(shell, address, role, key, block \\ nil) do
    data_value(shell, address, role, key, block)
  end

  def data_value(shell, address, role, key, block \\ nil) do
    role = role_to_int(role)

    hash_at(
      shell,
      address,
      @slot_data,
      Hash.to_bytes32(role) <> Hash.to_bytes32(key),
      block
    )
  end

  # helpfull to track changes to the contract state
  def root(shell, address, block) do
    shell.get_account(address, block || shell.peak()).storage_root
  end

  defp cast(shell, address, name, types, args) do
    shell.send_transaction(address, name, types, args)
  end
end
