defmodule Mix.Tasks.Diode.Resolve do
  @moduledoc """
  Resolves an Ethereum address or BNS name (drive ownership, members, aliases).
  """
  @shortdoc "Resolve an address or BNS name"

  use Mix.Task

  alias DiodeClient.{Base16, Contracts}
  alias DiodeClient.Contracts.{Drive, DriveMember, Factory}

  def run([address]) do
    Logger.configure(level: :info)
    IO.puts("Resolving #{address}...")
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
    resolve(address)
  end

  def run(_) do
    IO.puts("Usage: mix diode.resolve <address>")
    System.halt(1)
  end

  def resolve(name, level \\ 0)

  def resolve(hex = "0x" <> _, level) do
    address = Base16.decode(hex)

    with name when name != nil <- Contracts.BNS.resolve_address(address) do
      puts(level, "reverse-name", name)
    end

    case shell_for(address) do
      nil ->
        hex

      shell ->
        type = Factory.contract_type(shell, address)
        puts(level, "type", type_label(type))
        resolve_contract(shell, address, hex, type, level)
    end
  end

  def resolve(name, level) do
    name =
      if String.contains?(name, ".") do
        name
      else
        name <> ".diode"
      end

    names = Contracts.BNS.resolve_name_all(name)
    owner = Contracts.BNS.resolve_name_owner(name)
    puts(level, "BNS owner", Base16.encode(owner))

    resolve(Base16.encode(owner), level + 1)

    {name,
     for {name, index} <- Enum.with_index(names) do
       puts(level, "BNS name[#{index}]", Base16.encode(name))
       resolve(Base16.encode(name), level + 1)
     end}
  end

  defp resolve_contract(shell, address, hex, :drive, level) do
    owner = Drive.owner(shell, address)
    puts(level, "owner", encode_addr(owner))

    case Drive.member_roles(shell, address) do
      roles when is_map(roles) ->
        {hex,
         for {member, role} <- roles do
           puts(level, "member", "#{Base16.encode(member)} #{inspect(role)}")
           resolve(Base16.encode(member), level + 1)
         end}

      other ->
        puts(level, "members", inspect(other))
        hex
    end
  end

  defp resolve_contract(shell, address, hex, :drive_member, level) do
    owner = DriveMember.owner?(shell, address, nil)
    members = as_list(DriveMember.members(shell, address, nil))
    addtl = as_list(DriveMember.addtl_drive_addresses(shell, address, nil))

    puts(level, "owner", encode_addr(owner))

    for {drive_address, idx} <- Enum.with_index(addtl) do
      puts(level, "addtl_drive_address[#{idx}]", Base16.encode(drive_address))
    end

    {hex,
     for member <- members do
       puts(level, "member", Base16.encode(member))
       resolve(Base16.encode(member), level + 1)
     end}
  end

  defp resolve_contract(_shell, _address, hex, _type, _level), do: hex

  defp shell_for(address) do
    cond do
      DiodeClient.Shell.get_account_root(address) != nil ->
        DiodeClient.Shell

      DiodeClient.Shell.Moonbeam.get_account_root(address) != nil ->
        DiodeClient.Shell.Moonbeam

      true ->
        nil
    end
  end

  # Runtime may return :revert / {:error, _} from eth_call; keep resolve robust.
  defp as_list(list) when is_list(list), do: list
  defp as_list(_), do: []

  defp encode_addr(addr) when is_binary(addr), do: Base16.encode(addr)
  defp encode_addr(false), do: "nil"
  defp encode_addr(nil), do: "nil"
  defp encode_addr(other), do: inspect(other)

  defp type_label(:drive), do: "Drive"
  defp type_label(:drive_member), do: "DriveMember"
  defp type_label(:unknown), do: "unknown"
  defp type_label({:other, name}), do: name

  defp puts(level, key, value) do
    key = String.pad_leading("", level * 2) <> "┗━" <> key
    IO.puts("#{String.pad_trailing(key, 20)}: #{value}")
  end
end
