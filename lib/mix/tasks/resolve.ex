defmodule Mix.Tasks.Resolve do
  @moduledoc false
  alias DiodeClient.{Base16, Contracts}

  def run([address]) do
    Logger.configure(level: :info)
    IO.puts("Resolving #{address}...")
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
    resolve(address)
  end

  def resolve(name, level \\ 0)

  def resolve(hex = "0x" <> _, level) do
    with name when name != nil <- Contracts.BNS.resolve_address(Base16.decode(hex)) do
      puts(level, "reverse-name", name)
    end

    shell =
      cond do
        DiodeClient.Shell.get_account_root(Base16.decode(hex)) != nil ->
          DiodeClient.Shell

        DiodeClient.Shell.Moonbeam.get_account_root(Base16.decode(hex)) != nil ->
          DiodeClient.Shell.Moonbeam

        true ->
          nil
      end

    if shell do
      owner = Contracts.DriveMember.owner?(shell, Base16.decode(hex), nil)
      members = Contracts.DriveMember.members(shell, Base16.decode(hex), nil)

      # if owner == false do
      #   DiodeClient.Shell.get_account_root(Base16.decode(hex)) |> IO.inspect()
      #   DiodeClient.Shell.get_account(Base16.decode(hex)) |> IO.inspect()
      # end

      puts(level, "owner", if(owner, do: Base16.encode(owner), else: "nil"))

      {hex,
       for name <- members do
         puts(level, "member", Base16.encode(name))
         resolve(Base16.encode(name), level + 1)
       end}
    else
      hex
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

    {name,
     for {name, index} <- Enum.with_index(names) do
       puts(level, "BNS name[#{index}]", Base16.encode(name))
       resolve(Base16.encode(name), level + 1)
     end}
  end

  defp puts(level, key, value) do
    key = String.pad_leading("", level * 2) <> "┗━" <> key
    IO.puts("#{String.pad_trailing(key, 20)}: #{value}")
  end
end
