defmodule Mix.Tasks.Resolve do
  alias DiodeClient.{Base16, Contracts}

  def run([address]) do
    Logger.configure(level: :info)
    IO.puts("Resolving #{address}...")
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
    resolve(address)
  end

  def resolve(name, level \\ 0)

  def resolve("0x" <> _ = hex, level) do
    if DiodeClient.Shell.get_account_root(Base16.decode(hex)) do
      owner = Contracts.DriveMember.owner?(DiodeClient.Shell, Base16.decode(hex), nil)
      members = Contracts.DriveMember.members(DiodeClient.Shell, Base16.decode(hex), nil)

      if owner == false do
        DiodeClient.Shell.get_account_root(Base16.decode(hex)) |> IO.inspect()
        DiodeClient.Shell.get_account(Base16.decode(hex)) |> IO.inspect()
      end

      puts(level, "owner", if(owner, do: Base16.encode(owner), else: "nil"))

      {hex,
       for name <- members do
         puts(level, "name", Base16.encode(name))
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
    puts(level, "owner", Base16.encode(owner))

    {name,
     for name <- names do
       puts(level, "name", Base16.encode(name))
       resolve(Base16.encode(name), level + 1)
     end}
  end

  defp puts(level, key, value) do
    key = String.pad_leading("", level * 2) <> "┗━" <> key
    IO.puts("#{String.pad_trailing(key, 20)}: #{value}")
  end
end
