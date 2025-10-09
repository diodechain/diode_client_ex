defmodule DiodeClient.Contracts.Drive do
  @moduledoc """
  Zone (drive) contract methods
  """
  alias DiodeClient.Contracts.Utils

  def version(shell, address, block \\ nil) do
    Utils.call(shell, address, "Version", [], [], "uint256", block)
  end

  def owner(shell, address, block \\ nil) do
    Utils.call(shell, address, "owner", [], [], "address", block)
  end

  def member_roles(shell, address, block \\ nil) do
    block = block || shell.peak()

    case version(shell, address, block) do
      :revert ->
        :revert

      vsn when is_integer(vsn) and vsn <= 139 ->
        Utils.call(shell, address, "Members", [], [], "address[]", block)
        |> Task.async_stream(fn member ->
          {member, Utils.call(shell, address, "Role", ["address"], [member], "uint256", block)}
        end)
        |> Enum.map(fn {:ok, {member, role}} -> {member, int_to_role(role)} end)
        |> Map.new()
        |> Map.put(owner(shell, address, block), Role.Owner)

      vsn when is_integer(vsn) and vsn > 139 ->
        Utils.call(shell, address, "MemberRoles", [], [], "(address,uint256)[]", block)
        |> Map.new()
        |> Map.put(owner(shell, address, block), Role.Owner)

      _ ->
        :revert
    end
  end

  defp int_to_role(int) do
    case int do
      0 -> Role.None
      100 -> Role.BackupBot
      200 -> Role.Reader
      300 -> Role.Member
      400 -> Role.Admin
      500 -> Role.Owner
    end
  end
end
