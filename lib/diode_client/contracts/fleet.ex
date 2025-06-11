defmodule DiodeClient.Contracts.Fleet do
  @moduledoc """
  Fleet contract
  """
  def device_allowlisted?(shell, fleet, device, block \\ nil) do
    shell.call(fleet, "DeviceAllowlisted", ["address"], [device],
      block: block,
      result_types: ["bool"]
    )
  end
end
