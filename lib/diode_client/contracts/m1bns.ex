defmodule DiodeClient.Contracts.M1BNS do
  alias DiodeClient.Hash
  alias DiodeClient.Shell.MoonbaseAlpha, as: Shell
  @address Hash.to_address(0x75140F88B0F4B2FBC6DADC16CC51203ADB07FE36)
  use DiodeClient.Contracts.Utils, {@address, Shell}

  def is_bns(address) do
    address == @address
  end

  def send_transaction(name, types, args) do
    Model.App.send_transaction(Shell, @address, name, types, args)
  end
end
