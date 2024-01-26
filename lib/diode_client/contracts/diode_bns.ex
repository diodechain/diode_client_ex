defmodule DiodeClient.Contracts.DiodeBNS do
  @moduledoc """
  Location of the BNS smart contract on Diode Network.
  """
  alias DiodeClient.{Hash, Shell}
  @address Hash.to_address(0xAF60FAA5CD840B724742F1AF116168276112D6A6)
  use DiodeClient.Contracts.Utils, {@address, Shell}

  def is_bns(address) do
    address == @address
  end
end
