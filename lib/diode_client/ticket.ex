defmodule DiodeClient.Ticket do
  @moduledoc false

  defp mod(tck) do
    case elem(tck, 0) do
      :ticket -> DiodeClient.TicketV1
      :ticketv2 -> DiodeClient.TicketV2
    end
  end

  def key(tck), do: mod(tck).key(tck)
  def device_wallet(tck), do: mod(tck).device_wallet(tck)
  def device_address(tck), do: mod(tck).device_address(tck)
  def device_sign(tck, private), do: mod(tck).device_sign(tck, private)
  def server_sign(tck, private), do: mod(tck).server_sign(tck, private)
  def raw(tck), do: mod(tck).raw(tck)
  def device_blob(tck), do: mod(tck).device_blob(tck)
  def server_blob(tck), do: mod(tck).server_blob(tck)
  def server_id(tck), do: mod(tck).server_id(tck)
  def block_number(tck), do: mod(tck).block_number(tck)
  def device_signature(tck), do: mod(tck).device_signature(tck)
  def server_signature(tck), do: mod(tck).server_signature(tck)
  def fleet_contract(tck), do: mod(tck).fleet_contract(tck)
  def total_connections(tck), do: mod(tck).total_connections(tck)
  def total_bytes(tck), do: mod(tck).total_bytes(tck)
  def local_address(tck), do: mod(tck).local_address(tck)
  def preferred_server_ids(tck), do: mod(tck).preferred_server_ids(tck)
  def message(tck), do: mod(tck).message(tck)
end
