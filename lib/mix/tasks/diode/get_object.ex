defmodule Mix.Tasks.Diode.GetObject do
  @moduledoc """
  Fetch and print a Diode network object (ticket) for an address.

      mix diode.get_object 0xabcd...
  """
  @shortdoc "Fetch and print a Diode ticket object for an address"

  use Mix.Task

  alias DiodeClient.{Base16, Shell, Ticket, TicketV1, TicketV2}

  require TicketV1
  require TicketV2

  def run([address]) do
    Logger.configure(level: :info)
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()

    key = Base16.decode(address)
    IO.puts("getobject #{Base16.encode(key)}")
    print_object(Shell.get_object(key))
  end

  def run(_) do
    Mix.shell().error("Usage: mix diode.get_object <address>")
    System.halt(1)
  end

  defp print_object(nil) do
    IO.puts("not found")
  end

  defp print_object(
         {:ticket, server_id, block_number, block_hash, fleet_contract, total_connections,
          total_bytes, local_address, device_signature, server_signature}
       ) do
    tck =
      TicketV1.ticket(
        server_id: server_id,
        block_number: block_number,
        block_hash: block_hash,
        fleet_contract: fleet_contract,
        total_connections: total_connections,
        total_bytes: total_bytes,
        local_address: local_address,
        device_signature: device_signature,
        server_signature: server_signature
      )

    print_common(tck, :ticket)
    puts("block_number", Ticket.block_number(tck))
    puts("block_hash", Base16.encode(block_hash))
    puts("epoch", Ticket.epoch(tck))
  end

  defp print_object(
         {:ticketv2, server_id, chain_id, epoch, fleet_contract, total_connections, total_bytes,
          local_address, device_signature, server_signature}
       ) do
    tck =
      TicketV2.ticketv2(
        server_id: server_id,
        chain_id: chain_id,
        epoch: epoch,
        fleet_contract: fleet_contract,
        total_connections: total_connections,
        total_bytes: total_bytes,
        local_address: local_address,
        device_signature: device_signature,
        server_signature: server_signature
      )

    print_common(tck, :ticketv2)
    puts("chain_id", chain_id)
    puts("epoch", Ticket.epoch(tck))
    puts("block_number (hint)", Ticket.block_number(tck))
  end

  defp print_common(tck, type) do
    puts("type", type)
    puts("device_address", Base16.encode(Ticket.device_address(tck)))
    puts("server_id", Base16.encode(Ticket.server_id(tck)))
    puts("fleet_contract", Base16.encode(Ticket.fleet_contract(tck)))
    puts("total_connections", Ticket.total_connections(tck))
    puts("total_bytes", Ticket.total_bytes(tck))
    puts("local_address", format_local_address(Ticket.local_address(tck)))
    print_metadata(tck)
    puts("preferred_server_ids", format_addresses(Ticket.preferred_server_ids(tck)))
    puts("device_signature", Base16.encode(Ticket.device_signature(tck)))

    case Ticket.server_signature(tck) do
      nil -> puts("server_signature", "nil")
      sig -> puts("server_signature", Base16.encode(sig))
    end
  end

  defp print_metadata(tck) do
    %{version: version, timestamp: timestamp} = Ticket.metadata(tck)

    puts("metadata_version", version)
    puts("metadata_timestamp", format_metadata_timestamp(version, timestamp))
  end

  defp format_metadata_timestamp(2, timestamp), do: Integer.to_string(timestamp)
  defp format_metadata_timestamp(_version, _timestamp), do: "n/a"

  defp format_local_address(<<pref, addr::binary-size(20)>>) when pref in [0, 1] do
    preference =
      case pref do
        0 -> "alternate first"
        1 -> "server_id first"
      end

    "#{preference}, #{Base16.encode(addr)}"
  end

  defp format_local_address(<<2, _meta::binary>>), do: "metadata v2 (RLP-encoded)"

  defp format_local_address(la), do: Base16.encode(la)

  defp format_addresses(addrs) do
    Enum.map_join(addrs, ", ", &Base16.encode/1)
  end

  defp puts(key, value) do
    IO.puts("#{String.pad_trailing(key, 24)}: #{value}")
  end
end
