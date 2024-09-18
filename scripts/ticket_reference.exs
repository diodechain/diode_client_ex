# Description: This script is used to generate a ticket for the device to connect to the server.
# Run with:
# `mix run scripts/ticket_reference.exs`

defmodule TicketReference do
  alias DiodeClient.{Base16, Hash, Rlp, TicketV2, Wallet}
  import TicketV2

  def run() do
    device_wallet =
      Wallet.from_privkey(
        Base16.decode("0x7336f02f2bac8fb693a96848f6e70f0da7b474193b6dd63c76478ba92e982025")
      )

    server_wallet =
      Wallet.from_pubkey(
        Base16.decode("0x02a49e15dc55dbb6a6756b695b508002c7cab42429ab826ee6e07ad5109655204c")
      )

    tck =
      ticketv2(
        server_id: Wallet.address!(server_wallet),
        epoch: 666,
        chain_id: 1284,
        total_connections: 1,
        total_bytes: 128_000,
        local_address: "test",
        fleet_contract: DiodeClient.Base16.decode("0x8aFe08d333f785C818199a5bdc7A52ac6Ffc492A")
      )

    IO.inspect(tck, label: "Ticket Data")
    IO.inspect(TicketV2.device_blob(tck), label: "Device Blob", limit: 1000)
    IO.inspect(Hash.keccak_256(TicketV2.device_blob(tck)), label: "Device Blob Digest")
    tck = TicketV2.device_sign(tck, Wallet.privkey!(device_wallet))
    IO.inspect(TicketV2.device_signature(tck), label: "Device Signature", limit: 1000)
    IO.inspect(TicketV2.message(tck), label: "Ticket Message", limit: 1000)

    request_id = <<71, 76, 30, 165>>
    msg = Rlp.encode!([request_id, TicketV2.message(tck)])
    IO.inspect(msg, label: "Ticket Request Package", limit: 1000)
  end
end

TicketReference.run()
