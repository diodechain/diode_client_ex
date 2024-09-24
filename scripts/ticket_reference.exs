# Description: This script is used to generate a ticket for the device to connect to the server.
# Run with:
# `mix run scripts/ticket_reference.exs`

defmodule TicketReference do
  alias DiodeClient.{Base16, Hash, Rlp, TicketV2, Wallet}
  import TicketV2

  def run() do
    device_wallet =
      Wallet.from_privkey(
        Base16.decode("0xc8654718fc3a9d546843e34efccf1497048b2c922e9a362cf065d978904d0857")
      )

    IO.inspect(Wallet.base16(device_wallet), label: "Device Address")

    server_wallet =
      Wallet.from_pubkey(
        Base16.decode(
          "0x041d4e9e6cd6de7f3d02b3a9bdcdd95a252307a8717b4e5441130c5f93cce626886d43861bf778527a2658b7ef0d195e2bed49f009a2ef683ac25a41df49c3181d"
        )
      )

    IO.inspect(Wallet.base16(server_wallet), label: "Server Address")

    tck =
      ticketv2(
        server_id: Wallet.address!(server_wallet),
        epoch: 666,
        chain_id: 1284,
        total_connections: 1,
        total_bytes: 128_000,
        local_address: "test",
        # fleet_contract: DiodeClient.Base16.decode("0x8aFe08d333f785C818199a5bdc7A52ac6Ffc492A")
        fleet_contract: DiodeClient.Base16.decode("0x6000000000000000000000000000000000000000")
      )

    IO.inspect(tck, label: "Ticket Data")
    IO.inspect(Base16.encode(TicketV2.device_blob(tck)), label: "Device Blob", limit: 1000)

    IO.inspect(Base16.encode(Hash.keccak_256(TicketV2.device_blob(tck))),
      label: "Device Blob Digest"
    )

    tck = TicketV2.device_sign(tck, Wallet.privkey!(device_wallet))

    IO.inspect(Base16.encode(TicketV2.device_signature(tck)),
      label: "Device Signature",
      limit: 1000
    )

    IO.inspect(TicketV2.message(tck), label: "Ticket Message", limit: 1000)

    request_id = <<5>>
    msg = Rlp.encode!([request_id, TicketV2.message(tck)])
    msg = <<byte_size(msg)::unsigned-size(16)>> <> msg
    IO.inspect(Base16.encode(msg), label: "Ticket Request Package", limit: 1000)
  end
end

TicketReference.run()
