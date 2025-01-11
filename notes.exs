# Aug 22nd
DiodeClient.interface_add("example_server_interface")
DiodeClient.Manager.get_peak(DiodeClient.Shell)

pid = spawn(fn ->
  DiodeClient.Shell.Moonbeam.get_account_root(<<146, 135, 11, 38, 142, 74, 134, 157, 21, 213, 196, 68, 154, 200, 70, 13, 34, 110, 102, 94>>)
  |> IO.inspect(label: "get_account_root")
end)

pid3 = spawn(fn ->
  DiodeClient.Shell.get_account_root(<<146, 135, 11, 38, 142, 74, 134, 157, 21, 213, 196, 68, 154, 200, 70, 13, 34, 110, 102, 94>>)
  |> IO.inspect(label: "get_account_root")
end)

pid2 = spawn(fn ->
  DiodeClient.Manager.get_connection()
  |> IO.inspect(label: "connection")
end)

[c] = DiodeClient.Manager.connections()

Process.info(pid, :current_stacktrace)
Process.info(c, :current_stacktrace)

:sys.get_state(DiodeClient.Manager)

# July 31st
DiodeClient.address()
bns = DiodeClient.Base16.decode("0xAF60FAA5CD840B724742F1AF116168276112D6A6")

c = DiodeClient.Manager.connections() |> Enum.find(fn c -> DiodeClient.Connection.server_url(c) == "eu1.prenet.diode.io" end)

for c <- DiodeClient.Manager.connections() do
  DiodeClient.ETSLru.flush(DiodeClient.ShellCache)
  DiodeClient.Manager.set_connection(c)
  IO.inspect({DiodeClient.Connection.server_url(c), DiodeClient.Shell.get_account(bns)})
  :ok
end


# Older

alias DiodeClient.Connection
alias DiodeClient.Connection
alias DiodeClient.{Shell, Ticket, TicketV2, Wallet}
import TicketV2

DiodeClient.ensure_wallet()

shell = Shell.Moonbeam
server = <<174, 105, 146, 17, 198, 33, 86, 184, 242, 156, 225, 123, 228, 125, 47, 6, 154, 39, 242, 166>>
tck = ticketv2(
  server_id: server,
  epoch: 662,
  chain_id: shell.chain_id(),
  total_connections: 128,
  total_bytes: 3_000_000,
  local_address: "",
  fleet_contract: DiodeClient.Base16.decode("0x8aFe08d333f785C818199a5bdc7A52ac6Ffc492A")
)

tck = Ticket.device_sign(tck, Wallet.privkey!(DiodeClient.wallet()))
tck = Ticket.server_sign(tck, <<13, 165, 190, 171, 98, 229, 162, 46, 209, 12, 168, 24, 106, 67, 115, 84, 194, 67, 69, 28, 110, 90, 145, 156, 179, 111, 32, 66, 45, 94, 168, 193>>)
