# Feb 4th 2025

┗━BNS owner         : 0x0530f2dfdab4860f4c0bde8a7bced46b1b76038d
┗━BNS name[0]       : 0x5849ea89593cf65e13110690d9339c121801a45c
  ┗━reverse-name    : knusperhaus.glmr
  ┗━owner           : 0x0530f2dfdab4860f4c0bde8a7bced46b1b76038d
  ┗━member          : 0x2f9881d85483f7973d80107866bec842abfc7504 Role.None
  ┗━member          : 0x40cb2d1d56aa2a856c9998d5bbf8011e5a25b026 Role.None
    ┗━reverse-name  : knusperhaus.diode
  ┗━member          : 0x77aeebfbaa1a1ac390ab46b7c9e35a5bc46f07ad Role.None
  ┗━member          : 0xa6d41640d29d9e032c9db85ddc51d6197c9bfbd1 Role.None
  ┗━member          : 0xee5fe238bb487b8cfbffdb753c15d90697500425 Role.None
  ┗━member          : 0x51c67925853b11be65afe9cfe2fd2313fff80b73 Role.None
  ┗━member          : 0x0530f2dfdab4860f4c0bde8a7bced46b1b76038d Role.Owner

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
