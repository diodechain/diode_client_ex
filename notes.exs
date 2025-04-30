# May 2nd 2025

contract = DiodeClient.Base16.decode("0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9")
tx = DiodeClient.Shell.OasisSapphire.create_transaction(contract, "Version", [], [])
DiodeClient.Shell.OasisSapphire.oasis_call(tx)


```bash
export host=https://sapphire.oasis.io
curl -k -H "Content-Type: application/json"  -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"from": "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A", "value": "0x0", "to": "0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9", "data": "0xa36464617461a264626f6479a462706b5820774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c506464617461581b344d40cf5152fa41f385b1f938f74c6d3bf4936e4435757ff762af6565706f6368199ed6656e6f6e63654ff4070095899c96c4e767d329f526b466666f726d617401656c65617368a4656e6f6e6365006a626c6f636b5f6861736858204a90b69a09be2bc87c7b6371f6c78be8aeb42d001341ffa98ac993811527ae606b626c6f636b5f72616e67650f6c626c6f636b5f6e756d6265721a0084aada697369676e617475726558414a45b184c2feaecde6246feabae2e9843d8c7b1ac448af3223c15b6d4b9e768619089e1178ac87f13a75f1db74ad266c12ab8656639741e93c16f16cff6ded461c", "gas": "0x1c9c380", "gasPrice": "0x174876e800"}, "0x84AADB"],"id":74}' $host

curl -k -H "Content-Type: application/json"  -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"from": "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A", "value": "0x0", "to": "0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9", "data": "0xa36464617461a264626f6479a46464617461581b344d40cf5152fa41f385b1f938f74c6d3bf4936e4435757ff762af6565706f6368199ed6656e6f6e63654ff4070095899c96c4e767d329f526b462706b5820774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c5066666f726d617401656c65617368a46a626c6f636b5f6861736858204a90b69a09be2bc87c7b6371f6c78be8aeb42d001341ffa98ac993811527ae606c626c6f636b5f6e756d6265721a0084aada6b626c6f636b5f72616e67650f656e6f6e636500697369676e617475726558414a45b184c2feaecde6246feabae2e9843d8c7b1ac448af3223c15b6d4b9e768619089e1178ac87f13a75f1db74ad266c12ab8656639741e93c16f16cff6ded461c", "gas": "0x1c9c380", "gasPrice": "0x174876e800"}, "0x84AADB"],"id":74}' $host

```

{'types': {'EIP712Domain': [{'name': 'name', 'type': 'string'}, {'name': 'version', 'type': 'string'}, {'name': 'chainId', 'type': 'uint256'}], 'Call': [{'name': 'from', 'type': 'address'}, {'name': 'to', 'type': 'address'}, {'name': 'gasLimit', 'type': 'uint64'}, {'name': 'gasPrice', 'type': 'uint256'}, {'name': 'value', 'type': 'uint256'}, {'name': 'data', 'type': 'bytes'}, {'name': 'leash', 'type': 'Leash'}], 'Leash': [{'name': 'nonce', 'type': 'uint64'}, {'name': 'blockNumber', 'type': 'uint64'}, {'name': 'blockHash', 'type': 'bytes32'}, {'name': 'blockRange', 'type': 'uint64'}]}, 'primaryType': 'Call', 'domain': {'name': 'oasis-runtime-sdk/evm: signed query', 'version': '1.0.0', 'chainId': 23294}, 'message': {'from': '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A', 'to': '0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9', 'value': '0x0', 'gasLimit': 30000000, 'gasPrice': 100000000000, 'data': b'\xbbb\x86\r', 'leash': {'nonce': 0, 'blockNumber': 8664283, 'blockHash': b'\x0f/\xab\xc0\xd2\xff\x12N6\xa6\x90\x85X\xd7\x92aG\xa0\xe7\x83ra\xd9\xdb\x86\xaaz2\x043\xb9\x89', 'blockRange': 15}}}

# Apr 29th 2025
sk private key 0xa91df693eb664b5e2d56d3d979fee99ba3507f0a24e26e2a4a485b12d2fa148b
sk public key 0x774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c50
eth_call [{'from': '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A', 'value': '0x0', 'to': '0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9', 'data': '0xa36464617461a264626f6479a462706b5820774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c506464617461581ba715cdabe4ccb2f5160c952f265c0608ce6280e03b43983a6b07b46565706f6368199e8e656e6f6e63654ff4070095899c96c4e767d329f526b466666f726d617401656c65617368a4656e6f6e6365006a626c6f636b5f686173685820abfcf8b66064b7a4b6606545134fbce4fa0c672e1556d9975efa222038fac8426b626c6f636b5f72616e67650f6c626c6f636b5f6e756d6265721a00840926697369676e61747572655841e9e9136d6beb8f13503030d10c3ea329d986a7e7c23e1c9dccb94baac1800dbc6d8d22ab1180b09e57ae2218201558326d82596b2b234265138cce5af4fd67a81c', 'gas': '0x1c9c380', 'gasPrice': '0x174876e800'}, 'latest']

DiodeClient.set_wallet(fn -> DiodeClient.Wallet.from_privkey(DiodeClient.Base16.decode("0x" <> String.duplicate("1", 64))) end)
alias DiodeClient.Base16
ref = Base16.decode("0xa36464617461a264626f6479a462706b5820774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c506464617461581ba715cdabe4ccb2f5160c952f265c0608ce6280e03b43983a6b07b46565706f6368199e8e656e6f6e63654ff4070095899c96c4e767d329f526b466666f726d617401656c65617368a4656e6f6e6365006a626c6f636b5f686173685820abfcf8b66064b7a4b6606545134fbce4fa0c672e1556d9975efa222038fac8426b626c6f636b5f72616e67650f6c626c6f636b5f6e756d6265721a00840926697369676e61747572655841e9e9136d6beb8f13503030d10c3ea329d986a7e7c23e1c9dccb94baac1800dbc6d8d22ab1180b09e57ae2218201558326d82596b2b234265138cce5af4fd67a81c")
{:ok, db, ""} = CBOR.decode(ref)

# Apr 22nd 2025
rpc = "https://sapphire.oasis.io"
{json, 0} = System.cmd("cast", ["rpc", "oasis_callDataPublicKey", "--rpc-url", rpc])
json = Jason.decode!(json)


# Apr 20th 2025

DiodeClient.set_wallet(fn -> DiodeClient.Wallet.from_privkey(DiodeClient.Base16.decode("0x" <> String.duplicate("1", 64))) end)
alias DiodeClient.Base16

contract = DiodeClient.Base16.decode("0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9")
contract_hex = DiodeClient.Base16.encode(contract)
client = DiodeClient.address()
client_hex = DiodeClient.Base16.encode(client)

nonce = 0
block_number = 8694491
block_hash = DiodeClient.Base16.decode("0x4a90b69a09be2bc87c7b6371f6c78be8aeb42d001341ffa98ac993811527ae60")
opts = [
  gasLimit: 10_000_000,
  to: contract,
  nonce: nonce,
  block_number: block_number,
  block_hash: block_hash,
  from: client
]
data = DiodeClient.ABI.encode_call("Version")
data_hex = DiodeClient.Base16.encode(data)
call = DiodeClient.Contracts.OasisSapphire.new_signed_call_data_pack(DiodeClient.ensure_wallet(), data, opts)
call_hex = DiodeClient.Base16.encode(call.data_pack)
CBOR.decode(call.data_pack)
rpc = "https://sapphire.oasis.io"

IO.puts("cast " <> Enum.join(["call", contract_hex, "--data", call_hex, "--rpc-url", rpc, "--from", client_hex, "-b", "#{block_number}", "--gas-limit", "#{call.msg["gasLimit"]}", "--gas-price", "#{call.msg["gasPrice"]}"], " "))
System.cmd("cast", ["call", contract_hex, "--data", call_hex, "--rpc-url", rpc, "--from", client_hex, "-b", "#{block_number}", "--gas-limit", "#{call.msg["gasLimit"]}", "--gas-price", "#{call.msg["gasPrice"]}"])

System.cmd("cast", ["call", contract_hex, "--data", data_hex, "--rpc-url", rpc, "--from", client_hex, "-b", "#{block_number}", "--gas-limit", "#{call.msg["gasLimit"]}", "--gas-price", "#{call.msg["gasPrice"]}"])


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
