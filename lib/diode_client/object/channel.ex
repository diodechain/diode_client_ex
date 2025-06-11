# Diode Server
# Copyright 2021-2024 Diode
# Licensed under the Diode License, Version 1.1
defmodule DiodeClient.Object.Channel do
  alias DiodeClient.{ABI, Hash, Rlp, Secp256k1, Wallet}
  require Record
  @behaviour DiodeClient.Object

  Record.defrecord(:channel,
    server_id: nil,
    chain_id: nil,
    block_number: nil,
    fleet_contract: nil,
    type: nil,
    name: nil,
    params: [],
    signature: nil
  )

  @type channel ::
          record(:channel,
            server_id: binary(),
            chain_id: binary(),
            block_number: integer(),
            fleet_contract: binary(),
            type: binary(),
            name: binary(),
            params: [],
            signature: Secp256k1.signature()
          )

  def new(server_id, fleet, name, device_sig) do
    channel(server_id: server_id, fleet_contract: fleet, name: name, signature: device_sig)
  end

  @impl true
  def key(channel(fleet_contract: fleet, type: type, name: name, params: params)) do
    params = Rlp.encode!(params) |> Hash.keccak_256()
    Hash.sha3_256(<<fleet::binary-size(20), type::binary, name::binary, params::binary>>)
  end

  @impl true
  def valid?(ch = channel()) do
    valid_type?(ch) and valid_device?(ch) and valid_params?(ch)
  end

  def valid_device?(ch = channel(chain_id: chain_id, fleet_contract: fleet)) do
    DiodeClient.Contracts.Fleet.device_allowlisted?(chain_id, fleet, device_address(ch))
  end

  def valid_params?(channel(params: [])), do: true
  def valid_params?(_), do: false

  def valid_type?(channel(type: "mailbox")), do: true
  def valid_type?(channel(type: "broadcast")), do: true
  def valid_type?(_), do: false

  def device_address(rec = channel(signature: signature)) do
    Secp256k1.recover!(signature, message(rec), :kec)
    |> Wallet.from_pubkey()
    |> Wallet.address!()
  end

  defp message(
         channel(
           chain_id: chain_id,
           block_number: num,
           server_id: id,
           fleet_contract: fleet,
           type: type,
           name: name,
           params: params
         )
       ) do
    params = Rlp.encode!(params) |> Hash.sha3_256()

    hash =
      DiodeClient.shell_for_chain_id(chain_id).get_block_header(num) |> DiodeClient.Block.hash()

    ["channel", id, hash, fleet, type, name, params]
    |> Enum.map(&ABI.encode("bytes32", &1))
    |> :erlang.iolist_to_binary()
  end

  def sign(ch = channel(), private) do
    channel(ch, signature: Secp256k1.sign(private, message(ch), :kec))
  end

  def chain_id(channel(chain_id: chain_id)), do: chain_id
  @impl true
  def block_number(channel(block_number: block_number)), do: block_number
  def server_id(channel(server_id: server_id)), do: server_id
  def fleet_contract(channel(fleet_contract: fleet_contract)), do: fleet_contract
  def type(channel(type: type)), do: type
  def name(channel(name: name)), do: name
  def params(channel(params: params)), do: params
  def signature(channel(signature: signature)), do: signature
end
