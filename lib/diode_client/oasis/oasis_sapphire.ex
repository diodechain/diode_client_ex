defmodule DiodeClient.OasisSapphire do
  @moduledoc """
    Oasis Sapphire Query Call Signing
    https://github.com/oasisprotocol/sapphire-contracts/blob/main/contracts/CallPermit.sol
  """
  alias DiodeClient.{Base16, EIP712, TestValues}
  alias DiodeClient.Oasis.{OrderedMap, TransportCipher}

  @default_gas_limit 30_000_000
  @default_gas_price 100_000_000_000
  @default_chain_id 23_294
  @default_block_range 15

  def new_signed_call_data_pack(
        account_wallet,
        data_bytes,
        opts \\ []
      ) do
    domain_data = %{
      "name" => "oasis-runtime-sdk/evm: signed query",
      "version" => "1.0.0",
      "chainId" => opts[:chain_id] || @default_chain_id
      # "verifyingContract": "",
      # "salt": "",
    }

    msg_types = %{
      "EIP712Domain" => [
        {"name", "string"},
        {"version", "string"},
        {"chainId", "uint256"}
      ],
      "Call" => [
        {"from", "address"},
        {"to", "address"},
        {"gasLimit", "uint64"},
        {"gasPrice", "uint256"},
        {"value", "uint256"},
        {"data", "bytes"},
        {"leash", "Leash"}
      ],
      "Leash" => [
        {"nonce", "uint64"},
        {"blockNumber", "uint64"},
        {"blockHash", "bytes32"},
        {"blockRange", "uint64"}
      ]
    }

    nonce = opts[:nonce] || raise "nonce is required"
    block_number = opts[:block_number] || raise "block_number is required"
    block_hash = opts[:block_hash] || raise "block_hash is required"
    block_hash = String.replace_prefix(block_hash, "0x", "")
    block_number = block_number - 1

    leash =
      [
        nonce: nonce,
        block_hash: cbor_bytes(block_hash),
        block_range: @default_block_range,
        block_number: block_number
      ]
      |> OrderedMap.new()

    msg_data = %{
      "from" => opts[:from],
      "to" => opts[:to],
      "value" => opts[:value] || 0,
      "gasLimit" => opts[:gas] || @default_gas_limit,
      "gasPrice" => opts[:gas_price] || @default_gas_price,
      "data" => data_bytes,
      "leash" => %{
        "nonce" => nonce,
        "blockNumber" => block_number,
        "blockHash" => block_hash,
        "blockRange" => @default_block_range
      }
    }

    full_message = %{
      "types" => msg_types,
      "primaryType" => "Call",
      "domain" => domain_data,
      "message" => msg_data
    }

    # sign the message with the private key:
    <<rec, signature::binary>> = EIP712.sign_typed_data(account_wallet, full_message)
    signature = <<signature::binary, rec + 27>>

    {pubkey, epoch} = oasis_call_data_public_key()
    cipher = TransportCipher.new({pubkey, epoch})

    data_pack =
      [
        data: make_envelope(cipher, data_bytes),
        leash: leash,
        signature: cbor_bytes(signature)
      ]
      |> OrderedMap.new()
      |> CBOR.encode()

    %{data_pack: data_pack, msg: msg_data, cipher: cipher}
  end

  def decrypt_data_pack_response(data_pack, response) do
    {:ok,
     %{
       "ok" => %{
         "data" => %CBOR.Tag{value: data},
         "nonce" => %CBOR.Tag{value: nonce}
       }
     }, ""} = CBOR.decode(response)

    DeoxysII.decrypt(data_pack.cipher.deoxys, nonce, nil, data)
  end

  def oasis_call_data_public_key() do
    epoch =
      TestValues.get(:oasis_epoch) ||
        DiodeClient.Shell.OasisSapphire.oasis_call_data_public_key()["epoch"]

    key =
      TestValues.get(:oasis_peer_pubkey) ||
        Base16.decode(DiodeClient.Shell.OasisSapphire.oasis_call_data_public_key()["key"])

    {key, epoch}
  end

  defp encrypt_calldata(cipher, calldata) do
    nonce = DiodeClient.TestValues.get(:oasis_nonce) || DeoxysII.random_nonce()
    plaintext = CBOR.encode(%{"body" => cbor_bytes(calldata)})
    ciphertext = DeoxysII.encrypt(cipher.deoxys, nonce, nil, plaintext)
    {ciphertext, nonce}
  end

  def make_envelope(cipher, plaintext) do
    {ciphertext, nonce} = encrypt_calldata(cipher, plaintext)

    # Using keylists over maps to ensure order of elements (canonical cbor encoding)
    [
      body:
        [
          pk: cbor_bytes(cipher.epheremal_pubkey),
          data: cbor_bytes(ciphertext),
          epoch: cipher.epoch,
          nonce: cbor_bytes(nonce)
        ]
        |> OrderedMap.new(),
      format: 1
    ]
    |> OrderedMap.new()
  end

  defp cbor_bytes(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end
end
