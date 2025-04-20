defmodule DiodeClient.Contracts.OasisSapphire do
  @moduledoc """
    Oasis Sapphire Query Call Signing
    https://github.com/oasisprotocol/sapphire-contracts/blob/main/contracts/CallPermit.sol
  """
  alias DiodeClient.Base16
  alias DiodeClient.{EIP712}

  @default_gas_limit 30_000_000
  @default_gas_price 1_000_000_000
  @default_chain_id 23294
  @default_block_range 15

  defmodule TransportCipher do
    defstruct [
      :epoch,
      :peer_pubkey,
      :epheremal_pubkey,
      :epheremal_privkey,
      :shared_secret,
      :deoxys
    ]

    def new({peer_pubkey, epoch}) do
      # {epheremal_privkey, epheremal_pubkey} = Curve25519.generate_key_pair()
      # sk private key 0xa91df693eb664b5e2d56d3d979fee99ba3507f0a24e26e2a4a485b12d2fa148b
      # sk public key 0x774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c50
      epheremal_privkey =
        Base16.decode("0xa91df693eb664b5e2d56d3d979fee99ba3507f0a24e26e2a4a485b12d2fa148b")

      epheremal_pubkey =
        Base16.decode("0x774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c50")

      key = "MRAE_Box_Deoxys-II-256-128"
      msg = Curve25519.derive_shared_secret(epheremal_privkey, peer_pubkey)
      IO.inspect(DiodeClient.Base16.encode(msg), label: "msg")
      shared_secret = :hmac.hmac512_256(key, msg)

      IO.inspect(DiodeClient.Base16.encode(shared_secret), label: "shared_secret")
      IO.inspect(DiodeClient.Base16.encode(epheremal_privkey), label: "epheremal_privkey")
      IO.inspect(DiodeClient.Base16.encode(peer_pubkey), label: "peer_pubkey")

      %__MODULE__{
        epoch: epoch,
        peer_pubkey: peer_pubkey,
        epheremal_pubkey: epheremal_pubkey,
        epheremal_privkey: epheremal_privkey,
        shared_secret: shared_secret,
        deoxys: DeoxysII.new(shared_secret)
      }
    end
  end

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

    leash = %{
      "nonce" => nonce,
      "block_number" => block_number - 1,
      "block_hash" => cbor_bytes(block_hash),
      "block_range" => @default_block_range
    }

    msg_data = %{
      "from" => opts[:from],
      "to" => opts[:to],
      "value" => opts[:value] || 0,
      "gasLimit" => opts[:gas] || @default_gas_limit,
      "gasPrice" => opts[:gas_price] || @default_gas_price,
      "data" => data_bytes,
      "leash" => %{
        "nonce" => leash["nonce"],
        "blockNumber" => leash["block_number"],
        "blockHash" => leash["block_hash"].value,
        "blockRange" => leash["block_range"]
      }
    }

    full_message = %{
      "types" => msg_types,
      "primaryType" => "Call",
      "domain" => domain_data,
      "message" => msg_data
    }

    # sign the message with the private key:
    signature = EIP712.sign_typed_data(account_wallet, full_message)
    IO.inspect(full_message, label: "full_message")

    data_pack =
      %{
        "data" => make_envelope(data_bytes),
        "leash" => leash,
        "signature" => cbor_bytes(signature)
      }
      |> CBOR.encode()

    %{data_pack: data_pack, msg: msg_data}
  end

  def oasis_callDataPublicKey() do
    rpc = "https://sapphire.oasis.io"
    {json, 0} = System.cmd("cast", ["rpc", "oasis_callDataPublicKey", "--rpc-url", rpc])
    json = Jason.decode!(json)
    key = Base16.decode(json["key"])
    _epoch = json["epoch"]
    epoch = 40609
    {key, epoch}
  end

  defp encrypt_calldata(cipher, calldata) do
    # nonce = DeoxysII.random_nonce()
    nonce = <<244, 7, 0, 149, 137, 156, 150, 196, 231, 103, 211, 41, 245, 38, 180>>
    plaintext = CBOR.encode(%{"body" => cbor_bytes(calldata)})
    ciphertext = DeoxysII.encrypt(cipher.deoxys, nonce, nil, plaintext)
    IO.inspect({ciphertext, plaintext}, label: "ciphertext/plaintext")
    {ciphertext, nonce}
  end

  def make_envelope(plaintext) do
    {pubkey, epoch} = oasis_callDataPublicKey()
    cipher = TransportCipher.new({pubkey, epoch})
    {ciphertext, nonce} = encrypt_calldata(cipher, plaintext)

    %{
      "body" => %{
        "pk" => cbor_bytes(cipher.epheremal_pubkey),
        "data" => cbor_bytes(ciphertext),
        "nonce" => nonce,
        "epoch" => epoch
      },
      "format" => 1
    }
  end

  defp cbor_bytes(data) do
    %CBOR.Tag{tag: :bytes, value: data}
  end
end
