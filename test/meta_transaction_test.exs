defmodule MetaTransactionTest do
  use ExUnit.Case

  alias DiodeClient.{ABI, Base16, MetaTransaction, Secp256k1, Shell, Wallet}

  test "meta transaction creation, signature recovery, and dm1 RLP encoding on Base" do
    wallet = DiodeClient.ensure_wallet()
    signer_address = Wallet.address!(wallet)
    identity_address = Base16.decode("0x0000000000000000000000000000000000001234")

    to_address = Base16.decode("0x000000000000000000000000000000000000dead")
    value = 0
    call_data = ABI.encode_call("testFunction", ["uint256"], [123])
    gaslimit = 100_000
    deadline = System.os_time(:second) + 3600
    nonce = 1
    chain_id = Shell.Base.chain_id()

    meta_tx =
      MetaTransaction.sign(
        %MetaTransaction{
          from: identity_address,
          to: to_address,
          value: value,
          call: call_data,
          gaslimit: gaslimit,
          deadline: deadline,
          nonce: nonce,
          chain_id: chain_id
        },
        wallet
      )

    {v, r, s} = meta_tx.signature
    digest = MetaTransaction.digest(meta_tx)

    signature = <<v - 27, r::big-unsigned-size(256), s::big-unsigned-size(256)>>
    {:ok, recovered_pubkey} = Secp256k1.recover(signature, digest, :none)
    recovered_address = Wallet.from_pubkey(recovered_pubkey) |> Wallet.address!()

    assert recovered_address == signer_address

    assert [
             "dm1",
             ^signer_address,
             ^identity_address,
             ^nonce,
             ^deadline,
             ^to_address,
             ^call_data,
             ^v,
             ^r,
             ^s
           ] = MetaTransaction.to_rlp(meta_tx)
  end
end
