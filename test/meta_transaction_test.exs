defmodule MetaTransactionTest do
  use ExUnit.Case

  alias DiodeClient.{Secp256k1, Wallet, MetaTransaction, Contracts.CallPermit, ABI, Base16}

  test "meta transaction creation and signature recovery" do
    # Generate a wallet for testing
    {_pub, priv} = Secp256k1.generate()
    wallet = Wallet.from_privkey(priv)
    from_address = Wallet.address!(wallet)

    # Create meta transaction parameters
    to_address = Base16.decode("0x000000000000000000000000000000000000dead")
    value = 0
    call_data = ABI.encode_call("testFunction", ["uint256"], [123])
    gaslimit = 100_000
    deadline = System.os_time(:second) + 3600
    nonce = 1
    # Moonbeam chain ID
    chain_id = 1284

    # Create and sign the meta transaction
    meta_tx =
      MetaTransaction.sign(
        %MetaTransaction{
          from: from_address,
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

    # Extract the signature components
    {v, r, s} = meta_tx.signature

    # Create the dispatch call that would be sent to the contract
    dispatch_call =
      CallPermit.dispatch(
        from_address,
        to_address,
        value,
        call_data,
        gaslimit,
        deadline,
        {v, r, s}
      )

    dispatch = CallPermit.decode_dispatch(dispatch_call)

    assert dispatch.from == from_address
    assert dispatch.to == to_address
    assert dispatch.value == value
    assert dispatch.data == call_data
    assert dispatch.gaslimit == gaslimit
    assert dispatch.deadline == deadline

    # Recreate the message that was signed
    recreated_message =
      CallPermit.call_permit(
        chain_id,
        dispatch.from,
        dispatch.to,
        dispatch.value,
        dispatch.data,
        dispatch.gaslimit,
        dispatch.deadline,
        nonce
      )

    message =
      CallPermit.call_permit(
        chain_id,
        from_address,
        to_address,
        value,
        call_data,
        gaslimit,
        deadline,
        nonce
      )

    assert recreated_message == message

    # Recover the signer's public key from the signature
    signature = <<v - 27, r::big-unsigned-size(256), s::big-unsigned-size(256)>>
    recreated_signature = Secp256k1.rlp_to_bitcoin(<<dispatch.v>>, dispatch.r, dispatch.s)
    assert signature == recreated_signature
    {:ok, recovered_pubkey} = Secp256k1.recover(signature, message, :none)

    # Convert the recovered public key to an address
    recovered_address = Wallet.from_pubkey(recovered_pubkey) |> Wallet.address!()

    # Verify the recovered address matches the original signer
    assert recovered_address == from_address

    # Verify the dispatch call is properly formatted
    assert is_binary(dispatch_call)
    # Should at least have function selector
    assert byte_size(dispatch_call) > 4
  end
end
