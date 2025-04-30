defmodule OasisTest do
  use ExUnit.Case
  alias DiodeClient.Base16
  alias DiodeClient.Wallet
  alias DiodeClient.TestValues

  test "it works" do
    TestValues.put(
      :oasis_nonce,
      <<244, 7, 0, 149, 137, 156, 150, 196, 231, 103, 211, 41, 245, 38, 180>>
    )

    TestValues.put(
      :oasis_peer_pubkey,
      Base16.decode("0x4e0c4c5a0399453a9d3e858290dcd2483ef2b0afc9d87ba71aed140e96f27b5f")
    )

    TestValues.put(
      :oasis_epheremal_key,
      {Base16.decode("0xa91df693eb664b5e2d56d3d979fee99ba3507f0a24e26e2a4a485b12d2fa148b"),
       Base16.decode("0x774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c50")}
    )

    TestValues.put(:oasis_epoch, 40_662)

    contract = Base16.decode("0xBc07eF1b0B79e2D41D82CD940C1e79DCf3F1A0F9")
    client_wallet = Wallet.from_privkey(Base16.decode("0x" <> String.duplicate("1", 64)))
    client = Wallet.address!(client_wallet)

    nonce = 0
    block_number = 8_694_491

    block_hash =
      DiodeClient.Base16.decode(
        "0x4a90b69a09be2bc87c7b6371f6c78be8aeb42d001341ffa98ac993811527ae60"
      )

    opts = [
      gasLimit: 10_000_000,
      to: contract,
      nonce: nonce,
      block_number: block_number,
      block_hash: block_hash,
      from: client
    ]

    data = DiodeClient.ABI.encode_call("Version")
    call = DiodeClient.OasisSapphire.new_signed_call_data_pack(client_wallet, data, opts)
    call_hex = DiodeClient.Base16.encode(call.data_pack)

    reference_out =
      "0xa36464617461a264626f6479a462706b5820774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c506464617461581b344d40cf5152fa41f385b1f938f74c6d3bf4936e4435757ff762af6565706f6368199ed6656e6f6e63654ff4070095899c96c4e767d329f526b466666f726d617401656c65617368a4656e6f6e6365006a626c6f636b5f6861736858204a90b69a09be2bc87c7b6371f6c78be8aeb42d001341ffa98ac993811527ae606b626c6f636b5f72616e67650f6c626c6f636b5f6e756d6265721a0084aada697369676e617475726558414a45b184c2feaecde6246feabae2e9843d8c7b1ac448af3223c15b6d4b9e768619089e1178ac87f13a75f1db74ad266c12ab8656639741e93c16f16cff6ded461c"

    assert call_hex == reference_out
  end
end
