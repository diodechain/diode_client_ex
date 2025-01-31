defmodule BitMessageTest do
  use ExUnit.Case
  alias DiodeClient.{BitMessage, Base16, Wallet, Rlp}

  test "point multiply equivalence" do
    receiver = Wallet.new()
    tmp_key = Wallet.new()

    p1 = BitMessage.point_multiply(Wallet.pubkey!(receiver), Wallet.privkey!(tmp_key))
    p2 = BitMessage.point_multiply(Wallet.pubkey!(tmp_key), Wallet.privkey!(receiver))

    assert p1 == p2
  end

  test "point multiply reference" do
    receiver =
      Wallet.from_privkey(
        Base16.decode("0x444ec51a39df96db80f41bc368d401e6956fa46ec84b76adcd16fe6d895643bb")
      )

    tmp_key =
      Wallet.from_privkey(
        Base16.decode("0x4572945cedb6bb48b89fab35e6cd80ed0c0efd15e6531d124aa1fb79b7b9ddf1")
      )

    p1 = BitMessage.point_multiply(Wallet.pubkey!(receiver), Wallet.privkey!(tmp_key))
    p2 = BitMessage.point_multiply(Wallet.pubkey!(tmp_key), Wallet.privkey!(receiver))

    assert p1 == p2

    assert Base16.encode(p1) ==
             "0x04d4382056d3087ed26a7c4d10d28f67fad021bbf5c469b47f9f40cedffd980080d4d9bfd94a4434f794b076f478b19d0fb0696b99d9156f5aef24be5521b90f8b"
  end

  test "point multiply reference 2" do
    receiver =
      Wallet.from_privkey(
        Base16.decode("0xe160226e0622f4f318fd483a90bfb3290e6553bf6f5445a54c2b78c28410b322")
      )

    tmp_key =
      Wallet.from_pubkey(
        Base16.decode(
          "0x046127cedd9d7c238ca411f8e3166de42dad124c9bae80b3554a93c6151e08f9d38a8f98940939a21791b7869a306f7d9e47349e7453604efe428c84b642b112a3"
        )
      )

    p = BitMessage.point_multiply(Wallet.pubkey!(tmp_key), Wallet.privkey!(receiver))

    assert Base16.encode(p) ==
             "0x04f6325cac6e7649484e8fe73d599c5667f488098552894b8bb2c712045858877ef4cd849143cc8fbf605226c9cd55722b7de88de56ac8c0295225ee5fc1859ba8"
  end

  test "point multiply reference 3" do
    receiver =
      Wallet.from_privkey(
        Base16.decode("0x1160226e0622f4f318fd483a90bfb3290e6553bf6f5445a54c2b78c28410b322")
      )

    tmp_key =
      Wallet.from_pubkey(
        Base16.decode(
          "0x046127cedd9d7c238ca411f8e3166de42dad124c9bae80b3554a93c6151e08f9d38a8f98940939a21791b7869a306f7d9e47349e7453604efe428c84b642b112a3"
        )
      )

    p = BitMessage.point_multiply(Wallet.pubkey!(tmp_key), Wallet.privkey!(receiver))

    assert Base16.encode(p) ==
             "0x042df0dc576046a5cce0affa9e3229207d6e8916002061e06075e32d74fb764af9d6b22062bbb1e163d2d976376b2098b4fa52e9ac184623ccd53a5a660e7363e5"
  end

  test "reference decrypt" do
    blob =
      "0xf8d80290205eb068db804295e4c862914832ad7ba1036127cedd9d7c238ca411f8e3166de42dad124c9bae80b3554a93c6151e08f9d3b86006f2c466cb459dfcea7967b722fe16fbdf954a835747a194553c8a0b30c5248361ffca3e25138603eeba721e924634aed5acbc096deb58cad0e67dbb2c4dd500260ce0ccc0ee03ccd16cffe0bd0dcce607ce742907d16521f45c78edbd74f2a8b840e74d5597f3ee401eb572973e61e26f275ec7191484917e352afbc84677bec3ec59269f6c9a5113a18752a7c9eb213ea1ba1bfb03b50ba289f80d5aaa7e1865ab"
      |> Base16.decode()

    key = "0xe160226e0622f4f318fd483a90bfb3290e6553bf6f5445a54c2b78c28410b322" |> Base16.decode()
    {[<<2>>, iv, pubkey, cipher_text, hmac], ""} = DiodeClient.Rlp.decode(blob)
    bm = %BitMessage{iv: iv, pubkey: pubkey, cipher_text: cipher_text, mac: hmac}
    out = BitMessage.decrypt(bm, Wallet.from_privkey(key))
    {[<<1>>, message, _sig], _padding} = DiodeClient.Rlp.decode(out)
    json = Jason.decode!(message)
    assert is_binary(out)
    assert json == %{"some" => "event"}
  end

  test "encrypt & decrpyt" do
    receiver = Wallet.new()
    message = "This is a super secret message just for you"

    bm = BitMessage.encrypt(message, receiver)
    out = BitMessage.decrypt(bm, receiver)

    assert :binary.part(out, 0, byte_size(message)) == message
  end

  test "encode size" do
    message = "This is a super secret message just for you"
    bm = BitMessage.encrypt(message, Wallet.new(), :sha256)
    data = Rlp.encode!([bm.iv, bm.pubkey, bm.cipher_text, bm.mac])
    data_without_mac = Rlp.encode!([bm.iv, bm.pubkey, bm.cipher_text])

    assert byte_size(message) == 43
    assert byte_size(data) == 135
    assert byte_size(data_without_mac) == 102
    overhead = byte_size(data) - byte_size(message)
    assert overhead == 92

    # Typical udp limit is 1472 bytes
    message =
      "This is a super secret message just for you"
      |> String.duplicate(30)
      |> String.pad_trailing(1376)

    bm = BitMessage.encrypt(message, Wallet.new(), :sha256)
    data = Rlp.encode!([bm.iv, bm.pubkey, bm.cipher_text, bm.mac])
    data_without_mac = Rlp.encode!([bm.iv, bm.pubkey, bm.cipher_text])

    assert byte_size(message) == 1376
    assert byte_size(data) == 1466
    assert byte_size(data_without_mac) == 1433
    overhead = byte_size(data) - byte_size(message)
    assert overhead == 90
  end
end
