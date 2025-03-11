defmodule WalletTest do
  use ExUnit.Case
  alias DiodeClient.Secp256k1
  alias DiodeClient.Wallet

  test "sign and verify" do
    # Generate a full wallet with private key
    {pub, priv} = Secp256k1.generate()
    full_wallet = Wallet.from_privkey(priv)

    # Create pubkey-only wallet
    pubkey_wallet = Wallet.from_pubkey(pub)

    # Create address-only wallet
    address = Wallet.address!(full_wallet)
    address_wallet = Wallet.from_address(address)

    # Sign a test message with the full wallet
    msg = "test message"
    signature = Wallet.sign(full_wallet, msg)

    # Verify with different wallet types
    assert Wallet.verify(full_wallet, msg, signature)
    assert Wallet.verify(pubkey_wallet, msg, signature)
    assert Wallet.verify(address_wallet, msg, signature)

    # Verify fails with wrong message
    refute Wallet.verify(full_wallet, "wrong message", signature)
    refute Wallet.verify(pubkey_wallet, "wrong message", signature)
    refute Wallet.verify(address_wallet, "wrong message", signature)

    # Generate another wallet to test invalid signatures
    {_other_pub, other_priv} = Secp256k1.generate()
    other_wallet = Wallet.from_privkey(other_priv)
    other_sig = Wallet.sign(other_wallet, msg)

    # Verify fails with wrong signature
    refute Wallet.verify(full_wallet, msg, other_sig)
    refute Wallet.verify(pubkey_wallet, msg, other_sig)
    refute Wallet.verify(address_wallet, msg, other_sig)
  end
end
