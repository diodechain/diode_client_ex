defmodule DiodeClient.BitMessage do
  @moduledoc """
    BitMessage implementation used for Diode P2P cold messages.

    Our storage is a bit more compact than the original BitMessage spec at:
    https://wiki.bitmessage.org/index.php/Encryption

    1. We're skipping "Curve Type" because we always use secp256k1
    2. We always use the compact public key representation instead of full X and Y
  """
  alias DiodeClient.{BitMessage, Wallet}
  defstruct [:iv, :pubkey, :cipher_text, :mac]
  @padding 16

  def encrypt(message, to_pubkey_k) do
    iv = :crypto.strong_rand_bytes(16)
    tmp_key_r = Wallet.new()
    public_p = point_multiply(Wallet.pubkey!(to_pubkey_k), Wallet.privkey!(tmp_key_r))

    <<4, x::binary-size(32), _y::binary-size(32)>> = public_p
    <<key_e::binary-size(32), key_m::binary-size(32)>> = :crypto.hash(:sha512, x)

    message = pkcs7_pad(message, @padding)
    state = :crypto.crypto_init(:aes_256_cbc, key_e, iv, true)
    cipher_text = :crypto.crypto_update(state, message)
    hmac = :crypto.mac(:hmac, :sha512, key_m, iv <> Wallet.pubkey!(tmp_key_r) <> cipher_text)

    %BitMessage{iv: iv, pubkey: Wallet.pubkey!(tmp_key_r), cipher_text: cipher_text, mac: hmac}
  end

  def decrypt(
        %BitMessage{iv: iv, pubkey: pubkey_r, cipher_text: cipher_text, mac: hmac},
        to_privkey_k
      ) do
    public_p = point_multiply(pubkey_r, Wallet.privkey!(to_privkey_k))
    <<4, x::binary-size(32), _y::binary-size(32)>> = public_p
    <<key_e::binary-size(32), key_m::binary-size(32)>> = :crypto.hash(:sha512, x)

    case :crypto.mac(:hmac, :sha512, key_m, iv <> pubkey_r <> cipher_text) do
      ^hmac ->
        state = :crypto.crypto_init(:aes_256_cbc, key_e, iv, false)
        :crypto.crypto_update(state, cipher_text)

      _other ->
        {:error, :hmac_mismatch}
    end
  end

  defp pkcs7_pad(message, pad_length) do
    rem = rem(byte_size(message), pad_length)

    if rem != 0 do
      add = pad_length - rem
      message <> String.duplicate(<<add>>, add)
    else
      message
    end
  end

  def point_multiply(point, scalar) do
    {:ok, key} = :libsecp256k1.ec_pubkey_tweak_mul(point, scalar)
    {:ok, public} = :libsecp256k1.ec_pubkey_decompress(key)
    public
  end
end