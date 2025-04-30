defmodule DiodeClient.Oasis.TransportCipher do
  @moduledoc """
  Transport Cipher for Oasis Sapphire
  """
  alias DiodeClient.TestValues

  defstruct [
    :epoch,
    :peer_pubkey,
    :epheremal_pubkey,
    :epheremal_privkey,
    :shared_secret,
    :deoxys
  ]

  def new({peer_pubkey, epoch}) do
    {epheremal_privkey, epheremal_pubkey} =
      TestValues.get(:oasis_epheremal_key) || Curve25519.generate_key_pair()

    key = "MRAE_Box_Deoxys-II-256-128"
    msg = Curve25519.derive_shared_secret(epheremal_privkey, peer_pubkey)
    shared_secret = :hmac.hmac512_256(key, msg)

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
