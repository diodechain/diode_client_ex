defmodule DiodeClient.MetaTransaction do
  @moduledoc """
  Meta transaction to submit pre-signed transactions to the blockchain.
  """
  alias DiodeClient.Contracts.CallPermit
  alias DiodeClient.{MetaTransaction, Secp256k1, Wallet}
  defstruct [:from, :to, :value, :call, :gaslimit, :deadline, :nonce, :signature, :chain_id]

  def sign(
        mtx = %MetaTransaction{
          from: from,
          to: to,
          value: value,
          call: data,
          gaslimit: gaslimit,
          deadline: deadline,
          nonce: nonce,
          chain_id: chain_id
        },
        wallet
      ) do
    signature = CallPermit.call_permit(chain_id, from, to, value, data, gaslimit, deadline, nonce)

    [v, r, s] =
      Wallet.privkey!(wallet)
      |> Secp256k1.sign(signature, :none)
      |> Secp256k1.bitcoin_to_rlp()

    %MetaTransaction{mtx | signature: {v, r, s}}
  end

  def to_rlp(%MetaTransaction{
        from: from,
        to: to,
        value: value,
        call: data,
        gaslimit: gaslimit,
        deadline: deadline,
        # nonce: nonce,
        signature: {v, r, s}
      }) do
    [from, to, value, data, gaslimit, deadline, v, r, s]
  end
end
