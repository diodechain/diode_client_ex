defmodule DiodeClient.MetaTransaction do
  @moduledoc """
  Meta transaction to submit pre-signed transactions to the blockchain.
  """
  alias DiodeClient.Contracts.CallPermit
  alias DiodeClient.{Hash, MetaTransaction, Secp256k1, Shell, Wallet}
  defstruct [:from, :to, :value, :call, :gaslimit, :deadline, :nonce, :signature, :chain_id]

  @moonbeam [Shell.MoonbaseAlpha.chain_id(), Shell.Moonbeam.chain_id()]

  def sign(mtx = %MetaTransaction{}, wallet) do
    [v, r, s] =
      Wallet.privkey!(wallet)
      |> Secp256k1.sign(digest(mtx), :none)
      |> Secp256k1.bitcoin_to_rlp()

    %MetaTransaction{mtx | signature: {v, r, s}}
  end

  def digest(%MetaTransaction{
        from: from,
        to: to,
        value: value,
        call: data,
        gaslimit: gaslimit,
        deadline: deadline,
        nonce: nonce,
        chain_id: chain_id
      })
      when chain_id in @moonbeam do
    CallPermit.call_permit(chain_id, from, to, value, data, gaslimit, deadline, nonce)
  end

  def digest(
        mtx = %MetaTransaction{
          to: dst,
          call: data,
          deadline: deadline,
          nonce: nonce
        }
      ) do
    struct_hash =
      [
        Hash.keccak_256("Transaction(uint256 nonce,uint256 deadline,address dst,bytes data)"),
        nonce,
        deadline,
        dst,
        Hash.keccak_256(data)
      ]
      |> hash_encode()

    Hash.keccak_256("\x19\x01" <> domain_separator(mtx) <> struct_hash)
  end

  # in this form "from" is the address of the DriveMember contract
  defp domain_separator(%MetaTransaction{from: address, chain_id: chain_id}) do
    [
      0x8B73C3C69BB8FE3D512ECC4CF759CC79239F7B179B0FFACAA9A75D522B39400F,
      Hash.keccak_256("DriveMember"),
      Hash.keccak_256("116"),
      <<chain_id::unsigned-integer-size(256)>>,
      address
    ]
    |> hash_encode()
  end

  defp hash_encode(list) do
    Enum.map_join(list, &Hash.to_bytes32/1)
    |> Hash.keccak_256()
  end

  def to_rlp(%MetaTransaction{
        from: from,
        to: to,
        value: value,
        call: data,
        gaslimit: gaslimit,
        deadline: deadline,
        # nonce: nonce,
        signature: {v, r, s},
        chain_id: chain_id
      })
      when chain_id in @moonbeam do
    [from, to, value, data, gaslimit, deadline, v, r, s]
  end

  def to_rlp(%MetaTransaction{
        from: from,
        to: dst,
        call: data,
        deadline: deadline,
        nonce: nonce,
        signature: {v, r, s}
      }) do
    ["dm1", from, nonce, deadline, dst, data, v, r, s]
  end

  def simulate(
        %MetaTransaction{
          from: from,
          to: to,
          call: data,
          deadline: deadline,
          nonce: nonce,
          signature: {v, r, s}
        },
        shell
      ) do
    shell.call(
      from,
      "SubmitMetaTransaction",
      ["uint256", "uint256", "address", "bytes", "uint8", "bytes32", "bytes32"],
      [nonce, deadline, to, data, v, r, s]
    )
  end
end
