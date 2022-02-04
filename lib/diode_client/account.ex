defmodule DiodeClient.Account do
  alias DiodeClient.{Account, Hash, Rlp}
  defstruct [:nonce, :balance, :storage_root, :code_hash]

  def to_rlp(%Account{nonce: nonce, balance: balance, storage_root: root, code_hash: code_hash}) do
    [
      nonce,
      balance,
      root,
      code_hash
    ]
  end

  def hash(%Account{} = account) do
    Hash.sha3_256(Rlp.encode!(to_rlp(account)))
  end
end
