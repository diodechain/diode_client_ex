defmodule DiodeClient.Account do
  @moduledoc false
  alias DiodeClient.{Account, Hash, Rlp}
  defstruct [:nonce, :balance, :storage_root, :code_hash]

  @type t :: %Account{
          nonce: integer() | nil,
          balance: integer() | nil,
          storage_root: binary() | nil,
          code_hash: binary() | nil
        }

  def to_rlp(%Account{nonce: nonce, balance: balance, storage_root: root, code_hash: code_hash}) do
    [
      nonce,
      balance,
      root,
      code_hash
    ]
  end

  def hash(account = %Account{}) do
    Hash.sha3_256(Rlp.encode!(to_rlp(account)))
  end
end
