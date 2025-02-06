defmodule DiodeClient.Shell.Common do
  alias DiodeClient.{Connection, Shell, Transaction, MetaTransaction, Rlp}

  def send_transaction(shell, tx = %Transaction{}) do
    rlp = Transaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(Shell.sticky_conn(), [shell.prefix() <> "sendtransaction", rlp]), tx}
  end

  def send_transaction(shell, tx = %MetaTransaction{}) do
    rlp = MetaTransaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(Shell.sticky_conn(), [shell.prefix() <> "sendmetatransaction", rlp]), tx}
  end
end
