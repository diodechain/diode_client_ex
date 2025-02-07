defmodule DiodeClient.Shell.Common do
  @moduledoc """
  Common functions for the shell implementations.
  """

  alias DiodeClient.{Connection, Shell, Transaction, MetaTransaction, Rlp, Wallet}

  def send_transaction(shell, tx = %Transaction{}) do
    rlp = Transaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(Shell.sticky_conn(), [shell.prefix() <> "sendtransaction", rlp]), tx}
  end

  def send_transaction(shell, tx = %MetaTransaction{}) do
    rlp = MetaTransaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(Shell.sticky_conn(), [shell.prefix() <> "sendmetatransaction", rlp]), tx}
  end

  def create_transaction(shell, data, opts) do
    wallet = Map.get(opts, :wallet) || DiodeClient.ensure_wallet()
    from = Wallet.address!(wallet)
    gas = Map.get(opts, :gas, 0x15F90)
    gas_price = Map.get(opts, :gas_price, 0x3B9ACA00)
    value = Map.get(opts, :value, 0x0)
    nonce = Map.get_lazy(opts, :nonce, fn -> shell.get_account(from).nonce end)
    version = Map.get(opts, :version, 0)
    access_list = Map.get(opts, :access_list, [])
    max_priority_fee_per_gas = Map.get(opts, :max_priority_fee_per_gas, 0)

    tx = %Transaction{
      to: nil,
      nonce: nonce,
      gasPrice: gas_price,
      gasLimit: gas,
      value: value,
      chain_id: shell.chain_id(),
      version: version,
      access_list: access_list,
      max_priority_fee_per_gas: max_priority_fee_per_gas
    }

    case Map.get(opts, :to) do
      # Contract creation
      nil -> %Transaction{tx | init: data}
      # Normal transaction
      to -> %Transaction{tx | to: to, data: data}
    end
    |> Transaction.sign(Wallet.privkey!(wallet))
  end
end
