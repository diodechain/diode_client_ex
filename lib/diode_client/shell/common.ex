defmodule DiodeClient.Shell.Common do
  @moduledoc """
  Common functions for the shell implementations.
  """

  require Logger

  alias DiodeClient.{
    ABI,
    Base16,
    Connection,
    Shell,
    Transaction,
    MetaTransaction,
    Rlp,
    Wallet,
    IdentityRequest
  }

  def send_transaction(shell, tx = %IdentityRequest{}) do
    rlp = IdentityRequest.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(Shell.sticky_conn(), [shell.prefix() <> "sendmetatransaction", rlp]), tx}
  end

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
    gas = Map.get(opts, :gas, 0x15F900)
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

    tx =
      case Map.get(opts, :to) do
        # Contract creation
        nil -> %Transaction{tx | init: data}
        # Normal transaction
        to -> %Transaction{tx | to: to, data: data}
      end

    if Map.get(opts, :sign, true) do
      Transaction.sign(tx, Wallet.privkey!(wallet))
    else
      tx
    end
  end

  def call(shell, address, method, types, args, opts \\ []) do
    opts = Map.merge(Map.new(opts), %{to: address, sign: false})
    tx = create_transaction(shell, ABI.encode_call(method, types, args), opts)

    call_tx(shell, tx,
      block: Map.get(opts, :block, shell.peak()),
      result_types: Map.get(opts, :result_types)
    )
  end

  def call_tx(shell, transaction, opts \\ []) do
    block =
      case Keyword.get(opts, :block) do
        nil ->
          Base16.encode(shell.peak_number(), short: true)

        "latest" ->
          Base16.encode(shell.peak_number(), short: true)

        block when is_integer(block) ->
          Base16.encode(block, short: true)

        block when is_map(block) ->
          Base16.encode(DiodeClient.Block.number(block), short: true)
          # block -> block
      end

    params =
      [
        %{
          from: Base16.encode(Transaction.from(transaction) || DiodeClient.address()),
          to: Base16.encode(transaction.to),
          value: Base16.encode(transaction.value, short: true),
          data: Base16.encode(transaction.data),
          gas: Base16.encode(transaction.gasLimit, short: true),
          gasPrice: Base16.encode(transaction.gasPrice, short: true)
        },
        block
      ]
      |> Jason.encode!()

    cmd = [shell.prefix() <> "rpc", "eth_call", params]

    with [json] <- DiodeClient.Shell.cached_rpc(cmd) do
      case Jason.decode!(json) do
        %{"result" => result} ->
          Base16.decode(result)
          |> decode_result(Keyword.get(opts, :result_types))

        %{"error" => error} ->
          Logger.error("Error #{shell.prefix()}.eth_call: #{inspect(error)}")
          nil
      end
    end
  end

  def decode_result("", _types), do: :revert
  def decode_result(nil, _types), do: nil

  def decode_result(result, types) do
    case types do
      nil -> result
      types when is_list(types) -> DiodeClient.ABI.decode_args(types, result)
      type when is_binary(type) -> List.first(DiodeClient.ABI.decode_args([type], result))
    end
  end
end
