defmodule DiodeClient.Shell.MoonbaseAlpha do
  @moduledoc """
  DiodeClient.Shell is the interface to the blockchain state. It allows
  fetching accounts and block header information. Data fetched is by
  default checked against a merkle proof.

  # Example fetching smart contract state from an address

  ```
  me = DiodeClient.address()
  DiodeClient.Shell.get_account(me)
  ```

  """
  alias DiodeClient.{
    ABI,
    Account,
    Connection,
    Hash,
    MetaTransaction,
    Rlp,
    Rlpx,
    Shell,
    Transaction,
    Wallet
  }

  use DiodeClient.Log

  def chain_id(), do: 1287
  def prefix(), do: "m1:"
  @gas_limit 10_000_000

  def blockexplorer_url(opts \\ []) do
    cond do
      opts[:address] != nil ->
        "https://moonbase.moonscan.io/address/#{maybe_hex(opts[:address])}"

      opts[:tx] != nil ->
        "https://moonbase.moonscan.io/tx/#{maybe_hex(opts[:tx])}"

      true ->
        "https://moonbase.moonscan.io/"
    end
  end

  defp maybe_hex(x = "0x" <> _), do: x
  defp maybe_hex(x), do: DiodeClient.Base16.encode(x, false)

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    create_transaction(address, function_name, types, values, opts)
    |> send_transaction()
  end

  def send_transaction(tx = %Transaction{}) do
    rlp = Transaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(conn(), ["m1:sendtransaction", rlp]), tx}
  end

  def send_transaction(tx = %MetaTransaction{}) do
    rlp = MetaTransaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(conn(), ["m1:sendmetatransaction", rlp]), tx}
  end

  def create_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    opts =
      opts
      |> Keyword.put_new(:gas, @gas_limit)
      |> Keyword.put_new(:gas_price, 0)
      |> Keyword.put(:to, Hash.to_address(address))
      |> Map.new()

    # https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html
    callcode = ABI.encode_call(function_name, types, values)
    create_transaction(callcode, opts)
  end

  @deadline 1_800_000_000
  def create_meta_transaction(address, function_name, types, values, nonce, opts \\ [])
      when is_list(types) and is_list(values) do
    # https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html
    callcode = ABI.encode_call(function_name, types, values)
    wallet = DiodeClient.ensure_wallet()
    from = Wallet.address!(wallet)

    gaslimit = Keyword.get(opts, :gas, @gas_limit)
    deadline = Keyword.get(opts, :deadline, @deadline)
    value = Keyword.get(opts, :value, 0)

    MetaTransaction.sign(
      %MetaTransaction{
        from: from,
        to: address,
        call: callcode,
        gaslimit: gaslimit,
        deadline: deadline,
        value: value,
        nonce: nonce,
        chain_id: chain_id()
      },
      wallet
    )
  end

  defdelegate get_object(key), to: Shell
  defdelegate get_node(key), to: Shell

  def get_block_header(block_index) do
    cached_rpc(["m1:getblockheader", block_index])
  end

  def get_meta_nonce(address, peak \\ peak()) do
    address = Hash.to_address(address)
    peak_index = Rlpx.bin2uint(peak["number"])
    [num] = cached_rpc(["m1:getmetanonce", peak_index, address])
    Rlpx.bin2uint(num)
  end

  def get_account(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)
    [acc] = cached_rpc(["m1:getaccount", peak_index, address])
    acc = Rlpx.list2map(acc)

    %Account{
      nonce: Rlpx.bin2uint(acc["nonce"]),
      balance: Rlpx.bin2uint(acc["balance"]),
      storage_root: Rlpx.bin2addr(acc["storage_root"]),
      code_hash: acc["code"]
    }
  end

  def get_account_root(address, peak \\ peak()) do
    address = Hash.to_address(address)
    %Account{storage_root: root} = get_account(address, peak)
    root
  end

  def get_account_value(address, key = <<_::256>>, peak \\ peak())
      when is_binary(address) or is_integer(address) do
    hd(get_account_values(address, [key], peak))
  end

  def get_account_values(address, keys, peak \\ peak())
      when is_list(keys) and (is_binary(address) or is_integer(address)) do
    peak_index = peak_number(peak)
    address = Hash.to_address(address)
    values = cached_rpc(["m1:getaccountvalues", peak_index, address | keys])

    case values do
      [:error, message] ->
        log(
          "getaccountvalues #{inspect({peak_index, address, keys})} produced error #{inspect(message)}"
        )

        raise "getaccountvalues #{inspect({peak_index, address, keys})} produced error #{inspect(message)}"

      [values] ->
        # Diode L1 can differentiate between unset (empty) values and all zero
        # values -- this is not the case for moonbeam. So to make signup name checks
        # succeed here we're checking that the value is not all zero.

        Enum.map(values, fn value ->
          if value == <<0::unsigned-size(256)>> do
            :undefined
          else
            value
          end
        end)
    end
  end

  def peak() do
    [block] = cached_rpc(["m1:getblockheader", peak_number()])
    Rlpx.list2map(block)
  end

  def peak_number() do
    Rlpx.bin2uint(hd(rpc(["m1:getblockpeak"])))
  end

  def peak_number(peak) do
    Rlpx.bin2uint(peak["number"])
  end

  defdelegate cached_rpc(args), to: DiodeClient.Shell
  defdelegate rpc(args), to: DiodeClient.Shell

  defp conn() do
    DiodeClient.default_conn()
  end

  defp create_transaction(data, opts) do
    wallet = DiodeClient.ensure_wallet()

    from = Wallet.address!(wallet)
    gas = Map.get(opts, :gas, 0x15F90)
    gas_price = Map.get(opts, :gas_price, 0x3B9ACA00)
    value = Map.get(opts, :value, 0x0)
    nonce = Map.get_lazy(opts, :nonce, fn -> get_account(from).nonce end)

    tx = %Transaction{
      to: nil,
      nonce: nonce,
      gasPrice: gas_price,
      gasLimit: gas,
      value: value,
      chain_id: chain_id()
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
