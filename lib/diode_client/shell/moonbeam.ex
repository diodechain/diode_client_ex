defmodule DiodeClient.Shell.Moonbeam do
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
    Hash,
    MetaTransaction,
    Rlpx,
    Shell,
    Wallet
  }

  require Logger

  def chain_id(), do: 1284
  def prefix(), do: "glmr:"
  @gas_limit 10_000_000

  def blockexplorer_url(opts \\ []) do
    cond do
      opts[:address] != nil ->
        "https://moonbeam.moonscan.io/address/#{maybe_hex(opts[:address])}"

      opts[:tx] != nil ->
        "https://moonbeam.moonscan.io/tx/#{maybe_hex(opts[:tx])}"

      true ->
        "https://moonbeam.moonscan.io/"
    end
  end

  defp maybe_hex(x = "0x" <> _), do: x
  defp maybe_hex(x), do: DiodeClient.Base16.encode(x, false)

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    create_transaction(address, function_name, types, values, opts)
    |> send_transaction()
  end

  def send_transaction(tx), do: Shell.Common.send_transaction(__MODULE__, tx)

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
    Shell.Common.create_transaction(__MODULE__, callcode, opts)
  end

  def create_meta_transaction(address, function_name, types, values, nonce, opts \\ [])
      when is_list(types) and is_list(values) do
    # https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html
    callcode = ABI.encode_call(function_name, types, values)
    wallet = DiodeClient.ensure_wallet()
    from = Wallet.address!(wallet)

    gaslimit = Keyword.get(opts, :gas, @gas_limit)
    deadline = Keyword.get(opts, :deadline, System.os_time(:second) + 3600)
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
    case cached_rpc([prefix() <> "getblockheader", block_index]) do
      [block] -> Rlpx.list2map(block)
    end
  end

  def get_meta_nonce(address, peak \\ peak()) do
    address = Hash.to_address(address)
    peak_index = Rlpx.bin2uint(peak["number"])
    [num] = cached_rpc([prefix() <> "getmetanonce", peak_index, address])
    Rlpx.bin2uint(num)
  end

  def get_account(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)
    [acc] = cached_rpc([prefix() <> "getaccount", peak_index, address])
    acc = Rlpx.list2map(acc)

    %Account{
      nonce: Rlpx.bin2uint(acc["nonce"]),
      balance: Rlpx.bin2uint(acc["balance"]),
      storage_root: Rlpx.bin2addr(acc["storage_root"]),
      code_hash: acc["code"]
    }
  end

  def get_account_root(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)

    case cached_rpc([prefix() <> "getaccountroot", peak_index, address]) do
      nil -> nil
      [""] -> nil
      [root] -> root
    end
  end

  def get_account_value(address, key = <<_::256>>, peak \\ peak())
      when is_binary(address) or is_integer(address) do
    hd(get_account_values(address, [key], peak))
  end

  def get_account_values(address, keys, peak \\ peak())
      when is_list(keys) and (is_binary(address) or is_integer(address)) do
    Enum.chunk_every(keys, 100)
    |> Enum.flat_map(fn chunk -> do_get_account_values(address, chunk, peak) end)
  end

  defp do_get_account_values(address, keys, peak)
       when is_list(keys) and (is_binary(address) or is_integer(address)) do
    peak_index = peak_number(peak)
    address = Hash.to_address(address)
    values = cached_rpc([prefix() <> "getaccountvalues", peak_index, address | keys])

    case values do
      {:error, message} ->
        Logger.debug(
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

  def peak(), do: DiodeClient.Manager.get_peak(__MODULE__)

  def peak_number(peak \\ peak()) do
    Rlpx.bin2uint(peak["number"])
  end

  defdelegate cached_rpc(args), to: DiodeClient.Shell
  defdelegate rpc(args), to: DiodeClient.Shell
end
