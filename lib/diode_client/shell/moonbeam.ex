defmodule DiodeClient.Shell.Moonbeam do
  @moduledoc """
  Specialized shell for Moonbeam (chain ID 1284) with CallPermit meta-transactions.
  """

  alias DiodeClient.{
    ABI,
    Hash,
    Rlpx,
    Shell,
    Wallet
  }

  use DiodeClient.Shell.Common

  def block_time(), do: :timer.seconds(6)
  def chain_id(), do: 1284
  def prefix(), do: "glmr:"
  @gas_limit 10_000_000
  def default_gas_limit(), do: @gas_limit

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

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    if Keyword.get(opts, :meta_transaction, false) do
      wallet = DiodeClient.ensure_wallet()
      from = Wallet.address!(wallet)
      nonce = Keyword.get(opts, :nonce) || get_meta_nonce(from)
      create_meta_transaction(address, function_name, types, values, nonce, opts)
    else
      create_transaction(address, function_name, types, values, opts)
    end
    |> send_transaction()
  end

  def create_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    callcode = ABI.encode_call(function_name, types, values)
    Shell.Common.create_transaction(__MODULE__, address, callcode, Map.new(opts))
  end

  def create_meta_transaction(address, function_name, types, values, nonce, opts \\ [])
      when is_list(types) and is_list(values) do
    callcode = ABI.encode_call(function_name, types, values)
    Shell.Common.create_meta_transaction(__MODULE__, address, callcode, nonce, opts)
  end

  def get_meta_nonce(address, peak \\ peak(), _opts \\ []) do
    address = Hash.to_address(address)
    peak_index = Rlpx.bin2uint(peak["number"])
    [num] = cached_rpc([prefix() <> "getmetanonce", peak_index, address])
    Rlpx.bin2uint(num)
  end
end
