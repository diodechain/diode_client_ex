defmodule DiodeClient.Shell.Base do
  @moduledoc """
   Specialized shell for Base.
  """

  alias DiodeClient.{ABI, Shell, Wallet}
  use DiodeClient.Shell.Common

  def block_time(), do: :timer.seconds(2)
  def chain_id(), do: 8453
  def prefix(), do: "base:"
  @gas_limit 10_000_000
  def default_gas_limit(), do: @gas_limit

  def blockexplorer_url(opts \\ []) do
    cond do
      opts[:address] != nil ->
        "https://basescan.org/address/#{maybe_hex(opts[:address])}"

      opts[:tx] != nil ->
        "https://basescan.org/tx/#{maybe_hex(opts[:tx])}"

      true ->
        "https://basescan.org"
    end
  end

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    meta_transaction = Keyword.get(opts, :meta_transaction, false)

    if meta_transaction do
      wallet = DiodeClient.ensure_wallet()
      from = Wallet.address!(wallet)
      nonce = Keyword.get(opts, :nonce) || get_meta_nonce(from, peak(), opts)

      create_meta_transaction(address, function_name, types, values, nonce, opts)
      # |> MetaTransaction.simulate(__MODULE__)
      |> send_transaction()
    else
      create_transaction(address, function_name, types, values, opts)
      |> send_transaction()
    end
  end

  def create_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    callcode = ABI.encode_call(function_name, types, values)
    Shell.Common.create_transaction(__MODULE__, address, callcode, Map.new(opts))
  end

  def create_meta_transaction(address, function_name, types, values, nonce, opts \\ [])
      when is_list(types) and is_list(values) do
    # https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html
    callcode = ABI.encode_call(function_name, types, values)
    opts = Keyword.put(opts, :from, DiodeClient.Shell.Common.identity_address(opts))
    Shell.Common.create_meta_transaction(__MODULE__, address, callcode, nonce, opts)
  end

  def get_meta_nonce(address, peak \\ peak(), opts \\ []) do
    DiodeClient.Shell.Common.get_meta_nonce(__MODULE__, address, peak, opts)
  end

  def get_account(address, peak \\ peak()) do
    DiodeClient.Shell.Common.get_account(__MODULE__, address, peak)
  end

  def get_account_root(address, peak \\ peak()) do
    DiodeClient.Shell.Common.get_account_root(__MODULE__, address, peak)
  end

  def get_account_values(address, keys, peak \\ peak())
      when is_list(keys) and (is_binary(address) or is_integer(address)) do
    DiodeClient.Shell.Common.get_account_values(__MODULE__, address, keys, peak)
  end

  def call(address, method, types, args, opts \\ []) do
    DiodeClient.Shell.Common.call(__MODULE__, address, method, types, args, opts)
  end
end
