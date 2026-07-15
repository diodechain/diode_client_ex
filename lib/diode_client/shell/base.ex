defmodule DiodeClient.Shell.Base do
  @moduledoc """
  Specialized shell for Base L2.
  """

  use DiodeClient.Shell.Common, meta_transactions: :identity

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
end
