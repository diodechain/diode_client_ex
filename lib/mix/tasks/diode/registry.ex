defmodule Mix.Tasks.Diode.Registry do
  @moduledoc """
  Read `DiodeRegistryLight` state on Moonbeam.

      mix diode.registry version
      mix diode.registry epoch
      mix diode.registry fleets
      mix diode.registry relays
      mix diode.registry fleet 0x...
      mix diode.registry node 0x...fleet... 0x...node...
  """
  @shortdoc "Read DiodeRegistryLight on Moonbeam"

  use Mix.Task

  alias DiodeClient.{Base16, Hash}
  alias DiodeClient.Contracts.Registry

  @diode_decimals 1_000_000_000_000_000_000

  defp init() do
    Logger.configure(level: :info)
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
  end

  defp block() do
    Registry.shell().peak_number() - 3
  end

  def run(["version"]) do
    init()
    print_header()
    IO.puts("Version: #{Registry.version(block())}")
  end

  def run(["epoch"]) do
    init()
    print_header()
    print_epoch()
  end

  def run(["fleets"]) do
    init()
    print_header()

    Registry.fleet_array(block())
    |> Enum.with_index(1)
    |> Enum.each(fn {fleet, index} ->
      IO.puts("#{index}. #{Hash.printable(fleet)}")
    end)
  end

  def run(["relays"]) do
    init()
    print_header()

    Registry.relay_array(block())
    |> Enum.with_index(1)
    |> Enum.each(fn {relay, index} ->
      IO.puts("#{index}. #{Hash.printable(relay)}")
    end)
  end

  def run(["fleet", "0x" <> _ = fleet]) do
    init()
    print_header()
    print_fleet(Base16.decode(fleet))
  end

  def run(["node", "0x" <> _ = fleet, "0x" <> _ = node]) do
    init()
    print_header()
    print_node(Base16.decode(fleet), Base16.decode(node))
  end

  def run(_) do
    Mix.shell().error("""
    Usage:
      mix diode.registry version
      mix diode.registry epoch
      mix diode.registry fleets
      mix diode.registry relays
      mix diode.registry fleet <fleet_address>
      mix diode.registry node <fleet_address> <node_address>
    """)

    System.halt(1)
  end

  defp print_header() do
    shell = Registry.shell()
    block = block()

    IO.puts("Registry: #{Hash.printable(Registry.address())}")
    IO.puts("Shell:    #{inspect(shell)} @ block #{block}")
    IO.puts("")
  end

  defp print_epoch() do
    block = block()

    IO.puts("Seconds per epoch: #{Registry.seconds_per_epoch()}")
    IO.puts("Computed epoch:    #{Registry.epoch(block)}")
    IO.puts("Stored epoch:      #{Registry.current_epoch(block)}")
    IO.puts("Sync needed:       #{Registry.epoch_sync_needed?(block)}")
    IO.puts("Token:             #{Hash.printable(Registry.token(block))}")
  end

  defp print_fleet(fleet) do
    IO.puts("Fleet: #{Hash.printable(fleet)}")
    IO.puts("")

    %{
      exists: exists,
      current_balance: current_balance,
      withdraw_request_size: withdraw_request_size,
      withdrawable_balance: withdrawable_balance,
      current_epoch: current_epoch,
      score: score
    } = Registry.get_fleet(fleet, block())

    IO.puts("exists:                 #{exists}")
    IO.puts("current_balance:        #{format_amount(current_balance)}")
    IO.puts("withdraw_request_size:  #{format_amount(withdraw_request_size)}")
    IO.puts("withdrawable_balance:   #{format_amount(withdrawable_balance)}")
    IO.puts("current_epoch:          #{current_epoch}")
    IO.puts("score:                  #{score}")
  end

  defp print_node(fleet, node) do
    IO.puts("Fleet: #{Hash.printable(fleet)}")
    IO.puts("Node:  #{Hash.printable(node)}")
    IO.puts("")

    %{node: node_address, score: score} = Registry.get_node(fleet, node, block())

    IO.puts("node:  #{Hash.printable(node_address)}")
    IO.puts("score: #{score}")
  end

  defp format_amount(amount) when is_integer(amount) do
    whole = div(amount, @diode_decimals)
    fraction = rem(amount, @diode_decimals)

    "#{whole}.#{fraction |> Integer.to_string() |> String.pad_leading(18, "0")} DIODE (#{amount} wei)"
  end
end
