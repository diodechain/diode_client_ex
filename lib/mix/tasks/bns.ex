defmodule Mix.Tasks.Bns do
  @moduledoc """
  BNS CLI

  export SEED_LIST=us1.prenet.diode.io
  """
  alias DiodeClient.{Base16, Contracts, Transaction, Block}

  defp init() do
    Logger.configure(level: :info)
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
  end

  def run(["register", name, destination]) do
    init()
    IO.puts("Registering #{name} to #{destination}...")
    register(name, destination)
  end

  def run(["unregister", name]) do
    init()
    IO.puts("Unregistering #{name}...")
    unregister(name)
  end

  def run(["whoami"]) do
    init()
    IO.puts("Whoami: #{DiodeClient.Wallet.printable(DiodeClient.wallet())}")
  end

  def run(_) do
    IO.puts("Usage: mix bns register <name> <destination>")
    IO.puts("Usage: mix bns unregister <name>")
    IO.puts("Usage: mix bns whoami")
    System.halt(1)
  end

  def register(name, destination) do
    {result, tx} = Contracts.BNS.register(name, Base16.decode(destination))
    IO.puts("Result: #{inspect(result)}")
    # IO.puts("Transaction: #{inspect(tx)}")

    with ["ok", _tx_hash] <- result do
      await_transaction(tx)
    end
  end

  def unregister(name) do
    {result, tx} = Contracts.BNS.unregister(name)
    IO.puts("Result: #{inspect(result)}")

    with ["ok", _tx_hash] <- result do
      await_transaction(tx)
    end
  end

  defp await_transaction(tx) do
    peak = DiodeClient.Manager.get_peak(Transaction.shell(tx))
    nonce = Transaction.nonce(tx)
    user_nonce = Transaction.user_nonce(tx)

    if nonce >= user_nonce do
      IO.puts(
        "Waiting for transaction #{nonce} to be mined, current nonce: #{user_nonce} @ #{Block.number(peak)}"
      )

      await_transaction(tx, peak)
    else
      IO.puts("Transaction #{nonce} already mined")
    end
  end

  defp await_transaction(tx, peak) do
    new_peak = DiodeClient.Manager.get_peak(Transaction.shell(tx))

    if peak == new_peak do
      Process.sleep(1000)
      await_transaction(tx, new_peak)
    else
      nonce = Transaction.nonce(tx)
      user_nonce = Transaction.user_nonce(tx)

      IO.puts(
        "Waiting for transaction #{nonce} to be mined, current nonce: #{user_nonce} @ #{Block.number(new_peak)}"
      )

      if nonce >= user_nonce do
        Process.sleep(5000)
        await_transaction(tx, new_peak)
      else
        IO.puts("Transaction #{nonce} already mined")
      end
    end
  end
end
