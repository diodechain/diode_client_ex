defmodule Mix.Tasks.Diode.EvmTransaction do
  @moduledoc """
  Builds and submits a test Oasis Sapphire transaction via cast.
  """
  @shortdoc "Send a test Oasis Sapphire transaction via cast"

  use Mix.Task

  def run(args) do
    Logger.configure(level: :info)
    process(args)
  end

  def process([]) do
    {balance, 0} =
      System.cmd("cast", ["balance", DiodeClient.Base16.encode(DiodeClient.address())])

    _balance = String.trim(balance) |> String.to_integer()
    {gas_price, 0} = System.cmd("cast", ["gas-price", "--rpc-url", "https://sapphire.oasis.io"])
    gas_price = String.trim(gas_price) |> String.to_integer()

    tx =
      DiodeClient.Shell.OasisSapphire.create_transaction(
        DiodeClient.Base16.decode("0x517D05603fdf943F7a2ffA6881811bED2A8CE19D"),
        "setValue",
        ["uint256"],
        [128],
        gas_price: gas_price,
        gas: 500_000
      )

    privkey = DiodeClient.wallet() |> DiodeClient.Wallet.privkey!()

    tx2 =
      %{tx | data: DiodeClient.OasisSapphire.encrypt_data(DiodeClient.Transaction.payload(tx))}
      |> DiodeClient.Transaction.sign(privkey)

    raw_tx = DiodeClient.Transaction.to_binary(tx2) |> DiodeClient.Base16.encode()

    {cmd, args} =
      {"cast",
       ["rpc", "--rpc-url", "https://sapphire.oasis.io", "eth_sendRawTransaction", raw_tx]}

    IO.puts(cmd <> " " <> Enum.join(args, " "))
    System.cmd(cmd, args, into: IO.stream())
  end
end
