defmodule Mix.Tasks.Diode.EvmCall do
  @moduledoc """
  Runs `cast call --trace` from an eth_call JSON-RPC request file (Oasis Sapphire).
  """
  @shortdoc "Trace an eth_call via cast (Oasis Sapphire)"

  use Mix.Task

  def run(args) do
    Logger.configure(level: :info)
    process(args)
  end

  def process([filename]) do
    %{"params" => params, "method" => "eth_call", "jsonrpc" => "2.0"} =
      File.read!(filename)
      |> Jason.decode!()

    rpc_url = "https://sapphire.oasis.io"
    params = hd(params)

    {cmd, args} =
      {"cast",
       [
         "call",
         "--rpc-url",
         rpc_url,
         "--trace",
         "--data",
         params["data"],
         "--from",
         params["from"],
         params["to"]
       ]}

    IO.puts(cmd <> " " <> Enum.join(args, " "))
    System.cmd(cmd, args, into: IO.stream())
  end
end
