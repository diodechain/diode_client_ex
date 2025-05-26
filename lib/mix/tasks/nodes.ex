defmodule Mix.Tasks.Nodes do
  @moduledoc false
  import DiodeClient.Object.Server
  alias DiodeClient.{Base16, Hash}

  def run(args) do
    Logger.configure(level: :info)
    Application.ensure_all_started(:diode_client)
    DiodeClient.ensure_wallet()
    process(args)
  end

  def process(["list"]) do
    IO.puts("Generating set")
    s = set()
    IO.puts("Set generated: #{length(s)}")

    full =
      Enum.with_index(s, fn key, index ->
        IO.puts("Getting nodes for #{key_hash(key)} #{index}/#{length(s)}")
        DiodeClient.Shell.get_nodes(key)
      end)
      |> Enum.concat()

    IO.puts("Retrieved a total of #{length(full)} Nodes")
    unique = Enum.uniq(full)
    IO.puts("Found #{length(unique)} unique nodes")

    current_block = DiodeClient.Shell.Moonbeam.peak_number()

    for srv = server(host: host, version: version, extra: extra) <- unique do
      block = Enum.map(extra, fn [k, v] -> {k, v} end) |> Map.new() |> Map.get("block")
      key = DiodeClient.Object.Server.key(srv)

      IO.puts(
        "Node: #{key_hash(key)} Version #{inspect(version)} Block #{block - current_block} IP #{inspect(host)}"
      )
    end
  end

  def process(["get"]) do
    addr = DiodeClient.Wallet.new() |> DiodeClient.Wallet.address!()
    process(["get", Base16.encode(addr)])
  end

  def process(["get", "0x" <> _ = value]) do
    current_block = DiodeClient.Shell.Moonbeam.peak_number()
    addr = Base16.decode(value)
    IO.puts("Getting nodes for #{Base16.encode(addr)} => #{key_hash(addr)}")
    IO.puts("")

    servers = DiodeClient.Shell.get_nodes(addr)

    for srv = server(host: host, version: version, extra: extra) <- servers do
      block = Enum.map(extra, fn [k, v] -> {k, v} end) |> Map.new() |> Map.get("block")
      key = DiodeClient.Object.Server.key(srv)

      IO.puts(
        "Node: #{key_hash(key)} Version #{inspect(version)} Block #{block - current_block} IP #{inspect(host)}"
      )
    end
  end

  def key_hash(bin) do
    Base16.encode(Hash.sha3_256(bin))
  end

  def set() do
    set(Map.new(), 0)
  end

  def set(set, num) do
    if map_size(set) == 64 do
      Map.to_list(set)
      |> Enum.sort()
      |> Enum.map(fn {_k, v} -> v end)
    else
      <<key, _::binary>> = Hash.sha3_256(<<num>>)
      set(Map.put(set, key, <<num>>), num + 1)
    end
  end
end
