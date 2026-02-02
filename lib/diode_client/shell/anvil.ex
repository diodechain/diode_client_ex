defmodule DiodeClient.Shell.Anvil do
  @moduledoc """
  Shell for testing against a local Anvil chain (Foundry).
  Uses HTTP JSON-RPC; RPC URL and chain ID are configurable via ANVIL_RPC_URL and ANVIL_CHAIN_ID.
  """
  alias DiodeClient.{
    ABI,
    Account,
    Base16,
    ETSLru,
    Hash,
    ShellCache,
    Transaction
  }

  require Logger
  use DiodeClient.Shell.Common

  def rpc_url do
    System.get_env("ANVIL_RPC_URL", "http://127.0.0.1:8545")
  end

  def chain_id do
    case System.get_env("ANVIL_CHAIN_ID", "31337") do
      id when is_binary(id) -> String.to_integer(id)
    end
  end

  def block_time(), do: :timer.seconds(1)
  def prefix(), do: ""
  @gas_limit 10_000_000
  def default_gas_limit(), do: @gas_limit

  def blockexplorer_url(_opts \\ []) do
    ""
  end

  def peak do
    with [json] <- rpc(["getblockpeak"]),
         [block] <- parse_block_peak(json) do
      block
    end
  end

  def get_block_header(block_index) do
    case cached_rpc([prefix() <> "getblockheader", block_index]) do
      [block] when is_map(block) -> block
      [block] -> block
      {:error, reason} -> raise "Anvil getblockheader failed: #{inspect(reason)}"
    end
  end

  def cached_rpc(args) do
    ETSLru.fetch(ShellCache, args, fn ->
      case do_http_rpc(args) do
        {:error, _} = err -> err
        result -> [result]
      end
    end)
  end

  def uncache_rpc(args) do
    ETSLru.delete(ShellCache, args)
  end

  def rpc(args) do
    case do_http_rpc(args) do
      {:error, _} = err -> err
      result -> [result]
    end
  end

  def send_transaction(tx = %Transaction{}) do
    raw = Transaction.to_binary(tx)
    hex = Base16.encode(raw, short: false)

    case json_rpc("eth_sendRawTransaction", [hex]) do
      %{"result" => tx_hash} ->
        {[tx_hash], tx}

      %{"error" => error} ->
        {{:error, inspect(error)}, tx}
    end
  end

  def send_transaction(_tx = %DiodeClient.IdentityRequest{}) do
    {:error, :not_implemented}
  end

  def send_transaction(_tx = %DiodeClient.MetaTransaction{}) do
    {:error, :not_implemented}
  end

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    create_transaction(address, function_name, types, values, opts)
    |> send_transaction()
  end

  def create_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    callcode = ABI.encode_call(function_name, types, values)
    DiodeClient.Shell.Common.create_transaction(__MODULE__, address, callcode, Map.new(opts))
  end

  def get_meta_nonce(_address, _peak \\ peak(), _opts \\ []) do
    {:error, :not_implemented}
  end

  def get_account(address, _peak \\ peak()) do
    address = Hash.to_address(address)
    addr_hex = Base16.encode(address, short: false)
    block = "latest"

    with {:ok, balance} <- json_rpc_ok("eth_getBalance", [addr_hex, block]),
         {:ok, nonce} <- json_rpc_ok("eth_getTransactionCount", [addr_hex, block]),
         {:ok, code} <- json_rpc_ok("eth_getCode", [addr_hex, block]) do
      balance_bin = decode_hex_to_bin(balance)
      nonce_bin = decode_hex_to_bin(nonce)

      code_hash =
        if code in ["0x", "0x0", nil],
          do: DiodeClient.Hash.sha3_256(""),
          else: DiodeClient.Hash.sha3_256(Base16.decode(code))

      %Account{
        nonce: :binary.decode_unsigned(nonce_bin),
        balance: :binary.decode_unsigned(balance_bin),
        storage_root: nil,
        code_hash: code_hash
      }
    end
  end

  def get_account_root(_address, _peak \\ peak()) do
    nil
  end

  def get_account_value(address, key = <<_::256>>, peak \\ peak())
      when is_binary(address) or is_integer(address) do
    hd(get_account_values(address, [key], peak))
  end

  def get_account_values(address, keys, peak \\ peak())
      when is_list(keys) and (is_binary(address) or is_integer(address)) do
    address = Hash.to_address(address)
    addr_hex = Base16.encode(address, short: false)
    block_hex = block_to_hex(peak)

    Enum.map(keys, fn key ->
      key_hex = Base16.encode(key, short: false)

      case json_rpc_ok("eth_getStorageAt", [addr_hex, key_hex, block_hex]) do
        {:ok, "0x" <> rest} ->
          bin = Base16.decode("0x" <> rest)

          if bin == <<0::256>> do
            :undefined
          else
            bin
          end

        {:error, _} ->
          :undefined
      end
    end)
  end

  def call(address, method, types, args, opts \\ []) do
    DiodeClient.Shell.Common.call(__MODULE__, address, method, types, args, opts)
  end

  # Private: HTTP JSON-RPC. For "rpc" commands return raw JSON string so Common can Jason.decode! it.
  defp do_http_rpc(["rpc", method, params]) when is_binary(params) do
    params_list = Jason.decode!(params)
    json_rpc_raw(method, params_list)
  end

  defp do_http_rpc(["getblockheader", block_index]) do
    block_hex = block_num_to_hex(block_index)

    case json_rpc("eth_getBlockByNumber", [block_hex, false]) do
      %{"result" => nil} ->
        {:error, "block not found"}

      %{"result" => block} when is_map(block) ->
        eth_block_to_diode_block(block)

      other ->
        {:error, inspect(other)}
    end
  end

  defp do_http_rpc(["getblockpeak"]) do
    case json_rpc("eth_blockNumber", []) do
      %{"result" => hex} ->
        block_hex = hex

        case json_rpc("eth_getBlockByNumber", [block_hex, false]) do
          %{"result" => nil} -> {:error, "block not found"}
          %{"result" => block} when is_map(block) -> eth_block_to_diode_block(block)
          other -> {:error, inspect(other)}
        end

      %{"error" => err} ->
        {:error, inspect(err)}
    end
  end

  defp do_http_rpc(_) do
    {:error, :unknown_command}
  end

  defp parse_block_peak(result) when is_map(result) do
    [result]
  end

  defp parse_block_peak(_) do
    {:error, :invalid_peak}
  end

  defp block_num_to_hex(num) when is_integer(num) do
    "0x" <> Integer.to_string(num, 16)
  end

  defp block_num_to_hex(bin) when is_binary(bin) do
    "0x" <> Base.encode16(bin, case: :lower)
  end

  defp block_to_hex("latest"), do: "latest"

  defp block_to_hex(block) when is_map(block) do
    case block["number"] do
      num when is_binary(num) -> num
      num when is_integer(num) -> block_num_to_hex(num)
    end
  end

  defp block_to_hex(n) when is_integer(n), do: block_num_to_hex(n)

  defp eth_block_to_diode_block(block) do
    %{
      "number" => hex_to_bin(block["number"]),
      "block_hash" => hex_to_bin(block["hash"]),
      "previous_block" => hex_to_bin(block["parentHash"]),
      "state_hash" => hex_to_bin(block["stateRoot"]),
      "timestamp" => hex_to_bin(block["timestamp"]),
      "transaction_hash" => hex_to_bin(block["transactionsRoot"]),
      "miner_signature" => block["miner"] || "",
      "nonce" => hex_to_bin(block["nonce"] || "0x0")
    }
  end

  defp decode_hex_to_bin(nil), do: <<0>>
  defp decode_hex_to_bin("0x"), do: <<0>>
  defp decode_hex_to_bin("0x0"), do: <<0>>
  defp decode_hex_to_bin(str = <<"0x", _::binary>>), do: Base16.decode(str)

  defp hex_to_bin(nil), do: <<0>>
  defp hex_to_bin("0x"), do: <<0>>
  defp hex_to_bin("0x0"), do: <<0>>
  defp hex_to_bin(str = <<"0x", _::binary>>), do: Base16.decode(str)

  defp json_rpc_raw(method, params) do
    body =
      %{jsonrpc: "2.0", method: method, params: params, id: 1}
      |> Jason.encode!()

    url = String.to_charlist(rpc_url())
    headers = [{~c"content-type", ~c"application/json"}]

    case :httpc.request(
           :post,
           {url, headers, ~c"application/json", body},
           [timeout: 30_000],
           []
         ) do
      {:ok, {{_, 200, _}, _headers, resp_body}} when is_binary(resp_body) ->
        resp_body

      {:ok, {{_, 200, _}, _headers, _resp_body}} ->
        Jason.encode!(%{"error" => %{"message" => "invalid response"}})

      {:ok, {{_, status, _}, _, _}} ->
        Jason.encode!(%{"error" => %{"message" => "HTTP #{status}"}})

      {:error, reason} ->
        Jason.encode!(%{"error" => %{"message" => inspect(reason)}})
    end
  end

  defp json_rpc(method, params) do
    json_rpc_raw(method, params) |> Jason.decode!()
  end

  defp json_rpc_ok(method, params) do
    case json_rpc(method, params) do
      %{"result" => result} -> {:ok, result}
      %{"error" => err} -> {:error, err}
    end
  end
end
