defmodule DiodeClient.Shell do
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
    BertExt,
    Connection,
    ETSLru,
    Hash,
    Transaction,
    Rlpx,
    ShellCache
  }

  require Logger

  def block_time(), do: :timer.seconds(12)
  def chain_id(), do: 15
  def prefix(), do: ""
  @gas_limit 10_000_000
  @null_hash DiodeClient.Hash.sha3_256("")
  @null_root <<67, 138, 144, 64, 93, 170, 135, 101, 57, 8, 44, 208, 186, 246, 205, 218, 163, 191,
               136, 15, 28, 138, 240, 192, 56, 31, 0, 66, 219, 147, 8, 138>>

  def blockexplorer_url(opts \\ []) do
    cond do
      opts[:address] != nil ->
        "https://diode.io/prenet/#/address/#{maybe_hex(opts[:address])}"

      opts[:tx] != nil ->
        "https://diode.io/prenet/#/tx/#{maybe_hex(opts[:tx])}"

      true ->
        "https://diode.io/prenet/"
    end
  end

  defp maybe_hex(x = "0x" <> _), do: x
  defp maybe_hex(x), do: DiodeClient.Base16.encode(x, false)

  defmacrop assert_equal(a, b, flush_keys) do
    stra = Macro.to_string(a)
    strb = Macro.to_string(b)

    quote do
      if unquote(a) != unquote(b) do
        for key <- unquote(flush_keys) do
          uncache_rpc(key)
        end

        throw(
          {:merkle_check_failed,
           "Assert #{inspect(unquote(stra))} == #{inspect(unquote(strb))} failed! (#{inspect(unquote(a))} != #{inspect(unquote(b))})"}
        )
      end
    end
  end

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    create_transaction(address, function_name, types, values, opts)
    |> send_transaction()
  end

  def send_transaction(tx = %Transaction{}) do
    DiodeClient.Shell.Common.send_transaction(__MODULE__, tx)
  end

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
    DiodeClient.Shell.Common.create_transaction(__MODULE__, callcode, opts)
  end

  def get_object(key) do
    case cached_rpc(["getobject", key]) do
      [
        [
          "ticket",
          server_id,
          block_number,
          fleet_contract,
          total_connections,
          total_bytes,
          local_address,
          device_signature,
          server_signature
        ]
      ] ->
        block_number = Rlpx.bin2uint(block_number)
        block_hash = get_block_header(block_number)["block_hash"]

        {:ticket, server_id, block_number, block_hash, fleet_contract,
         Rlpx.bin2uint(total_connections), Rlpx.bin2uint(total_bytes), local_address,
         device_signature, server_signature}

      [
        [
          "ticketv2",
          server_id,
          chain_id,
          epoch,
          fleet_contract,
          total_connections,
          total_bytes,
          local_address,
          device_signature,
          server_signature
        ]
      ] ->
        {:ticketv2, server_id, Rlpx.bin2uint(chain_id), Rlpx.bin2uint(epoch), fleet_contract,
         Rlpx.bin2uint(total_connections), Rlpx.bin2uint(total_bytes), local_address,
         device_signature, server_signature}

      _other ->
        nil
    end
  end

  def get_node(key) do
    Connection.rpc(conn(), ["getnode", key])
  end

  def get_nodes(key) do
    case Connection.rpc(conn(), ["getnodes", key]) do
      [nodes] -> Enum.map(nodes, &DiodeClient.Object.decode_rlp_list!/1)
      _other -> []
    end
  end

  def get_block_header(block_index) do
    case cached_rpc(["getblockheader", block_index]) do
      [block] -> Rlpx.list2map(block)
    end
  end

  def get_state_roots(%{"number" => number, "state_hash" => hash}) do
    number = Rlpx.bin2uint(number)
    [roots] = cached_rpc(["getstateroots", number])
    assert_equal(hash, signature(roots), [["getstateroots", number]])
    roots
  end

  def get_account(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)

    [state_roots, account] =
      await_all([
        fn -> get_state_roots(peak) end,
        fn -> cached_rpc(["getaccount", peak_index, address]) end
      ])

    flush_keys = [["getaccount", peak_index, address], ["getstateroots", peak_index]]

    case account do
      # empty needs a proof as well...
      {:error, "account does not exist"} ->
        %Account{
          nonce: 0,
          balance: 0,
          storage_root: nil,
          code_hash: @null_hash
        }

      [acc, proofs] when is_list(acc) ->
        acc = Rlpx.list2map(acc)

        acc = %Account{
          nonce: Rlpx.bin2uint(acc["nonce"]),
          balance: Rlpx.bin2uint(acc["balance"]),
          storage_root: Rlpx.bin2addr(acc["storage_root"]),
          code_hash: acc["code"]
        }

        proof = proof(proofs, 0)
        # Checking that this proof connects to the root
        [prefix, pos | values] = value(proofs)
        assert_equal(proof, Enum.at(state_roots, pos), flush_keys)

        x = bit_size(prefix)
        k = Hash.sha3_256(address)
        <<key_prefix::bitstring-size(x), _::bitstring>> = k
        <<last_byte>> = binary_part(k, byte_size(k), -1)

        # Checking that the provided range is for the given keys prefix
        assert_equal(prefix, key_prefix, flush_keys)

        # Checking that the provided leaf matches the given key
        assert_equal(pos, rem(last_byte, 16), flush_keys)
        hash = :proplists.get_value(address, values)

        # Finally ensuring that the proofed value is our account hash
        assert_equal(hash, Account.hash(acc), flush_keys)

        if acc.code_hash in [nil, @null_hash] do
          %Account{acc | storage_root: nil}
        else
          acc
        end
    end
  end

  def get_account_root(address, peak \\ peak()) do
    address = Hash.to_address(address)
    %Account{storage_root: root} = get_account(address, peak)
    root
  end

  def get_account_roots(address, peak \\ peak()) do
    peak_index = peak_number(peak)
    address = Hash.to_address(address)

    [root, roots] =
      await_all([
        fn -> get_account_root(address, peak) end,
        fn ->
          case cached_rpc(["getaccountroots", peak_index, address]) do
            [roots] ->
              roots

            other ->
              raise(
                "#{Connection.server_url(conn())}: received invalid response #{inspect(other)} at #{inspect(peak_index)}"
              )
          end
        end
      ])

    flush_keys = [
      ["getaccountroots", peak_index, address],
      ["getaccount", peak_index, address],
      ["getstateroots", peak_index]
    ]

    assert_equal(root || @null_root, signature(roots), flush_keys)
    roots
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

    [roots, values] =
      await_all([
        fn -> get_account_roots(address, peak) end,
        fn -> cached_rpc(["getaccountvalues", peak_index, address | keys]) end
      ])

    flush_keys = [
      ["getaccountvalues", peak_index, address | keys],
      ["getaccountroots", peak_index, address],
      ["getaccount", peak_index, address],
      ["getstateroots", peak_index]
    ]

    case values do
      {:error, message} ->
        Logger.debug("getaccountvalues #{inspect(keys)} produced error #{inspect(message)}")
        raise "getaccountvalues #{inspect(keys)} produced error #{inspect(message)}"

      [values] ->
        Enum.zip(values, keys)
        |> Enum.map(fn {proofs, key} ->
          proof = proof(proofs, 0)
          # Checking that this proof connects to the root
          [prefix, pos | values] = value(proofs)
          assert_equal(proof, Enum.at(roots, pos), flush_keys)

          x = bit_size(prefix)
          k = Hash.sha3_256(key)
          <<key_prefix::bitstring-size(x), _::bitstring>> = k
          <<last_byte>> = binary_part(k, byte_size(k), -1)

          # Checking that the provided range is for the given keys prefix
          assert_equal(key_prefix, prefix, flush_keys)

          # Checking that the provided leaf matches the given key
          assert_equal(pos, rem(last_byte, 16), flush_keys)
          :proplists.get_value(key, values)
        end)
    end
  end

  def peak() do
    DiodeClient.Manager.get_peak(__MODULE__)
  end

  def peak_number(peak \\ peak()) do
    Rlpx.bin2uint(peak["number"])
  end

  def cached_rpc(args) do
    ETSLru.fetch(ShellCache, args, fn ->
      # Single retry for remote_closed
      case Connection.rpc(conn(), args) do
        {:error, "remote_closed"} -> Connection.rpc(conn(), args)
        ret -> ret
      end
    end)
  end

  def uncache_rpc(args) do
    ETSLru.delete(ShellCache, args)
  end

  def rpc(args) do
    Connection.rpc(conn(), args)
  end

  def ether(x), do: 1000 * finney(x)
  def finney(x), do: 1000 * szabo(x)
  def szabo(x), do: 1000 * gwei(x)
  def gwei(x), do: 1000 * mwei(x)
  def mwei(x), do: 1000 * kwei(x)
  def kwei(x), do: 1000 * wei(x)
  def wei(x) when is_integer(x), do: x

  # defp index() do
  #   Rlpx.bin2uint(Connection.peak(conn())["number"])
  # end

  defp conn() do
    DiodeClient.default_conn()
  end

  def sticky_conn() do
    DiodeClient.Manager.await()
    DiodeClient.Manager.get_sticky_connection()
  end

  defp value(term, prefix \\ <<>>)

  defp value([aprefix, pos | rest], prefix) when is_binary(aprefix) and byte_size(aprefix) < 32 do
    pos = Rlpx.bin2uint(pos)
    rest = Enum.map(rest, &List.to_tuple/1)
    [prefix, pos | rest]
  end

  defp value([left, right], depth) do
    value(left, <<depth::bitstring, 0::1>>) || value(right, <<depth::bitstring, 1::1>>)
  end

  defp value(hash, _depth) when is_binary(hash) do
    false
  end

  defp proof([prefix, pos | rest], depth) when is_binary(prefix) and byte_size(prefix) < 32 do
    prefix =
      if rem(depth, 8) == 0 do
        prefix
      else
        for <<x::bytes-size(1) <- prefix>>,
          do: if(x == "1", do: <<1::size(1)>>, else: <<0::size(1)>>),
          into: ""
      end

    pos = Rlpx.bin2uint(pos)
    rest = Enum.map(rest, &List.to_tuple/1)
    list = [prefix, pos | rest]
    signature(list)
  end

  defp proof([left, right], depth) do
    signature([proof(left, depth + 1), proof(right, depth + 1)])
  end

  defp proof(hash, _depth) when is_binary(hash) do
    hash
  end

  defp signature(list) do
    Hash.sha3_256(BertExt.encode!(list))
  end

  def await_all(promises) do
    refs =
      for p <- promises do
        spawn_monitor(fn -> exit({:result, p.()}) end)
      end

    for {pid, ref} <- refs do
      receive do
        {:DOWN, ^ref, :process, ^pid, {:result, result}} ->
          result

        {:DOWN, ^ref, :process, ^pid, reason} ->
          raise "promise failed: #{inspect(reason)}"
      end
    end
  end
end
