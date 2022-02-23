defmodule DiodeClient.Shell do
  alias DiodeClient.{
    ABI,
    Account,
    BertExt,
    Connection,
    ETSLru,
    Hash,
    Transaction,
    Rlp,
    Rlpx,
    ShellCache,
    Wallet
  }

  use DiodeClient.Log

  @chain_id 15
  @gas_limit 10_000_000

  @moduledoc """
    me = Diode.miner() |> Wallet.address!()
    Shell.get_balance(me)

    fleetContract = Base16.decode("0x6728c7bea74db60c2fb117c15de28b0b0686c389")
    Shell.call(fleetContract, "accountant")

    registryContract = Diode.registry_address()
    Shell.call(registryContract, "ContractStake", ["address"], [fleetContract])

    addr = Chain.GenesisFactory.genesis_accounts |> hd |> elem(0)
    Shell.call_from(Wallet.from_address(addr), registryContract, "ContractStake", ["address"], [fleetContract])
  """

  defmacrop assert_equal(a, b) do
    stra = Macro.to_string(a)
    strb = Macro.to_string(b)

    quote do
      if unquote(a) != unquote(b) do
        throw(
          {:merkle_check_failed,
           "Assert #{inspect(unquote(stra))} == #{inspect(unquote(strb))} failed! (#{
             inspect(unquote(a))
           } != #{inspect(unquote(b))})"}
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
    rlp = Transaction.to_rlp(tx) |> Rlp.encode!()
    {Connection.rpc(conn(), ["sendtransaction", rlp]), tx}
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
    create_transaction(callcode, opts)
  end

  def get_object(key) do
    Connection.rpc(conn(), ["getobject", key])
  end

  def get_node(key) do
    Connection.rpc(conn(), ["getnode", key])
  end

  def get_block_header(block_index) do
    cached_rpc(["getblockheader", block_index])
  end

  def get_state_roots(%{"number" => number, "state_hash" => hash}) do
    number = Rlpx.bin2uint(number)
    [roots] = cached_rpc(["getstateroots", number])
    assert_equal(hash, signature(roots))
    roots
  end

  def get_account(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)
    state_roots = Task.async(fn -> get_state_roots(peak) end)
    account = cached_rpc(["getaccount", peak_index, address])
    state_roots = Task.await(state_roots, :infinity)

    case account do
      # todo this needs a proof as well...
      [:error, "account does not exist"] ->
        %Account{
          nonce: 0,
          balance: 0,
          storage_root: nil,
          code_hash: Hash.keccak_256("")
        }

      [acc, proofs] when is_list(acc) ->
        acc = Rlpx.list2map(acc)

        acc = %Account{
          nonce: Rlpx.bin2uint(acc["nonce"]),
          balance: Rlpx.bin2uint(acc["balance"]),
          storage_root: acc["storage_root"],
          code_hash: acc["code"]
        }

        proof = proof(proofs, 0)
        # Checking that this proof connects to the root
        [prefix, pos | values] = value(proofs)
        assert_equal(proof, Enum.at(state_roots, pos))

        x = bit_size(prefix)
        k = Hash.sha3_256(address)
        <<key_prefix::bitstring-size(x), _::bitstring>> = k
        <<last_byte>> = binary_part(k, byte_size(k), -1)

        # Checking that the provided range is for the given keys prefix
        assert_equal(prefix, key_prefix)

        # Checking that the provided leaf matches the given key
        assert_equal(pos, rem(last_byte, 16))
        hash = :proplists.get_value(address, values)

        # Finally ensuring that the proofed value is our account hash
        assert_equal(hash, Account.hash(acc))
        acc
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

    root = Task.async(fn -> get_account_root(address, peak) end)
    [roots] = cached_rpc(["getaccountroots", peak_index, address])
    assert_equal(Task.await(root, :infinity), signature(roots))
    roots
  end

  def get_account_value(address, key = <<_::256>>, peak \\ peak())
      when is_binary(address) or is_integer(address) do
    hd(get_account_values(address, [key], peak))
  end

  def get_account_values(address, keys, peak \\ peak())
      when is_list(keys) and (is_binary(address) or is_integer(address)) do
    peak_index = peak_number(peak)
    address = Hash.to_address(address)
    roots = Task.async(fn -> get_account_roots(address, peak) end)

    values = cached_rpc(["getaccountvalues", peak_index, address | keys])
    roots = Task.await(roots, :infinity)

    case values do
      [:error, message] ->
        log("getaccountvalues #{inspect(keys)} produced error #{inspect(message)}")
        List.duplicate(nil, length(keys))

      [values] ->
        Enum.zip(values, keys)
        |> Enum.map(fn {proofs, key} ->
          proof = proof(proofs, 0)
          # Checking that this proof connects to the root
          [prefix, pos | values] = value(proofs)
          assert_equal(proof, Enum.at(roots, pos))

          x = bit_size(prefix)
          k = Hash.sha3_256(key)
          <<key_prefix::bitstring-size(x), _::bitstring>> = k
          <<last_byte>> = binary_part(k, byte_size(k), -1)

          # Checking that the provided range is for the given keys prefix
          assert_equal(key_prefix, prefix)

          # Checking that the provided leaf matches the given key
          assert_equal(pos, rem(last_byte, 16))
          :proplists.get_value(key, values)
        end)
    end
  end

  def peak() do
    Connection.peak(conn())
  end

  def peak_number(peak \\ peak()) do
    Rlpx.bin2uint(peak["number"])
  end

  defp cached_rpc(args) do
    ETSLru.fetch(ShellCache, args, fn ->
      # a = System.os_time(:millisecond)
      ret = Connection.rpc(conn(), args)
      # b = System.os_time(:millisecond)
      # Logger.debug("#{b - a}ms #{inspect(hd(args))}")
      ret
    end)
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

  defp create_transaction(data, opts) do
    wallet = DiodeClient.wallet()

    from = Wallet.address!(wallet)
    gas = Map.get(opts, :gas, 0x15F90)
    gas_price = Map.get(opts, :gas_price, 0x3B9ACA00)
    value = Map.get(opts, :value, 0x0)
    nonce = Map.get_lazy(opts, :nonce, fn -> get_account(from).nonce end)

    tx = %Transaction{
      to: nil,
      nonce: nonce,
      gasPrice: gas_price,
      gasLimit: gas,
      value: value,
      chain_id: @chain_id
    }

    case Map.get(opts, :to) do
      # Contract creation
      nil -> %Transaction{tx | init: data}
      # Normal transaction
      to -> %Transaction{tx | to: to, data: data}
    end
    |> Transaction.sign(Wallet.privkey!(wallet))
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
end
