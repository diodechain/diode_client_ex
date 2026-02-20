defmodule DiodeClient.Shell.OasisSapphire do
  @moduledoc """
   Specialized shell for Oasis Sapphire.
  """

  alias DiodeClient.{
    ABI,
    Account,
    Base16,
    Block,
    Hash,
    Transaction,
    Rlpx,
    Shell,
    Wallet
  }

  require Logger
  use DiodeClient.Shell.Common

  def block_time(), do: :timer.seconds(6)
  def chain_id(), do: 23_294
  def prefix(), do: "sapphire:"
  @gas_limit 10_000_000
  def default_gas_limit(), do: @gas_limit

  def blockexplorer_url(opts \\ []) do
    cond do
      opts[:address] != nil ->
        "https://explorer.oasis.io/mainnet/sapphire/address/#{maybe_hex(opts[:address])}"

      opts[:tx] != nil ->
        "https://explorer.oasis.io/mainnet/sapphire/tx/#{maybe_hex(opts[:tx])}"

      true ->
        "https://explorer.oasis.io/mainnet/sapphire"
    end
  end

  defp maybe_hex(x = "0x" <> _), do: x
  defp maybe_hex(x), do: DiodeClient.Base16.encode(x, false)

  def send_transaction(address, function_name, types, values, opts \\ [])
      when is_list(types) and is_list(values) do
    meta_transaction = Keyword.get(opts, :meta_transaction, false)

    if meta_transaction do
      wallet = DiodeClient.ensure_wallet()
      from = Wallet.address!(wallet)
      nonce = Keyword.get(opts, :nonce) || get_meta_nonce(from)

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
    opts = Keyword.put(opts, :from, identity_address(opts))
    Shell.Common.create_meta_transaction(__MODULE__, address, callcode, nonce, opts)
  end

  def get_meta_nonce(address, peak \\ peak(), opts \\ []) do
    id = identity_address(opts)

    call(id, "Nonce", ["address"], [address],
      block: peak,
      result_types: "uint"
    )
    |> case do
      nonce when is_integer(nonce) ->
        nonce

      :revert ->
        Logger.warning("Identity contract at #{DiodeClient.Base16.encode(id)} reverted")
        0
    end
  end

  def get_account(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)
    [acc] = cached_rpc([prefix() <> "getaccount", peak_index, address])
    acc = Rlpx.list2map(acc)

    %Account{
      nonce: Rlpx.bin2uint(acc["nonce"]),
      balance: Rlpx.bin2uint(acc["balance"]),
      storage_root: Rlpx.bin2addr(acc["storage_root"]),
      code_hash: acc["code"]
    }
  end

  def get_account_root(address, peak \\ peak()) do
    peak_index = Rlpx.bin2uint(peak["number"])
    address = Hash.to_address(address)

    case cached_rpc([prefix() <> "getaccountroot", peak_index, address]) do
      nil -> nil
      [""] -> nil
      [root] -> root
    end
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
    values = cached_rpc([prefix() <> "getaccountvalues", peak_index, address | keys])

    case values do
      {:error, message} ->
        Logger.debug(
          "getaccountvalues #{inspect({peak_index, address, keys})} produced error #{inspect(message)}"
        )

        raise "getaccountvalues #{inspect({peak_index, address, keys})} produced error #{inspect(message)}"

      [values] ->
        # Diode L1 can differentiate between unset (empty) values and all zero
        # values -- this is not the case for moonbeam. So to make signup name checks
        # succeed here we're checking that the value is not all zero.

        Enum.map(values, fn value ->
          if value == <<0::unsigned-size(256)>> do
            :undefined
          else
            value
          end
        end)
    end
  end

  def oasis_call_data_public_key() do
    # with [json] <- rpc([prefix() <> "rpc", "oasis_callDataPublicKey", "[]"]) do
    #   case Jason.decode!(json) do
    #     %{"result" => result} -> result
    #     %{"error" => error} ->
    #       Logger.error("Error #{prefix()}.oasis_call_data_public_key: #{inspect(error)}")
    #       nil
    #   end
    # end
    # https://api.docs.oasis.io/sol/sapphire-contracts/contracts/Subcall.sol/library.Subcall.html
    contract = DiodeClient.Base16.decode("0x0100000000000000000000000000000000000103")

    # data = DiodeClient.ABI.encode_args(["string", "bytes"], ["core.CallDataPublicKey", CBOR.encode(nil)])
    data =
      DiodeClient.Base16.decode(
        "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000016636f72652e43616c6c446174615075626c69634b6579000000000000000000000000000000000000000000000000000000000000000000000000000000000001f600000000000000000000000000000000000000000000000000000000000000"
      )

    opts = %{sign: false}
    tx = DiodeClient.Shell.Common.create_transaction(__MODULE__, contract, data, opts)

    [status, cbor] =
      DiodeClient.Shell.Common.call_tx(__MODULE__, tx,
        block: "latest",
        result_types: ["uint", "bytes"]
      )

    if status == 0 do
      {:ok,
       %{
         "epoch" => epoch,
         "public_key" => %{
           "key" => %CBOR.Tag{value: key},
           "expiration" => expiration,
           "signature" => %CBOR.Tag{value: signature}
         }
       }, ""} = CBOR.decode(cbor)

      %{"epoch" => epoch, "key" => key, "expiration" => expiration, "signature" => signature}
    else
      {:error, "Failed to get call data public key. Status: #{status}"}
    end
  end

  def call(address, method, types, args, opts \\ []) do
    tx = create_transaction(address, method, types, args)
    oasis_call(tx, opts)
  end

  defp prepare_signed_call(transaction, opts) do
    # For some reason calls to blocks with higher numbers are getting this error:
    #  roothash: block not found: client: failed to fetch annotated block from history: roothash: block not found
    # So we stay back by two blocks to avoid this issue.
    max_block = peak_number() - 2

    block =
      case Keyword.get(opts, :block) do
        nil -> get_block_header(max_block)
        "latest" -> get_block_header(max_block)
        block when is_integer(block) -> min(block, max_block)
        block when is_map(block) -> get_block_header(min(Block.number(block), max_block))
      end

    block_number = Block.number(block) + 1
    block_hash = block["block_hash"]

    sig_opts = [
      gas: transaction.gasLimit,
      gas_price: transaction.gasPrice,
      to: transaction.to,
      nonce: transaction.nonce,
      block_number: block_number,
      block_hash: block_hash,
      from: Transaction.from(transaction)
    ]

    call =
      DiodeClient.OasisSapphire.new_signed_call_data_pack(
        DiodeClient.ensure_wallet(),
        transaction.data,
        sig_opts
      )

    %{call: call, block_number: block_number}
  end

  def oasis_call(transaction, opts \\ []) do
    %{call: call, block_number: block_number} =
      prepare_signed_call(transaction, opts)

    params =
      [
        %{
          from: Base16.encode(Transaction.from(transaction)),
          to: Base16.encode(transaction.to),
          value: Base16.encode(transaction.value, short: true),
          data: Base16.encode(call.data_pack),
          gas: Base16.encode(call.msg["gasLimit"], short: true),
          gasPrice: Base16.encode(call.msg["gasPrice"], short: true)
        },
        Base16.encode(block_number + 1)
      ]
      |> Jason.encode!()

    with [json] <- cached_rpc([prefix() <> "rpc", "eth_call", params]),
         {:ok, %{"result" => result}} <- Jason.decode(json),
         cbor <-
           DiodeClient.OasisSapphire.decrypt_data_pack_response(call, Base16.decode(result)),
         {:ok, %{"ok" => %CBOR.Tag{value: data}}, ""} <- CBOR.decode(cbor) do
      DiodeClient.Shell.Common.decode_result(data, Keyword.get(opts, :result_types))
    else
      {:error, reason} ->
        {:error, reason}

      {:ok, %{"error" => error}} ->
        {:error, error}
    end
  end

  def encrypt_transaction(tx) do
    %{tx | data: DiodeClient.OasisSapphire.encrypt_data(DiodeClient.Transaction.payload(tx))}
  end

  def raw_call(address, method, types, args, opts \\ []) do
    DiodeClient.Shell.Common.call(__MODULE__, address, method, types, args, opts)
  end

  defp identity_address(opts) do
    identity =
      opts[:identity] ||
        raise "Missing :identity parameter, define or use the default `DiodeClient.Contracts.Factory.identity_address(DiodeClient.Shell.OasisSapphire)`"

    if !is_binary(identity) or byte_size(identity) != 20 do
      raise "Invalid :identity parameter, sould be a 20 byte public address"
    end

    identity
  end
end
