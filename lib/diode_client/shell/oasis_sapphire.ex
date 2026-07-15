defmodule DiodeClient.Shell.OasisSapphire do
  @moduledoc """
  Specialized shell for Oasis Sapphire.
  """

  alias DiodeClient.{
    Base16,
    Block,
    Transaction
  }

  use DiodeClient.Shell.Common, meta_transactions: :identity

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

  def oasis_call_data_public_key() do
    # https://api.docs.oasis.io/sol/sapphire-contracts/contracts/Subcall.sol/library.Subcall.html
    contract = DiodeClient.Base16.decode("0x0100000000000000000000000000000000000103")

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
        nil -> max_block
        "latest" -> max_block
        block when is_integer(block) -> min(block, max_block)
        block when is_map(block) -> min(Block.number(block), max_block)
      end
      |> get_block_header()

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
end
