defmodule DiodeClient.OasisSapphireIntegrationTest do
  @moduledoc """
  Opt-in validation against the public Oasis Sapphire RPC.

  Run with `OASIS_INTEGRATION=1 mix test test/oasis_sapphire_integration_test.exs`.
  """
  use ExUnit.Case, async: false

  alias DiodeClient.{ABI, Base16, OasisSapphire, TestValues, Wallet}
  alias DiodeClient.Shell.OasisSapphire, as: Sapphire

  @moduletag oasis: true
  @moduletag timeout: 60_000
  @moduletag skip: System.get_env("OASIS_INTEGRATION") != "1"

  @bns_contract Base16.decode("0x6CBF10355F8A16F7CD2F7AA762C08374959CE1BD")
  @resolve_address Base16.decode("0x0000000000000000000000000000000000000001")
  @private_key Base16.decode("0x" <> String.duplicate("1", 64))

  setup do
    TestValues.clear()
    on_exit(&TestValues.clear/0)
  end

  test "refreshes a stale anchor and rejects a non-canonical base hash" do
    configure_sapphire()
    wallet = Wallet.from_privkey(@private_key)
    from = Wallet.address!(wallet)
    data = ABI.encode_call("ResolveReverse", ["address"], [@resolve_address])
    head = Base16.decode_int(rpc!("eth_blockNumber", [])["result"])

    stale_anchor = head - 100
    stale_header = block_header!(stale_anchor)

    stale_call =
      signed_call(
        wallet,
        from,
        data,
        stale_anchor,
        Base16.decode(stale_header["hash"]),
        1
      )

    assert %{
             "error" => %{
               "message" => <<"invalid signed simulate call query:", _::binary>>
             }
           } = rpc!("eth_call", [call_params(stale_call, from), "latest"])

    fresh_anchor = Sapphire.signed_call_block_index([block: stale_header], head)
    assert fresh_anchor == head - 2

    fresh_header = block_header!(fresh_anchor)

    fresh_call =
      signed_call(
        wallet,
        from,
        data,
        fresh_anchor,
        Base16.decode(fresh_header["hash"]),
        2
      )

    assert is_binary(resolve_reverse!(fresh_call, from))

    wrong_hash_call =
      signed_call(wallet, from, data, fresh_anchor, <<0::256>>, 3)

    assert %{
             "error" => %{
               "message" => "invalid signed simulate call query: unexpected base block"
             }
           } = rpc!("eth_call", [call_params(wrong_hash_call, from), "latest"])
  end

  defp configure_sapphire do
    %{"result" => %{"key" => key, "epoch" => epoch}} =
      rpc!("oasis_callDataPublicKey", [])

    TestValues.put(:oasis_peer_pubkey, Base16.decode(key))
    TestValues.put(:oasis_epoch, epoch)
  end

  defp block_header!(number) do
    %{"result" => header} =
      rpc!("eth_getBlockByNumber", [Base16.encode(number, short: true), false])

    assert is_map(header)
    header
  end

  defp signed_call(wallet, from, data, block_number, block_hash, nonce) do
    OasisSapphire.new_signed_call_data_pack(wallet, data,
      gas: 10_000_000,
      to: @bns_contract,
      nonce: nonce,
      block_number: block_number + 1,
      block_hash: block_hash,
      from: from
    )
  end

  defp resolve_reverse!(call, from) do
    %{"result" => result} = rpc!("eth_call", [call_params(call, from), "latest"])
    cbor = OasisSapphire.decrypt_data_pack_response(call, Base16.decode(result))
    {:ok, %{"ok" => %CBOR.Tag{value: data}}, ""} = CBOR.decode(cbor)
    ABI.decode_args(["string"], data) |> List.first()
  end

  defp call_params(call, from) do
    %{
      from: Base16.encode(from),
      to: Base16.encode(@bns_contract),
      value: Base16.encode(0, short: true),
      data: Base16.encode(call.data_pack),
      gas: Base16.encode(call.msg["gasLimit"], short: true),
      gasPrice: Base16.encode(call.msg["gasPrice"], short: true)
    }
  end

  defp rpc!(method, params) do
    body = Jason.encode!(%{jsonrpc: "2.0", id: 1, method: method, params: params})

    request =
      {String.to_charlist(System.get_env("OASIS_RPC_URL", "https://sapphire.oasis.io")),
       [
         {~c"content-type", ~c"application/json"},
         {~c"user-agent", ~c"diode-client-test"}
       ], ~c"application/json", body}

    case :httpc.request(:post, request, [timeout: 20_000], []) do
      {:ok, {{_, 200, _}, _, response}} ->
        Jason.decode!(response)

      {:ok, {{_, status, reason}, _, _response}} ->
        flunk("Oasis RPC returned HTTP #{status} #{reason}")

      {:error, reason} ->
        flunk("Oasis RPC request failed: #{inspect(reason)}")
    end
  end
end
