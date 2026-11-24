defmodule DiodeClient.Shell.OasisSapphireTest do
  use ExUnit.Case, async: false

  alias DiodeClient.{
    ABI,
    Base16,
    ETSLru,
    OasisSapphire,
    ShellCache,
    TestValues,
    Transaction,
    Wallet
  }

  alias DiodeClient.Shell.OasisSapphire, as: Sapphire

  describe "signed_call_block_index/2" do
    test "uses head minus two when no block is passed" do
      assert Sapphire.signed_call_block_index([], 15_459_735) == 15_459_733
    end

    test "uses head minus two for latest block opt" do
      assert Sapphire.signed_call_block_index([block: "latest"], 15_459_735) == 15_459_733
    end

    test "ignores stale PeakBlock header far behind the live head" do
      stale = %{"number" => :binary.encode_unsigned(15_459_680, :big)}

      assert Sapphire.signed_call_block_index([block: stale], 15_459_735) == 15_459_733
    end

    test "accepts a recent block header within the leash range" do
      recent = %{"number" => :binary.encode_unsigned(15_459_730, :big)}

      assert Sapphire.signed_call_block_index([block: recent], 15_459_735) == 15_459_730
    end

    test "caps an integer block at head minus two" do
      assert Sapphire.signed_call_block_index([block: 99_999_999], 15_459_735) == 15_459_733
    end

    test "uses head minus two when integer block is too stale" do
      assert Sapphire.signed_call_block_index([block: 15_459_680], 15_459_735) == 15_459_733
    end
  end

  describe "unexpected_base_block_error?/1" do
    test "matches Sapphire unexpected base block error message" do
      assert Sapphire.unexpected_base_block_error?(
               "invalid signed simulate call query: unexpected base block"
             )
    end

    test "rejects unrelated errors and non-binaries" do
      refute Sapphire.unexpected_base_block_error?("execution reverted")
      refute Sapphire.unexpected_base_block_error?(nil)
      refute Sapphire.unexpected_base_block_error?(:unexpected_base_block)
    end
  end

  describe "canonical_anchor_hash/2" do
    test "prefers 32-byte previous_block from anchor + 1" do
      anchor = %{"block_hash" => <<1::256>>}
      next = %{"previous_block" => <<2::256>>}

      assert Sapphire.canonical_anchor_hash(anchor, next) == <<2::256>>
    end

    test "falls back to anchor block_hash when next header lacks 32-byte previous_block" do
      anchor = %{"block_hash" => <<1::256>>}

      assert Sapphire.canonical_anchor_hash(anchor, nil) == <<1::256>>
      assert Sapphire.canonical_anchor_hash(anchor, %{"previous_block" => <<>>}) == <<1::256>>
    end
  end

  describe "OasisSapphire.oasis_call_data_public_key/0" do
    setup do
      TestValues.clear()
      on_exit(&TestValues.clear/0)
      :ok
    end

    test "returns {key, epoch} from TestValues without invoking RPC" do
      key = <<9::256>>
      TestValues.put(:oasis_peer_pubkey, key)
      TestValues.put(:oasis_epoch, 42)

      assert OasisSapphire.oasis_call_data_public_key() == {key, 42}
    end
  end

  describe "oasis_call/2 cache eviction and retry" do
    setup do
      TestValues.clear()

      fallback_wallet = Wallet.from_privkey(Base16.decode("0x" <> String.duplicate("1", 64)))
      _ = DiodeClient.set_wallet(fallback_wallet)
      wallet = DiodeClient.ensure_wallet()

      TestValues.put(
        :oasis_nonce,
        <<244, 7, 0, 149, 137, 156, 150, 196, 231, 103, 211, 41, 245, 38, 180>>
      )

      TestValues.put(
        :oasis_peer_pubkey,
        Base16.decode("0x4e0c4c5a0399453a9d3e858290dcd2483ef2b0afc9d87ba71aed140e96f27b5f")
      )

      TestValues.put(
        :oasis_epheremal_key,
        {Base16.decode("0xa91df693eb664b5e2d56d3d979fee99ba3507f0a24e26e2a4a485b12d2fa148b"),
         Base16.decode("0x774605fdf528dfa0cc7da0c92daf2a6cc711bc45a422311b378d031c82c19c50")}
      )

      TestValues.put(:oasis_epoch, 40_662)

      on_exit(fn ->
        TestValues.clear()
        ETSLru.flush(ShellCache)
      end)

      {:ok, wallet: wallet}
    end

    test "evicts poisoned header and eth_call error then retries with canonical hash", %{
      wallet: wallet
    } do
      anchor_index = 16_789_811
      poisoned_hash = <<1::256>>
      canonical_hash = <<2::256>>
      contract = Base16.decode("0x6cbf10355f8a16f7cd2f7aa762c08374959ce1bd")
      from = Wallet.address!(wallet)
      callcode = ABI.encode_call("ResolveReverse", ["address"], [<<3::160>>])

      tx = %Transaction{
        to: contract,
        nonce: 0,
        gasPrice: 0,
        gasLimit: 10_000_000,
        value: 0,
        chain_id: Sapphire.chain_id(),
        data: callcode,
        signature: {:fake, from}
      }

      anchor_header = %{
        "number" => :binary.encode_unsigned(anchor_index, :big),
        "block_hash" => poisoned_hash
      }

      next_header = %{
        "number" => :binary.encode_unsigned(anchor_index + 1, :big),
        "previous_block" => canonical_hash
      }

      poisoned_key = {Sapphire, ["sapphire:getblockheader", anchor_index]}
      next_key = {Sapphire, ["sapphire:getblockheader", anchor_index + 1]}
      ETSLru.put(ShellCache, poisoned_key, [anchor_header])
      ETSLru.put(ShellCache, next_key, [next_header])

      poisoned_call =
        OasisSapphire.new_signed_call_data_pack(wallet, callcode,
          gas: tx.gasLimit,
          gas_price: tx.gasPrice,
          to: tx.to,
          nonce: tx.nonce,
          block_number: anchor_index + 1,
          block_hash: poisoned_hash,
          from: from
        )

      canonical_call =
        OasisSapphire.new_signed_call_data_pack(wallet, callcode,
          gas: tx.gasLimit,
          gas_price: tx.gasPrice,
          to: tx.to,
          nonce: tx.nonce,
          block_number: anchor_index + 1,
          block_hash: canonical_hash,
          from: from
        )

      poisoned_cmd = eth_call_cmd(from, tx, poisoned_call)
      canonical_cmd = eth_call_cmd(from, tx, canonical_call)

      ETSLru.put(ShellCache, {Sapphire, poisoned_cmd}, [
        Jason.encode!(%{
          "error" => %{
            "code" => -32_000,
            "message" => "invalid signed simulate call query: unexpected base block"
          }
        })
      ])

      # Simulate second attempt still hitting an error (e.g. non-retryable) so we prove
      # the retry ran with canonical_hash without needing live DeoxysII server encryption.
      ETSLru.put(ShellCache, {Sapphire, canonical_cmd}, [
        Jason.encode!(%{"error" => %{"code" => -32_000, "message" => "canonical retry hit"}})
      ])

      assert {:error, %{"message" => "canonical retry hit"}} =
               Sapphire.oasis_call(tx, head_block: anchor_index + 2)

      assert ETSLru.get(ShellCache, poisoned_key) == nil
      assert ETSLru.get(ShellCache, {Sapphire, poisoned_cmd}) == nil
    end

    defp eth_call_cmd(from, tx, call) do
      params =
        [
          %{
            from: Base16.encode(from),
            to: Base16.encode(tx.to),
            value: Base16.encode(tx.value, short: true),
            data: Base16.encode(call.data_pack),
            gas: Base16.encode(call.msg["gasLimit"], short: true),
            gasPrice: Base16.encode(call.msg["gasPrice"], short: true)
          },
          "latest"
        ]
        |> Jason.encode!()

      ["sapphire:rpc", "eth_call", params]
    end
  end
end
