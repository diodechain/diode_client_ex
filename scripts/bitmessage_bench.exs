alias DiodeClient.{BitMessage, Wallet}

wallet = Wallet.new()
small_message = "This is a super secret message just for you"
bm_small = BitMessage.encrypt(small_message, wallet)
large_message = String.duplicate(small_message, 30) |> String.pad_trailing(1376)
bm_large = BitMessage.encrypt(large_message, wallet)

Benchee.run(%{
  "encrypt small" => fn ->
    BitMessage.encrypt(small_message, wallet)
  end,
  "encrypt large" => fn ->
    BitMessage.encrypt(large_message, wallet)
  end,
  "decrypt_small" => fn ->
    BitMessage.decrypt(bm_small, wallet)
  end,
  "decrypt_large" => fn ->
    BitMessage.decrypt(bm_large, wallet)
  end
})

# Last result encrypt_large => 1.43k ips single core
# 1.43k * 1376 bytes = 1.97 MB/s
