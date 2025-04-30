defmodule EIP712Test do
  use ExUnit.Case
  doctest DiodeClient.EIP712
  alias DiodeClient.EIP712
  alias DiodeClient.Base16

  test "encode_type" do
    full_message = File.read!("test/testdata/typed_data_1.json") |> Jason.decode!()
    types = full_message["types"]

    full_message2 = File.read!("test/testdata/typed_data_2.json") |> Jason.decode!()
    types2 = full_message2["types"]

    # Testing type encoding
    assert EIP712.encode_type("EIP712Domain", types) ==
             "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

    assert EIP712.encode_type("Person", types) == "Person(string name,address wallet)"

    assert EIP712.encode_type("Mail", types) ==
             "Mail(Person from,Person to,string contents)Person(string name,address wallet)"

    assert EIP712.encode_type("EIP712Domain", types2) ==
             "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"

    assert EIP712.encode_type("Transaction", types2) ==
             "Transaction(address to,uint256 amount,bytes data,uint256 nonce)"

    assert EIP712.encode_type("TransactionApproval", types2) ==
             "TransactionApproval(address owner,Transaction transaction)Transaction(address to,uint256 amount,bytes data,uint256 nonce)"

    # Testing type hash
    assert Base16.encode(EIP712.type_hash("EIP712Domain", types)) ==
             "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"

    assert Base16.encode(EIP712.type_hash("Person", types)) ==
             "0xb9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c79500"

    assert Base16.encode(EIP712.type_hash("Mail", types)) ==
             "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"

    assert Base16.encode(EIP712.type_hash("EIP712Domain", types2)) ==
             "0xd87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472"

    assert Base16.encode(EIP712.type_hash("Transaction", types2)) ==
             "0xa826c254899945d99ae513c9f1275b904f19492f4438f3d8364fa98e70fbf233"

    assert Base16.encode(EIP712.type_hash("TransactionApproval", types2)) ==
             "0x5b360b7b2cc780b6a0687ac409805af3219ef7d9dcc865669e39a1dc7394ffc5"

    # Testing struct hash
    assert Base16.encode(EIP712.hash_struct("EIP712Domain", types, full_message["domain"])) ==
             "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"

    assert Base16.encode(EIP712.hash_struct("Person", types, full_message["message"]["from"])) ==
             "0xfc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8"

    assert Base16.encode(EIP712.hash_struct("Mail", types, full_message["message"])) ==
             "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"

    assert Base16.encode(EIP712.hash_struct("EIP712Domain", types2, full_message2["domain"])) ==
             "0x67083568259b4a947b02ce4dca4cc91f1e7f01d109c8805668755be5ab5adbb9"

    assert Base16.encode(
             EIP712.hash_struct("Transaction", types2, full_message2["message"]["transaction"])
           ) ==
             "0x9e7ba42b4ace63ae7d8ee163d5e642a085b32c2553717dcb37974e83fad289d0"

    assert Base16.encode(
             EIP712.hash_struct("TransactionApproval", types2, full_message2["message"])
           ) ==
             "0x309886ad75ec7c2c6a69bffa2669bad00e3b1e0a85221eff4e8926a2f8ff5077"

    # Testing typed data hash
    assert Base16.encode(EIP712.hash_typed_data(full_message, dump: true)) ==
             "0x1901f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090fc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"

    assert Base16.encode(EIP712.hash_typed_data(full_message)) ==
             "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
  end
end
