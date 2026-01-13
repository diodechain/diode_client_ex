defmodule ABITest do
  use ExUnit.Case
  alias DiodeClient.{Base16, Hash, Wallet, EIP712, ABI}

  test "reference" do
    assert EIP712.encode_single_type("Person", [
             {"name", "string"},
             {"wallet", "address"}
           ]) == "Person(string name,address wallet)"

    assert hex(
             EIP712.type_hash("Person", %{
               "Person" => [
                 {"name", "string"},
                 {"wallet", "address"}
               ]
             })
           ) == "0xb9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c79500"

    assert EIP712.encode_single_type("EIP712Domain", [
             {"name", "string"},
             {"version", "string"},
             {"chainId", "uint256"},
             {"verifyingContract", "address"}
           ]) ==
             "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

    assert EIP712.encode_type("Transaction", %{
             "Transaction" => [
               {"from", "Person"},
               {"to", "Person"},
               {"tx", "Asset"}
             ],
             "Person" => [
               {"wallet", "address"},
               {"name", "string"}
             ],
             "Asset" => [
               {"token", "address"},
               {"amount", "uint256"}
             ]
           }) ==
             "Transaction(Person from,Person to,Asset tx)Asset(address token,uint256 amount)Person(address wallet,string name)"

    domain_separator =
      EIP712.hash_struct("EIP712Domain", [
        {"name", "string", "Ether Mail"},
        {"version", "string", "1"},
        {"chainId", "uint256", 1},
        {"verifyingContract", "address", unhex("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")}
      ])

    assert hex(domain_separator) ==
             "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"

    assert EIP712.hash_domain_separator(
             "Ether Mail",
             "1",
             1,
             unhex("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
           ) == domain_separator

    assert hex(
             EIP712.encode(domain_separator, "Person", [
               {"name", "string", "Bob"},
               {"wallet", "address", unhex("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")}
             ])
           ) == "0x0a94cf6625e5860fc4f330d75bcd0c3a4737957d2321d1a024540ab5320fe903"
  end

  test "eip-712" do
    cow = Wallet.from_privkey(Hash.keccak_256("cow"))
    assert hex(Wallet.address!(cow)) == "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"

    type_data = %{
      "Person" => [
        {"name", "string"},
        {"wallet", "address"}
      ],
      "Mail" => [
        {"from", "Person"},
        {"to", "Person"},
        {"contents", "string"}
      ]
    }

    domain_separator =
      EIP712.hash_domain_separator(
        "Ether Mail",
        "1",
        1,
        unhex("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
      )

    digest =
      EIP712.encode(domain_separator, "Mail", type_data, %{
        "from" => %{
          "name" => "Cow",
          "wallet" => unhex("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
        },
        "to" => %{
          "name" => "Bob",
          "wallet" => unhex("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
        },
        "contents" => "Hello, Bob!"
      })

    assert hex(Wallet.sign(cow, digest, :none)) ==
             "0x014355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562"
  end

  test "encoding / decoding" do
    assert encode("uint256", 1) ==
             "0x0000000000000000000000000000000000000000000000000000000000000001"

    assert decode("uint256", "0x0000000000000000000000000000000000000000000000000000000000000001") ==
             {1, ""}

    assert encode("int256", -1) ==
             "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    assert decode("int256", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") ==
             {-1, ""}

    assert encode("bool", true) ==
             "0x0000000000000000000000000000000000000000000000000000000000000001"

    assert decode("bool", "0x0000000000000000000000000000000000000000000000000000000000000001") ==
             {1, ""}

    assert encode("bool", false) ==
             "0x0000000000000000000000000000000000000000000000000000000000000000"
  end

  test "array encoding / decoding" do
    result =
      "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"

    assert hex(ABI.encode_args(["uint256[]"], [[1, 2]])) == result
    assert ABI.decode_args(["uint256[]"], unhex(result)) == [[1, 2]]

    assert equality("uint256[]", [1, 2])

    assert equality("address[]", [
             unhex("0x0000000000000000000000000000000000000001"),
             unhex("0x0000000000000000000000000000000000000002")
           ])
  end

  test "tuple encoding / decoding" do
    assert encode("(address,uint256)", [0x1, 2]) ==
             "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"

    item = [unhex("0x0000000000000000000000000000000000000001"), 2]
    assert equality("(address,uint256)", item)
  end

  test "nested tuple encoding / decoding" do
    assert encode("((address,uint256))", [[0x1, 2]]) ==
             "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"

    item = [[<<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>, 2]]
    assert equality("((address,uint256))", item)
  end

  test "tuple array encoding / decoding" do
    item = [unhex("0x0000000000000000000000000000000000000001"), 2]

    assert encode("(address,uint256)[]", [item, item]) ==
             "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"

    assert decode(
             "(address,uint256)[]",
             "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
           ) == {[item, item], ""}

    assert equality("(address,uint256)[]", [item, item])
  end

  test "dynamic array encoding / decoding" do
    assert hex(ABI.encode_args(["bytes", "bytes[]"], ["hello", ["world", "!"]])) ==
             "0x00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000568656c6c6f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000005776f726c6400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012100000000000000000000000000000000000000000000000000000000000000"

    assert equality("(bytes, bytes[])", ["hello", ["world", "!"]])
  end

  test "dynamic tuple encoding / decoding" do
    w1 = DiodeClient.Wallet.from_privkey(Hash.keccak_256("w1")) |> DiodeClient.Wallet.address!()
    w2 = DiodeClient.Wallet.from_privkey(Hash.keccak_256("w2")) |> DiodeClient.Wallet.address!()
    w3 = DiodeClient.Wallet.from_privkey(Hash.keccak_256("w3")) |> DiodeClient.Wallet.address!()

    item = [[w1, 1, [w2, w3]]]

    ref1 =
      "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000003d2bca6abe6eeafba2b70efa6cf736fb5152fc23000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000002000000000000000000000000696b11d329404791fb2004b68cc2849c027edb2e000000000000000000000000e6ac36f4ab100d21475d3411e8a173ffffa06747"

    assert hex(ABI.encode_args(["(address,uint256,address[])[]"], [item])) ==
             ref1

    ref2 =
      "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000015b3598b77a04e4fcce7b8efd622f70e3459a0b500000000000000000000000000000000000000000000000000000000000001f400000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"

    item2 = [
      <<21, 179, 89, 139, 119, 160, 78, 79, 204, 231, 184, 239, 214, 34, 247, 14, 52, 89, 160,
        181>>,
      500,
      []
    ]

    assert ABI.decode_args(["(address,uint256,address[])[]"], unhex(ref2)) == [[item2]]
  end

  defp equality(type, value) do
    assert decode(type, encode(type, value)) == {value, ""}
  end

  defp encode(type, value), do: hex(ABI.encode(type, value))
  defp decode(type, value), do: ABI.decode(type, unhex(value))
  defp hex(x), do: Base16.encode(x)
  defp unhex(x), do: Base16.decode(x)
end
