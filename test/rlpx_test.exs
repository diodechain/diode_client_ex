defmodule DiodeClientRlpxTest do
  alias DiodeClient.{Rlp, Rlpx}
  use ExUnit.Case

  test "list2map" do
    input = %{files: [%{label: "one", hash: <<1>>}, %{label: "two", hash: <<2>>}]}

    assert Rlpx.list2map(Rlp.encode!(input) |> Rlp.decode!(), atoms: true, recursive: true) ==
             input

    output = %{
      files: [%{"label" => "one", "hash" => <<1>>}, %{"label" => "two", "hash" => <<2>>}]
    }

    assert Rlpx.list2map(Rlp.encode!(input) |> Rlp.decode!(), atoms: 1, recursive: true) == output
  end

  test "list2map empty lists/maps" do
    input_map = %{files: %{}}
    input_list = %{files: []}

    assert Rlpx.list2map(Rlp.encode!(input_map) |> Rlp.decode!(), atoms: 1, recursive: true) ==
             input_map

    assert Rlpx.list2map(Rlp.encode!(input_list) |> Rlp.decode!(), atoms: 1, recursive: true) ==
             input_map
  end
end
