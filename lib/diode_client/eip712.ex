defmodule DiodeClient.EIP712 do
  @moduledoc """
    EIP-712 implementation

  ## Examples

      # Example 1: Using separate arguments
      iex> domain_data = %{
      ...>   "name" => "Ether Mail",
      ...>   "version" => "1",
      ...>   "chainId" => 1,
      ...>   "verifyingContract" => "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
      ...>   "salt" => "decafbeef"
      ...> }
      iex> message_types = %{
      ...>   "Person" => [
      ...>     %{"name" => "name", "type" => "string"},
      ...>     %{"name" => "wallet", "type" => "address"}
      ...>   ],
      ...>   "Mail" => [
      ...>     %{"name" => "from", "type" => "Person"},
      ...>     %{"name" => "to", "type" => "Person"},
      ...>     %{"name" => "contents", "type" => "string"}
      ...>   ]
      ...> }
      iex> message_data = %{
      ...>   "from" => %{
      ...>     "name" => "Cow",
      ...>     "wallet" => "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
      ...>   },
      ...>   "to" => %{
      ...>     "name" => "Bob",
      ...>     "wallet" => "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
      ...>   },
      ...>   "contents" => "Hello, Bob!"
      ...> }
      iex> hashed_message = DiodeClient.EIP712.hash_typed_data(%{
      ...>   "types" => message_types,
      ...>   "primaryType" => "Mail",
      ...>   "domain" => domain_data,
      ...>   "message" => message_data
      ...> })
      iex> DiodeClient.Base16.encode(hashed_message)
      "0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530"

      # Example 2: Using a single full message
      iex> full_message = %{
      ...>   "types" => %{
      ...>     "EIP712Domain" => [
      ...>       %{"name" => "name", "type" => "string"},
      ...>       %{"name" => "version", "type" => "string"},
      ...>       %{"name" => "chainId", "type" => "uint256"},
      ...>       %{"name" => "verifyingContract", "type" => "address"},
      ...>       %{"name" => "salt", "type" => "bytes32"}
      ...>     ],
      ...>     "Person" => [
      ...>       %{"name" => "name", "type" => "string"},
      ...>       %{"name" => "wallet", "type" => "address"}
      ...>     ],
      ...>     "Mail" => [
      ...>       %{"name" => "from", "type" => "Person"},
      ...>       %{"name" => "to", "type" => "Person"},
      ...>       %{"name" => "contents", "type" => "string"}
      ...>     ]
      ...>   },
      ...>   "primaryType" => "Mail",
      ...>   "domain" => %{
      ...>     "name" => "Ether Mail",
      ...>     "version" => "1",
      ...>     "chainId" => 1,
      ...>     "verifyingContract" => "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
      ...>     "salt" => "decafbeef"
      ...>   },
      ...>   "message" => %{
      ...>     "from" => %{
      ...>       "name" => "Cow",
      ...>       "wallet" => "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
      ...>     },
      ...>     "to" => %{
      ...>       "name" => "Bob",
      ...>       "wallet" => "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
      ...>     },
      ...>     "contents" => "Hello, Bob!"
      ...>   }
      ...> }
      iex> hashed_message = DiodeClient.EIP712.hash_typed_data(full_message)
      iex> DiodeClient.Base16.encode(hashed_message)
      "0xc5bb16ccc59ae9a3ad1cb8343d4e3351f057c994a97656e1aff8c134e56f7530"

  .. _EIP-712: https://eips.ethereum.org/EIPS/eip-712
  """
  alias DiodeClient.{ABI, Base16, Hash, Wallet}
  defstruct [:primary_type, :types, :message]

  def sign_typed_data(account_wallet, %{
        "types" => types,
        "primaryType" => primary_type,
        "domain" => domain,
        "message" => message
      }) do
    digest =
      hash_typed_data(%{
        "types" => types,
        "primaryType" => primary_type,
        "domain" => domain,
        "message" => message
      })

    Wallet.sign(account_wallet, digest, :none)
  end

  def hash_typed_data(
        %{
          "types" => types,
          "primaryType" => primary_type,
          "domain" => domain,
          "message" => message
        },
        opts \\ []
      ) do
    domain_separator = hash_domain_separator(domain)
    encode(domain_separator, primary_type, types, message, opts)
  end

  def encode(domain_separator, primary_type, type_data, message, opts \\ []) do
    raw = "\x19\x01" <> domain_separator <> hash_struct(primary_type, type_data, message)

    if opts[:dump] == true do
      raw
    else
      Hash.keccak_256(raw)
    end
  end

  # Special case for a flat EIP712 (no nested user types)
  def encode(domain_separator, primary_type, message) do
    {types, values} = split_fields(message)
    encode(domain_separator, primary_type, %{primary_type => types}, values)
  end

  def encode_type(primary_type, type_data) do
    prefix = encode_single_type(primary_type, Map.get(type_data, primary_type))

    types =
      Enum.map(type_data[primary_type], fn field ->
        case field do
          %{"type" => type} -> type
          {_, type} -> type
          {_, type, _} -> type
        end
      end)
      |> Enum.uniq()

    postfix =
      Enum.filter(type_data, fn
        {name, _} -> name != primary_type and name in types
      end)
      |> Enum.map(fn {name, fields} -> encode_single_type(name, fields) end)
      |> Enum.sort()
      |> Enum.join()

    prefix <> postfix
  end

  def encode_single_type(type, fields) do
    names =
      Enum.map(fields, fn field ->
        case field do
          %{"name" => name, "type" => type} -> "#{type} #{name}"
          {name, type} -> "#{type} #{name}"
          {name, type, _} -> "#{type} #{name}"
        end
      end)

    type <> "(" <> Enum.join(names, ",") <> ")"
  end

  def type_hash(primary_type, type_data) when is_map(type_data) do
    encode_type(primary_type, type_data) |> Hash.keccak_256()
  end

  @spec hash_struct(binary(), [{String.t(), String.t(), any()}]) :: binary()
  def hash_struct(primary_type, type_data) do
    {types, values} = split_fields(type_data)
    hash_struct(primary_type, %{primary_type => types}, values)
  end

  def hash_struct(primary_type, type_data, message) do
    encode_data =
      Enum.map(type_data[primary_type], fn field ->
        {name, type} =
          case field do
            %{"name" => name, "type" => type} -> {name, type}
            {name, type} -> {name, type}
          end

        value = Map.get(message, name)
        optimal_size = ABI.optimal_type_size(type)

        cond do
          value == nil ->
            raise "value for #{name} is required"

          type == "bytes" or type == "string" ->
            ABI.encode("bytes32", Hash.keccak_256(value))

          optimal_size != nil and byte_size(value) == optimal_size * 2 + 2 ->
            ABI.encode(type, Base16.decode(value))

          optimal_size != nil and type != "address" and byte_size(value) < optimal_size ->
            value = value <> :binary.copy(<<0>>, optimal_size - byte_size(value))
            ABI.encode(type, value)

          Map.has_key?(type_data, type) ->
            hash_struct(type, type_data, value)

          true ->
            ABI.encode(type, value)
        end
      end)
      |> Enum.filter(fn data -> data != nil end)
      |> Enum.join()

    Hash.keccak_256(type_hash(primary_type, type_data) <> encode_data)
  end

  def hash_domain_separator(values) do
    domain_fields =
      [
        {"name", "string"},
        {"version", "string"},
        {"chainId", "uint256"},
        {"verifyingContract", "address"},
        {"salt", "bytes32"}
      ]
      |> Enum.filter(fn {name, _} -> Map.has_key?(values, name) end)

    hash_struct("EIP712Domain", %{"EIP712Domain" => domain_fields}, values)
  end

  def hash_domain_separator(name, version, chain_id, verifying_contract)
      when is_binary(name) and is_binary(version) and is_integer(chain_id) and
             is_binary(verifying_contract) do
    hash_domain_separator(%{
      "name" => name,
      "version" => version,
      "chainId" => chain_id,
      "verifyingContract" => verifying_contract
    })
  end

  def hash_domain_separator(name, version, chain_id)
      when is_binary(name) and is_binary(version) and is_integer(chain_id) do
    hash_domain_separator(%{
      "name" => name,
      "version" => version,
      "chainId" => chain_id
    })
  end

  defp split_fields(fields) do
    {types, values} =
      Enum.map(fields, fn {name, type, value} ->
        {{name, type}, {name, value}}
      end)
      |> Enum.unzip()

    {types, Map.new(values)}
  end
end
