defmodule DiodeClient.Transaction do
  @moduledoc false
  alias DiodeClient.{Base16, Hash, Rlp, Rlpx, Secp256k1, Transaction, Wallet}

  @enforce_keys [:chain_id]
  defstruct nonce: 1,
            gasPrice: 0,
            gasLimit: 0,
            to: nil,
            value: 0,
            chain_id: nil,
            signature: nil,
            init: nil,
            data: nil,
            # eip-1559,
            version: 0,
            max_priority_fee_per_gas: 0,
            # gasPrice is used as 'max_fee_per_gas'
            access_list: []

  @type t :: %Transaction{}

  def nonce(%Transaction{nonce: nonce}), do: nonce
  def data(%Transaction{data: nil}), do: ""
  def data(%Transaction{data: data}), do: data
  def gas_price(%Transaction{gasPrice: gas_price}), do: gas_price
  def gas_limit(%Transaction{gasLimit: gas_limit}), do: gas_limit
  def value(%Transaction{value: val}), do: val
  def signature(%Transaction{signature: sig}), do: sig
  def payload(%Transaction{to: nil, init: nil}), do: ""
  def payload(%Transaction{to: nil, init: init}), do: init
  def payload(%Transaction{data: nil}), do: ""
  def payload(%Transaction{data: data}), do: data
  def to(tx = %Transaction{to: nil}), do: new_contract_address(tx)
  def to(%Transaction{to: to}), do: to
  def chain_id(%Transaction{chain_id: chain_id}), do: chain_id

  @spec from_rlp(binary()) :: Transaction.t()
  def from_rlp(bin) do
    [nonce, gas_price, gas_limit, to, value, init, rec, r, s] = Rlp.decode!(bin)

    to = Rlpx.bin2addr(to)

    %Transaction{
      nonce: Rlpx.bin2uint(nonce),
      gasPrice: Rlpx.bin2uint(gas_price),
      gasLimit: Rlpx.bin2uint(gas_limit),
      to: to,
      value: Rlpx.bin2uint(value),
      init: if(to == nil, do: init, else: nil),
      data: if(to != nil, do: init, else: nil),
      signature: Secp256k1.rlp_to_bitcoin(rec, r, s),
      chain_id: Secp256k1.chain_id(rec)
    }
  end

  @spec print(DiodeClient.Transaction.t()) :: :ok
  def print(tx) do
    hash = Base16.encode(hash(tx))
    from = Base16.encode(from(tx))
    to = Base16.encode(to(tx))
    type = Atom.to_string(type(tx))
    value = value(tx)
    code = Base16.encode(payload(tx))
    nonce = nonce(tx)

    code =
      if byte_size(code) > 40 do
        binary_part(code, 0, 37) <> "... [#{byte_size(code)}]"
      end

    IO.puts("")
    IO.puts("\tTransaction: #{hash} Type: #{type}")
    IO.puts("\tFrom:        #{from} (#{nonce}) To: #{to}")
    IO.puts("\tValue:       #{value} Code: #{code}")

    # rlp = to_rlp(tx) |> Rlp.encode!()
    # IO.puts("\tRLP:          #{Base16.encode(rlp)}")
    :ok
  end

  @spec valid?(DiodeClient.Transaction.t()) :: boolean()
  def valid?(tx) do
    validate(tx) == true
  end

  @spec type(DiodeClient.Transaction.t()) :: :call | :create
  def type(tx) do
    if contract_creation?(tx) do
      :create
    else
      :call
    end
  end

  @spec validate(DiodeClient.Transaction.t()) :: true | {non_neg_integer(), any()}
  def validate(tx) do
    with {1, %Transaction{}} <- {1, tx},
         {2, 65} <- {2, byte_size(signature(tx))},
         {4, true} <- {4, value(tx) >= 0},
         {5, true} <- {5, gas_price(tx) >= 0},
         {6, true} <- {6, gas_limit(tx) >= 0},
         {7, true} <- {7, byte_size(payload(tx)) >= 0} do
      true
    else
      {nr, error} -> {nr, error}
    end
  end

  @spec contract_creation?(DiodeClient.Transaction.t()) :: boolean()
  def contract_creation?(%Transaction{to: to}) do
    to == nil
  end

  @spec new_contract_address(DiodeClient.Transaction.t()) :: binary()
  def new_contract_address(%Transaction{to: to}) when to != nil do
    nil
  end

  def new_contract_address(tx = %Transaction{nonce: nonce}) do
    address = Wallet.address!(origin(tx))

    Rlp.encode!([address, nonce])
    |> Hash.keccak_256()
    |> Hash.to_address()
  end

  def to_binary(tx = %Transaction{version: 2}) do
    rlp = to_rlp(tx) |> Rlp.encode!()
    <<0x02>> <> rlp
  end

  def to_binary(tx = %Transaction{version: 0}) do
    to_rlp(tx) |> Rlp.encode!()
  end

  def max_fee_per_gas(tx) do
    tx.gasPrice + tx.max_priority_fee_per_gas
  end

  @spec to_rlp(DiodeClient.Transaction.t()) :: [...]
  def to_rlp(tx = %Transaction{version: 2}) do
    <<rec, r::big-unsigned-size(256), s::big-unsigned-size(256)>> = tx.signature

    [
      tx.chain_id,
      tx.nonce,
      tx.max_priority_fee_per_gas,
      max_fee_per_gas(tx),
      tx.gasLimit,
      tx.to,
      tx.value,
      payload(tx),
      tx.access_list,
      rec,
      r,
      s
    ]
  end

  def to_rlp(tx) do
    [tx.nonce, gas_price(tx), gas_limit(tx), tx.to, tx.value, payload(tx)] ++
      Secp256k1.bitcoin_to_rlp(tx.signature, tx.chain_id)
  end

  @spec from(DiodeClient.Transaction.t()) :: <<_::160>>
  def from(tx) do
    Wallet.address!(origin(tx))
  end

  @spec recover(DiodeClient.Transaction.t()) :: binary()
  def recover(tx) do
    Secp256k1.recover!(signature(tx), to_message(tx), :kec)
  end

  @spec origin(DiodeClient.Transaction.t()) :: Wallet.t()
  def origin(%Transaction{signature: {:fake, pubkey}}) do
    Wallet.from_address(pubkey)
  end

  def origin(tx) do
    recover(tx) |> Wallet.from_pubkey()
  end

  @spec sign(DiodeClient.Transaction.t(), <<_::256>>) :: DiodeClient.Transaction.t()
  def sign(tx = %Transaction{}, priv) do
    %{tx | signature: Secp256k1.sign(priv, to_message(tx), :kec)}
  end

  def hash(tx = %Transaction{signature: {:fake, _pubkey}}) do
    to_message(tx) |> hash(chain_id(tx))
  end

  @spec hash(Transaction.t()) :: binary()
  def hash(tx) do
    to_binary(tx) |> hash(chain_id(tx))
  end

  defp hash(binary, chain_id) do
    if chain_id in [nil, 0, 13, 15] do
      Hash.sha3_256(binary)
    else
      Hash.keccak_256(binary)
    end
  end

  @spec to_message(DiodeClient.Transaction.t()) :: binary()
  def to_message(tx = %Transaction{version: 2}) do
    rlp =
      [
        tx.chain_id,
        tx.nonce,
        tx.max_priority_fee_per_gas,
        max_fee_per_gas(tx),
        tx.gasLimit,
        tx.to,
        tx.value,
        tx.data,
        tx.access_list
      ]
      |> Rlp.encode!()

    <<0x02>> <> rlp
  end

  def to_message(tx = %Transaction{chain_id: chain_id}) when chain_id in [nil, 0] do
    # pre EIP-155 encoding
    [tx.nonce, gas_price(tx), gas_limit(tx), tx.to, tx.value, payload(tx)]
    |> Rlp.encode!()
  end

  def to_message(tx = %Transaction{chain_id: chain_id}) do
    # EIP-155 encoding
    [tx.nonce, gas_price(tx), gas_limit(tx), tx.to, tx.value, payload(tx), chain_id, 0, 0]
    |> Rlp.encode!()
  end
end
