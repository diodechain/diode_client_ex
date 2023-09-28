defmodule DiodeClient.Contracts.CallPermit do
  alias DiodeClient.{ABI, Base16, EIP712, Wallet}
  # https://github.com/moonbeam-foundation/moonbeam/blob/master/precompiles/call-permit/CallPermit.sol
  @address Base16.decode("0x000000000000000000000000000000000000080A")
  # Moonbase Alpha (0x507)
  # @chain_id 1287
  @domain_separator Base16.decode(
                      "0x2d44830364594de15bf34f87ca86da8d1967e5bc7d64b301864028acb9120412"
                    )

  # /// @dev Dispatch a call on the behalf of an other user with a EIP712 permit.
  # /// Will revert if the permit is not valid or if the dispatched call reverts or errors (such as
  # /// out of gas).
  # /// If successful the EIP712 nonce is increased to prevent this permit to be replayed.
  # /// @param from Who made the permit and want its call to be dispatched on their behalf.
  # /// @param to Which address the call is made to.
  # /// @param value Value being transfered from the "from" account.
  # /// @param data Call data
  # /// @param gaslimit Gaslimit the dispatched call requires.
  # ///     Providing it prevents the dispatcher to manipulate the gaslimit.
  # /// @param deadline Deadline in UNIX seconds after which the permit will no longer be valid.
  # /// @param v V part of the signature.
  # /// @param r R part of the signature.
  # /// @param s S part of the signature.
  # /// @return output Output of the call.
  # /// @custom:selector b5ea0966
  def dispatch(from, to, value, data, gaslimit, deadline, v, r, s) do
    ABI.encode_call(
      "dispatch",
      [
        "address",
        "address",
        "uint256",
        "bytes",
        "uint64",
        "uint256",
        "uint8",
        "bytes32",
        "bytes32"
      ],
      [from, to, value, data, gaslimit, deadline, v, r, s]
    )
  end

  def nonces(owner) do
    ABI.encode_call("nonces", ["address"], [owner])
  end

  def domain_separator() do
    ABI.encode_call("DOMAIN_SEPARATOR", [], [])
  end


  @endpoint "https://moonbeam-alpha.api.onfinality.io/public"
  # @endpoint "https://rpc.api.moonbase.moonbeam.network"
  def endpoint() do
    @endpoint
  end

  def call_permit(from_wallet, to, value, data, gaslimit, deadline) do
    from = Wallet.address!(from_wallet)
    nonce = call(nonces(from)) |> Base16.decode_int()

    signature =
      EIP712.encode(@domain_separator, "CallPermit", [
        {"from", "address", from},
        {"to", "address", to},
        {"value", "uint256", value},
        {"data", "bytes", data},
        {"gaslimit", "uint64", gaslimit},
        {"nonce", "uint256", nonce},
        {"deadline", "uint256", deadline}
      ])

    [v, r, s] =
      Wallet.sign!(from_wallet, signature, :none)
      |> Secp256k1.bitcoin_to_rlp()

    dispatch(from, to, value, data, gaslimit, deadline, v, r, s)
  end
end
