defmodule DiodeClient.Contracts.CallPermit do
  @moduledoc """
    Moonbeam CallPermit contract
    https://github.com/moonbeam-foundation/moonbeam/blob/master/precompiles/call-permit/CallPermit.sol
  """
  alias DiodeClient.{ABI, Base16, EIP712}

  # Moonbase Alpha (0x507)
  # @chain_id 1287
  @domain_separator %{
    DiodeClient.Shell.MoonbaseAlpha.chain_id() =>
      Base16.decode("0x2d44830364594de15bf34f87ca86da8d1967e5bc7d64b301864028acb9120412"),
    DiodeClient.Shell.Moonbeam.chain_id() =>
      Base16.decode("0x4f83a3a1d1a8f42700b988f3d8f4b0a56bd0768a19d045db65158b079b2a0bae")
  }

  def address() do
    Base16.decode("0x000000000000000000000000000000000000080A")
  end

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
  def dispatch(from, to, value, data, gaslimit, deadline, {v, r, s}) do
    ABI.encode_call(
      "dispatch",
      dispatch_types(),
      [from, to, value, data, gaslimit, deadline, v, r, s]
    )
  end

  def decode_dispatch(encoded_call) do
    with {:ok, [from, to, value, data, gaslimit, deadline, v, r, s]} <-
           ABI.decode_call("dispatch", dispatch_types(), encoded_call) do
      %{
        from: from,
        to: to,
        value: value,
        data: data,
        gaslimit: gaslimit,
        deadline: deadline,
        v: v,
        r: r,
        s: s
      }
    end
  end

  defp dispatch_types() do
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
    ]
  end

  def nonces(owner) do
    ABI.encode_call("nonces", ["address"], [owner])
  end

  def domain_separator() do
    ABI.encode_call("DOMAIN_SEPARATOR", [], [])
  end

  def call_permit(chain_id, from, to, value, data, gaslimit, deadline, nonce) do
    EIP712.encode(@domain_separator[chain_id], "CallPermit", [
      {"from", "address", from},
      {"to", "address", to},
      {"value", "uint256", value},
      {"data", "bytes", data},
      {"gaslimit", "uint64", gaslimit},
      {"nonce", "uint256", nonce},
      {"deadline", "uint256", deadline}
    ])
  end
end
