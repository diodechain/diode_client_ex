defmodule DiodeClient.Contracts.Factory do
  @moduledoc """
  This module is used to create and manage the factory contract.
  The factory is creating Proxy contracts for deployed implementations.
  Only the original transaction submitter can upgrade the implementation.
  """
  alias DiodeClient.{ABI, Base16, Hash, IdentityRequest}

  @constructor_diode Base16.decode(
                       "0x608060405234801561001057600080fd5b5060405161027d38038061027d8339818101604052604081101561003357600080fd5b5080516020909101517f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc919091557fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103556101eb806100926000396000f3fe60806040526004361061002d5760003560e01c8063277f2594146100445780633b2a0ff2146100775761003c565b3661003c5761003a6100aa565b005b61003a6100aa565b34801561005057600080fd5b5061003a6004803603602081101561006757600080fd5b50356001600160a01b03166100f0565b34801561008357600080fd5b5061003a6004803603602081101561009a57600080fd5b50356001600160a01b0316610159565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc543660008037600080366000845af43d6000803e8080156100eb573d6000f35b600080fd5b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561014c57817f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5550610156565b6101546100aa565b505b50565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561014c57817fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103555061015656fea264697066735822122046073a9a998cc88e87a1097fe86f7bf447c03175c06d350ca5a603c0b2c4abf464736f6c63430006060033"
                     )

  @constructor_moonbeam Base16.decode(
                          "0x608060405234801561001057600080fd5b506040516102813803806102818339818101604052604081101561003357600080fd5b5080516020909101517f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc919091557fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103556101ef806100926000396000f3fe60806040526004361061002d5760003560e01c8063277f2594146100445780633b2a0ff2146100775761003c565b3661003c5761003a6100aa565b005b61003a6100aa565b34801561005057600080fd5b5061003a6004803603602081101561006757600080fd5b50356001600160a01b03166100f6565b34801561008357600080fd5b5061003a6004803603602081101561009a57600080fd5b50356001600160a01b031661015d565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc543660008037600080366000845af490503d6000803e8080156100ed573d6000f35b600080fd5b5050565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561015257817f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc555061015a565b6100f26100aa565b50565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561015257817fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103555061015a56fea264697066735822122066f22164759e5100e87b05d773998c880ba1f8f6e5574062cb6e9eeedb5efb8b64736f6c63430007060033"
                        )

  @constructor_sapphire Base16.decode(
                          "0x608060405234801561001057600080fd5b506040516102813803806102818339818101604052604081101561003357600080fd5b5080516020909101517f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc919091557fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103556101ef806100926000396000f3fe60806040526004361061002d5760003560e01c8063277f2594146100445780633b2a0ff2146100775761003c565b3661003c5761003a6100aa565b005b61003a6100aa565b34801561005057600080fd5b5061003a6004803603602081101561006757600080fd5b50356001600160a01b03166100f6565b34801561008357600080fd5b5061003a6004803603602081101561009a57600080fd5b50356001600160a01b031661015d565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc543660008037600080366000845af490503d6000803e8080156100ed573d6000f35b600080fd5b5050565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561015257817f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc555061015a565b6100f26100aa565b50565b7fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103546001600160a01b03811633141561015257817fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103555061015a56fea26469706673582212209f3bd0b5c9f77e605a6a54668faa62fb54278550e607aa76e2101f5263703a7164736f6c63430007060033"
                        )

  def contracts(TestShell) do
    contracts(DiodeClient.Shell)
  end

  def contracts(DiodeClient.Shell) do
    factory = Hash.to_address(0x932CA256C8F912A9BAFAAF4BD598FCD22B8E21B7)

    %{
      factory: factory,
      drive_member: Hash.to_address(0x6329E652E2212A33529334A3B39B3441861EFA58),
      fleet_member: Hash.to_address(0x3A887BEEEEE533A6799C0C9AC6FC69C022B57F4C),
      proxy_code_hash:
        Hash.keccak_256(
          @constructor_diode <> ABI.encode_args(["address", "address"], [0, factory])
        )
    }
  end

  def contracts(DiodeClient.Shell.Moonbeam) do
    factory = Hash.to_address(0xAF7DE307EB221C916BAA33218B6780CAE6AB8792)

    %{
      factory: factory,
      drive_member: Hash.to_address(0x2EE98B1DCB555E38B33B9D73D258A2FFE5A4E577),
      fleet_member: Hash.to_address(0x8A47E149637CFA7FEA946E4489A43D7CC7CD6374),
      proxy_code_hash:
        Hash.keccak_256(
          @constructor_moonbeam <> ABI.encode_args(["address", "address"], [0, factory])
        )
    }
  end

  def contracts(DiodeClient.Shell.OasisSapphire) do
    factory = Hash.to_address(0x355DDBCF0E9FD70D78829EECB443389290EE53E1)

    %{
      factory: factory,
      drive_member: Hash.to_address(0xBC07EF1B0B79E2D41D82CD940C1E79DCF3F1A0F9),
      fleet_member: Hash.to_address(0x0),
      proxy_code_hash:
        Hash.keccak_256(
          @constructor_sapphire <> ABI.encode_args(["address", "address"], [0, factory])
        )
    }
  end

  def fleet_member_target(shell) do
    contracts(shell).fleet_member
  end

  def drive_member_target(shell) do
    contracts(shell).drive_member
  end

  def address(shell) do
    contracts(shell).factory
  end

  def proxy_code_hash(shell) do
    contracts(shell).proxy_code_hash
  end

  def is_factory(address) do
    address in Enum.map(DiodeClient.shells(), &address/1)
  end

  def identity_salt(shell, wallet \\ DiodeClient.wallet()) do
    priv_key = DiodeClient.Wallet.privkey!(wallet)

    if shell == DiodeClient.Shell.OasisSapphire do
      :crypto.mac(:hmac, :sha256, "/identity?chain_id=#{shell.chain_id()}", priv_key)
    else
      :crypto.mac(:hmac, :sha256, "/identity", priv_key)
    end
  end

  def identity_address(shell, wallet \\ DiodeClient.wallet()) do
    c = contracts(shell)
    Hash.create2(c.factory, c.proxy_code_hash, identity_salt(shell, wallet))
  end

  def identity_address_call(shell, wallet \\ DiodeClient.wallet()) do
    c = contracts(shell)

    shell.call(c.factory, "Create2Address", ["bytes32"], [identity_salt(shell, wallet)])
    |> Base16.decode()
    |> Hash.to_address()
  end

  @doc """
  This initial identity creation is tricky on different chains because of the gas management. We cover three cases:
  - Diode L1: Gasless chain, anyone can submit their own transactions
  - Moonbeam: Third parties can pay the gas for others using the native "Call Permit" PreCompile
  - Sapphire: Normal gas payment is needed, after identity creation, we can use MetaTransactions against the identity
  """
  def create_identity_tx(shell) do
    shell.create_transaction(
      address(shell),
      "Create",
      ["address", "bytes32", "address"],
      [DiodeClient.address(), identity_salt(shell), drive_member_target(shell)]
    )
  end

  def create_identity_meta_tx(shell) do
    shell.create_meta_transaction(
      address(shell),
      "Create",
      ["address", "bytes32", "address"],
      [DiodeClient.address(), identity_salt(shell), drive_member_target(shell)],
      shell.get_meta_nonce(DiodeClient.address())
    )
  end

  def create_identity_request(shell) do
    %IdentityRequest{
      salt: identity_salt(shell),
      target: drive_member_target(shell)
    }
  end

  def upgrade_identity_tx(shell) do
    shell.create_transaction(
      address(shell),
      "Upgrade",
      ["bytes32", "address"],
      [identity_salt(shell), drive_member_target(shell)]
    )
  end
end
