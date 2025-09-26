defmodule DiodeClient.Contracts.List do
  @fields [
    # Address of the Global BNS contract
    :bns,
    # Address of the current drive implementation contract
    :drive,
    # Version number of the drive implementation contract
    :drive_version,
    # Address of the Global drive invites contract
    :drive_invites,
    # Address of the drive member implementation contract
    :drive_member,
    # Address of the Global factory contract
    :factory,
    # Address of the fleet member implementation contract
    :fleet_member,
    # Proxy code hash of proxy contracts created by the factory for create2 calculations
    :proxy_code_hash
  ]

  @enforce_keys @fields
  defstruct @fields
end
