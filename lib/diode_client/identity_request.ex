defmodule DiodeClient.IdentityRequest do
  @moduledoc false
  defstruct [:salt, :target]
  alias DiodeClient.IdentityRequest

  def to_rlp(%IdentityRequest{
        salt: salt,
        target: target
      }) do
    ["dm0", salt, target]
  end
end
