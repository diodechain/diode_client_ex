defmodule DiodeClient.IdentityRequest do
  @moduledoc false
  defstruct [:salt, :target, :from]
  alias DiodeClient.IdentityRequest

  def to_rlp(%IdentityRequest{
        salt: salt,
        target: target,
        from: from
      }) do
    ["dm0", from, salt, target]
  end
end
