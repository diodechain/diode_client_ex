defmodule DiodeClient.MetaTransaction do
  alias DiodeClient.MetaTransaction
  defstruct [:from, :to, :value, :call, :gaslimit, :deadline, :signature]

  def sign(%MetaTransaction{}) do

  end
end
