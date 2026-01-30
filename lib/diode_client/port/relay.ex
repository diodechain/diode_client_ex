defmodule DiodeClient.Port.Relay do
  @moduledoc """
  A relay is a reserved ip:port combination on a node server that can be used relay traffic between two clients.
  """
  defstruct [:url, :port, :source_addr]
end
