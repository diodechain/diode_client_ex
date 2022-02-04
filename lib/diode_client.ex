defmodule DiodeClient do
  use Application
  alias DiodeClient.{Connection, ETSLru, Port, Wallet, ShellCache, Sup}

  @impl true
  def start(_start_type, _start_args) do
    ETSLru.new(ShellCache, 1024)
    Supervisor.start_link([], strategy: :one_for_one, name: __MODULE__)
  end

  def add_client(name \\ :default, wallet) do
    set_wallet(wallet)
    Supervisor.start_child(__MODULE__, {Sup, name})
  end

  def is_client_online(name \\ :default) do
    Supervisor.which_children(__MODULE__)
    |> Enum.any?(fn {cname, pid, _type, _mods} -> cname == name and is_pid(pid) end)
  end

  def stop_client(name \\ :default) do
    Supervisor.terminate_child(__MODULE__, name)
  end

  def restart_client(name \\ :default) do
    Supervisor.restart_child(__MODULE__, name)
  end

  def ping(conn) do
    Connection.rpc(conn, ["ping"])
  end

  @spec port_connect(binary(), integer(), String.t()) :: {:ok, pid()} | {:error, any()}
  def port_connect(destination, port, access \\ "rw") do
    Port.connect(destination, port, access)
  end

  def port_listen(portnum, opts \\ []) do
    Port.listen(portnum, opts)
  end

  def port_accept(listener) do
    Port.accept(listener)
  end

  def port_close(pid) do
    Port.close(pid)
  end

  def set_wallet(cb) do
    :persistent_term.put({__MODULE__, :wallet}, cb)
  end

  def wallet() do
    case :persistent_term.get({__MODULE__, :wallet}) do
      {module, fun, args} -> apply(module, fun, args)
      cb when is_function(cb) -> cb.()
    end
  end

  def address() do
    Wallet.address!(wallet())
  end

  def online?() do
    Process.whereis(Sup) != nil
  end

  def default_conn() do
    case Process.whereis(DiodeClient.Manager) do
      nil ->
        Process.sleep(1_000)
        default_conn()

      _pid ->
        DiodeClient.Manager.get_connection()
    end
  end

  def connections() do
    case Process.whereis(DiodeClient.Manager) do
      nil -> []
      _pid -> DiodeClient.Manager.connections()
    end
  end
end
