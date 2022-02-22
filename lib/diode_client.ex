defmodule DiodeClient do
  @moduledoc ~S"""
  DiodeClient secure end-to-end encrypted connections bettween any two machines. Connections are established
  either through direct peer-to-peer TCP connections or bridged via the Diode network. To learn more about the
  decentralized Diode network visit https://diode.io/

  Example Usage with a simple server:

  ```elixir
  DiodeClient.add_interface("example_server_interface")
  address = DiodeClient.Wallet.printable(DiodeClient.wallet())

  {:ok, port} = DiodeClient.port_listen(5000)
  spawn_link(fn ->
    IO.puts("server #{address} started")
    {:ok, ssl} = DiodeClient.port_accept(port)
    peer = DiodeClient.Port.peer(ssl)
    IO.puts("got a connection from #{Base.encode16(peer)}")
    :ssl.controlling_process(ssl, self())
    :ssl.setopts(ssl, [packet: :line, active: true])
    for x <- 1..10 do
      IO.puts("sending message #{x}")
      :ssl.send(ssl, "Hello #{Base.encode16(peer)} this is message #{x}\n")
    end
    receive do
      {:ssl_closed, _ssl} -> IO.puts("closed!")
    end
  end)

  ```

  And the client. Here insert in the server address the address that has been printed above.
  For example `server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"`

  ```elixir
    # Client:
    server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"
    DiodeClient.add_interface("example_client_interface")

    spawn_link(fn ->
      {:ok, ssl} = DiodeClient.port_connect(server_address, 5000)
      :ssl.controlling_process(ssl, self())
      :ssl.setopts(ssl, [packet: :line, active: true])
      Enum.reduce_while(1..10, nil, fn _, _ ->
        receive do
          {:ssl, _ssl, msg} -> {:cont, IO.inspect(msg)}
          other -> {:halt, IO.inspect(other)}
        end
      end)
      :ssl.close(ssl)
      IO.puts("closed!")
    end)
  ```


  """
  use Application
  alias DiodeClient.{ETSLru, Port, Wallet, ShellCache, Sup}
  require Logger

  @impl true
  def start(_start_type, _start_args) do
    ETSLru.new(ShellCache, 10_000, fn
      [:error | _] -> false
      _other -> true
    end)

    Supervisor.start_link([], strategy: :one_for_one, name: __MODULE__)
  end

  def add_interface(wallet \\ "diode_client_interface", name \\ :default) do
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

  @spec port_connect(binary(), integer(), Keyword.t()) :: {:ok, any()} | {:error, any()}
  def port_connect(destination, port, options \\ [])

  def port_connect(destination = <<_::336>>, port, options) do
    port_connect(DiodeClient.Base16.decode(destination), port, options)
  end

  def port_connect(destination = <<_::320>>, port, options) do
    port_connect(Base.decode16!(destination), port, options)
  end

  def port_connect(destination = <<_::160>>, port, options)
      when (is_integer(port) or is_binary(port)) and is_list(options) do
    ensure_wallet()
    Port.connect(destination, port, options)
  end

  def port_listen(portnum, opts \\ []) when is_integer(portnum) or is_binary(portnum) do
    ensure_wallet()
    Port.listen(portnum, opts)
  end

  def port_accept(listener) do
    ensure_wallet()
    Port.accept(listener)
  end

  def port_close(pid) do
    ensure_wallet()
    Port.close(pid)
  end

  def set_wallet(mfa = {m, f, a}) when is_atom(m) and is_atom(f) and is_list(a),
    do: do_set_wallet(mfa)

  def set_wallet({:wallet, privkey, _pubkey, _address} = w) when is_binary(privkey),
    do: set_wallet(fn -> w end)

  def set_wallet(fun) when is_function(fun, 0), do: do_set_wallet(fun)
  def set_wallet(fun) when is_function(fun, 0), do: do_set_wallet(fun)

  def set_wallet(path) when is_binary(path) do
    if not File.exists?(path) do
      Logger.warn("diode_client is creating a new id at #{path}")
      wallet = Wallet.new()
      File.write!(path, Wallet.privkey!(wallet))
      File.chmod!(path, 0o600)
      wallet
    else
      File.read!(path)
      |> Wallet.from_privkey()
    end
    |> set_wallet()
  end

  defp do_set_wallet(w) do
    if :persistent_term.get({__MODULE__, :wallet}, nil) == nil do
      :persistent_term.put({__MODULE__, :wallet}, w)
    else
      {:error, "can't reset wallet"}
    end
  end

  def wallet() do
    case :persistent_term.get({__MODULE__, :wallet}) do
      {module, fun, args} -> apply(module, fun, args)
      cb when is_function(cb) -> cb.()
    end
  end

  def ensure_wallet() do
    if :persistent_term.get({__MODULE__, :wallet}, nil) == nil do
      add_interface()
    end

    wallet()
  end

  def address() do
    Wallet.address!(wallet())
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
