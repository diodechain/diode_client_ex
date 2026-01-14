defmodule DiodeClient do
  @moduledoc ~S"""
  [DiodeClient](https://github.com/diodechain/diode_client_ex) secure end-to-end encrypted connections between any two machines. Connections are established
  either through direct peer-to-peer TCP connections or bridged via the Diode network. To learn more about the
  decentralized Diode network visit https://diode.io/

  Example Usage of [DiodeClient](https://github.com/diodechain/diode_client_ex) with a simple server:

  ```elixir
  DiodeClient.interface_add("example_server_interface")
  address = DiodeClient.Base16.encode(DiodeClient.address())

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
    DiodeClient.interface_add("example_client_interface")

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
  alias DiodeClient.{Base16, ETSLru, Port, Wallet, ShellCache, HashCache, Sup}
  require Logger

  @impl true
  def start(_start_type, _start_args) do
    ETSLru.new(ShellCache, 10_000, {__MODULE__, :filter_invalid_object})
    ETSLru.new(HashCache, 1_000)
    Supervisor.start_link([], strategy: :one_for_one, name: __MODULE__)
  end

  def filter_invalid_object(object) do
    case object do
      :undefined -> false
      {:error, _reason} -> false
      _other -> true
    end
  end

  def interface_add(wallet \\ "diode_client_interface", name \\ :default) do
    set_wallet(wallet)
    Supervisor.start_child(__MODULE__, {Sup, name})
  end

  def interface_online?(name \\ :default) do
    Supervisor.which_children(__MODULE__)
    |> Enum.any?(fn {cname, pid, _type, _mods} ->
      cname == name and is_pid(pid) and DiodeClient.Manager.online?()
    end)
  end

  @spec interface_stop(atom()) :: :ok | {:error, :not_found}
  def interface_stop(name \\ :default) do
    case Process.whereis(DiodeClient.Manager) do
      nil -> name
      pid when is_pid(pid) -> DiodeClient.Manager.set_online(false)
    end
  end

  @spec interface_restart(atom()) :: {:error, any} | {:ok, pid} | {:ok, pid, any}
  def interface_restart(name \\ :default) do
    case Process.whereis(DiodeClient.Manager) do
      nil -> name
      pid when is_pid(pid) -> DiodeClient.Manager.set_online(true)
    end
  end

  @spec port_connect(binary(), integer(), Keyword.t()) :: {:ok, any()} | {:error, any()}
  @doc """
  Connect to a port on a remote host.

  ## Parameters

  `destination` is the 20 byte diode address of the remote host.
  `port` is the diode port number to connect to on the remote host.

  `options` is a keyword list of options to pass to the connection.

  valid options are:
  - `:access` - Defaults to "rw".
  - `:local` - Whether to attempt a local connection. Can be `true`, `false`, or `:always`. Defaults to `true`. `:always` can be used to enforce only local connections to a target and avoid relaying.

  Returns `{:ok, pid}` if the connection is successful, or `{:error, reason}` if the connection fails.
  """
  def port_connect(destination, port, options \\ [])

  def port_connect(destination = <<_::336>>, port, options) do
    port_connect(Base16.decode(destination), port, options)
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

  @doc false
  def set_wallet(mfa = {m, f, a}) when is_atom(m) and is_atom(f) and is_list(a),
    do: do_set_wallet(mfa)

  def set_wallet({:wallet, privkey, _pubkey, _address} = w) when is_binary(privkey),
    do: set_wallet(fn -> w end)

  def set_wallet(fun) when is_function(fun, 0), do: do_set_wallet(fun)
  def set_wallet(fun) when is_function(fun, 0), do: do_set_wallet(fun)

  def set_wallet(path) when is_binary(path) do
    if File.exists?(path) do
      File.read!(path)
      |> Wallet.from_privkey()
    else
      Logger.warning("diode_client is creating a new id at #{path}")
      wallet = Wallet.new()
      File.write!(path, Wallet.privkey!(wallet))
      File.chmod!(path, 0o600)
      wallet
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

  @doc false
  def wallet() do
    case :persistent_term.get({__MODULE__, :wallet}, nil) do
      {module, fun, args} ->
        apply(module, fun, args)

      cb when is_function(cb) ->
        cb.()

      nil ->
        throw("No wallet set, call DiodeClient.set_wallet/1 or DiodeClient.ensure_wallet/0 first")
    end
  end

  def set_fleet_address(address = <<_::160>>) do
    :persistent_term.put({__MODULE__, :fleet_address}, address)
    address
  end

  def fleet_address() do
    case :persistent_term.get({__MODULE__, :fleet_address}, nil) do
      {module, fun, args} -> apply(module, fun, args)
      cb when is_function(cb) -> cb.()
      address = <<_::160>> -> address
      nil -> set_fleet_address(Base16.decode("0x8aFe08d333f785C818199a5bdc7A52ac6Ffc492A"))
    end
  end

  @doc false
  def ensure_wallet() do
    if :persistent_term.get({__MODULE__, :wallet}, nil) == nil do
      interface_add()
    end

    wallet()
  end

  def address() do
    Wallet.address!(ensure_wallet())
  end

  @doc false
  def default_conn() do
    DiodeClient.Manager.await()
    DiodeClient.Manager.get_connection()
  end

  @doc false
  def connections() do
    case Process.whereis(DiodeClient.Manager) do
      nil -> []
      _pid -> DiodeClient.Manager.connections()
    end
  end

  @shells [
    DiodeClient.Shell,
    DiodeClient.Shell.Moonbeam,
    DiodeClient.Shell.MoonbaseAlpha,
    DiodeClient.Shell.OasisSapphire
  ]

  def shells() do
    @shells
  end

  for shell <- @shells do
    def shell_for_chain_id(unquote(shell.chain_id())), do: unquote(shell)
  end
end
