defmodule DiodeClient.Cowboy2Adapter do
  alias DiodeClient.Transport
  use DiodeClient.Log

  @moduledoc """
  The Cowboy2 adapter for Diode.
  """

  require Logger

  @doc false
  def child_specs(endpoint, config) do
    otp_app = Keyword.fetch!(config, :otp_app)

    refs_and_specs =
      for {scheme, port} <- [http: 4000, https: 4040], opts = config[scheme] do
        port = :proplists.get_value(:port, opts, port)

        unless port do
          log(":port for #{scheme} config is nil, cannot start server")
          raise "aborting due to nil port"
        end

        opts = [port: port_to_integer(port), otp_app: otp_app] ++ :proplists.delete(:port, opts)
        child_spec(scheme, endpoint, opts)
      end

    {refs, child_specs} = Enum.unzip(refs_and_specs)

    if drainer = refs != [] && Keyword.get(config, :drainer, []) do
      child_specs ++ [{Plug.Cowboy.Drainer, Keyword.put_new(drainer, :refs, refs)}]
    else
      child_specs
    end
  end

  defp child_spec(scheme, endpoint, config) do
    if scheme == :https do
      Application.ensure_all_started(:ssl)
    end

    dispatches = [{:_, Phoenix.Endpoint.Cowboy2Handler, {endpoint, endpoint.init([])}}]
    config = Keyword.put_new(config, :dispatch, [{:_, dispatches}])
    ref = Module.concat(endpoint, scheme |> Atom.to_string() |> String.upcase())
    spec = Plug.Cowboy.child_spec(ref: ref, scheme: scheme, plug: {endpoint, []}, options: config)

    spec =
      update_in(spec.start, fn {:ranch_listener_sup, :start_link,
                                [ref, _transport, trans_opts, protocol, proto_opts]} ->
        {:ranch_listener_sup, :start_link,
         [ref, Transport, Map.put(trans_opts, :sendfile, true), protocol, proto_opts]}
      end)

    spec = update_in(spec.start, &{__MODULE__, :start_link, [scheme, endpoint, &1]})
    {ref, spec}
  end

  @doc false
  def start_link(scheme, endpoint, {m, f, [ref | _] = a}) do
    # ref is used by Ranch to identify its listeners, defaulting
    # to plug.HTTP and plug.HTTPS and overridable by users.
    case apply(m, f, a) do
      {:ok, pid} ->
        log(fn -> info(scheme, endpoint, ref) end)
        {:ok, pid}

      {:error, {:shutdown, {_, _, {{_, {:error, :eaddrinuse}}, _}}}} = error ->
        log([info(scheme, endpoint, ref), " failed, port already in use"])
        error

      {:error, _} = error ->
        error
    end
  end

  defp info(scheme, endpoint, ref) do
    server = "cowboy #{Application.spec(:cowboy)[:vsn]}"
    "Running #{inspect(endpoint)} with #{server} at #{bound_address(scheme, ref)}"
  end

  defp bound_address(scheme, ref) do
    "#{inspect({scheme, ref})} (diode)"
  end

  # TODO: Deprecate {:system, env_var} once we require Elixir v1.9+
  defp port_to_integer({:system, env_var}), do: port_to_integer(System.get_env(env_var))
  defp port_to_integer(port) when is_binary(port), do: String.to_integer(port)
  defp port_to_integer(port) when is_integer(port), do: port
end
