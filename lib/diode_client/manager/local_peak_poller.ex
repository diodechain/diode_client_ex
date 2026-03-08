defmodule DiodeClient.Manager.LocalPeakPoller do
  @moduledoc false
  use WebSockex

  require Logger

  alias DiodeClient.{Manager, Rlpx}

  @eth_subscribe_new_heads ~s({"jsonrpc":"2.0","method":"eth_subscribe","params":["newHeads"],"id":1})

  def start_link(shell) when is_atom(shell) do
    url = shell.ws_url()

    state = %{
      shell: shell,
      manager: Process.whereis(Manager),
      url: url,
      last_poll_block: nil
    }

    WebSockex.start_link(url, __MODULE__, state, handle_initial_conn_failure: true)
  end

  @impl true
  def handle_connect(_conn, state) do
    send(self(), :send_subscribe)
    schedule_poll(state)
    {:ok, state}
  end

  @impl true
  def handle_info(:send_subscribe, state) do
    {:reply, {:text, @eth_subscribe_new_heads}, state}
  end

  def handle_info(:poll, state = %{shell: shell, manager: manager, last_poll_block: last})
      when is_pid(manager) do
    schedule_poll(state)
    peak = shell.peak()
    num = Rlpx.bin2uint(peak["number"])

    if last == nil or num > last do
      GenServer.cast(Manager, {:local_peak, shell, peak})
      {:ok, %{state | last_poll_block: num}}
    else
      {:ok, state}
    end
  end

  def handle_info(:poll, state) do
    schedule_poll(state)
    {:ok, state}
  end

  @impl true
  def handle_frame({:text, payload}, state = %{shell: shell, manager: manager})
      when is_pid(manager) do
    case Jason.decode(payload) do
      {:ok, %{"method" => "eth_subscription", "params" => %{"result" => block}}}
      when is_map(block) ->
        diode_block = shell.eth_header_to_diode_block(block)
        num = Rlpx.bin2uint(diode_block["number"])
        GenServer.cast(Manager, {:local_peak, shell, diode_block})
        {:ok, %{state | last_poll_block: num}}

      {:ok, %{"result" => _sub_id}} ->
        :ok

      {:ok, %{"error" => err}} ->
        Logger.warning("LocalPeakPoller eth_subscribe error: #{inspect(err)}")

      _ ->
        :ok
    end

    {:ok, state}
  end

  def handle_frame(_frame, state) do
    {:ok, state}
  end

  @impl true
  def handle_disconnect(%{reason: reason}, state = %{url: url}) do
    Logger.debug("LocalPeakPoller disconnected: #{inspect(reason)}")
    conn = WebSockex.Conn.new(url)
    {:reconnect, conn, state}
  end

  @impl true
  def terminate(reason, _state) do
    Logger.debug("LocalPeakPoller terminating: #{inspect(reason)}")
    :ok
  end

  defp schedule_poll(%{shell: shell}) do
    # Poll at half block_time as fallback when eth_subscribe doesn't emit (e.g. Anvil)
    interval = max(500, div(shell.block_time(), 2))
    Process.send_after(self(), :poll, interval)
  end
end
