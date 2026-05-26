defmodule DiodeClient.Ticket do
  @moduledoc false
  alias DiodeClient.{Rlp, Rlpx}
  require Logger

  defp mod(tck) do
    case elem(tck, 0) do
      :ticket -> DiodeClient.TicketV1
      :ticketv2 -> DiodeClient.TicketV2
    end
  end

  def block_number(tck), do: mod(tck).block_number(tck)
  def device_address(tck), do: mod(tck).device_address(tck)
  def device_address?(tck, wallet), do: mod(tck).device_address?(tck, wallet)
  def device_blob(tck), do: mod(tck).device_blob(tck)
  def device_sign(tck, private), do: mod(tck).device_sign(tck, private)
  def device_signature(tck), do: mod(tck).device_signature(tck)
  def device_wallet(tck), do: mod(tck).device_wallet(tck)
  def epoch(tck), do: mod(tck).epoch(tck)
  def fleet_contract(tck), do: mod(tck).fleet_contract(tck)
  def key(tck), do: mod(tck).key(tck)
  def local_address(tck), do: mod(tck).local_address(tck)
  def message(tck), do: mod(tck).message(tck)
  def raw(tck), do: mod(tck).raw(tck)
  def server_blob(tck), do: mod(tck).server_blob(tck)
  def server_id(tck), do: mod(tck).server_id(tck)
  def server_sign(tck, private), do: mod(tck).server_sign(tck, private)
  def server_signature(tck), do: mod(tck).server_signature(tck)
  def total_bytes(tck), do: mod(tck).total_bytes(tck)
  def total_connections(tck), do: mod(tck).total_connections(tck)

  def too_many_bytes?(tck) do
    total_bytes(tck) > 1024 * 1024 * 1024 * 1024 * 1024
  end

  defmodule Metadata do
    @moduledoc false
    defstruct [:version, :preferred, :timestamp]
  end

  def create_local_address(preferred_server_ids, timestamp)
      when is_list(preferred_server_ids) and is_integer(timestamp) do
    metadata = Rlp.encode!(%{"s" => preferred_server_ids, "t" => timestamp})
    <<2, metadata::binary>>
  end

  def metadata(tck) do
    id = server_id(tck)

    case local_address(tck) do
      <<0, addr::binary-size(20)>> ->
        struct(Metadata, %{version: 1, preferred: [addr, id]})

      <<1, addr::binary-size(20)>> ->
        struct(Metadata, %{version: 1, preferred: [id, addr]})

      <<2, meta::binary>> ->
        case Rlp.decode(meta) do
          {decoded_list, ""} when is_list(decoded_list) ->
            decoded = Rlpx.list2map(decoded_list)
            preferred = Map.get(decoded, "s", []) |> Enum.filter(&is_binary/1)
            timestamp = Map.get(decoded, "t", "") |> Rlpx.bin2uint()
            struct(Metadata, %{version: 2, preferred: preferred, timestamp: timestamp})

          other ->
            Logger.error("Invalid metadata in ticketv2: #{inspect(other)}")
            struct(Metadata, %{version: 0, preferred: [id]})
        end

      _ ->
        struct(Metadata, %{version: 0, preferred: [id]})
    end
  end

  def preferred_server_ids(tck) do
    metadata(tck).preferred
  end
end
