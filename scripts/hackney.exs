#!/usr/bin/env elixir
Mix.install([:hackney, {:diode_client, path: "../"}])

# :hackney_trace.enable(:max, :io)
Logger.configure(level: :debug)
Logger.put_application_level(:diode_client, :debug)

DiodeClient.interface_add()
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))
Application.ensure_all_started(:hackney)

dst =
  case System.argv() do
    [] ->
      URI.parse("http://0x90983fc294577b6f00cbd5d3b26adf2e85ca2cac/lol")

    ["ddriveupdate"] ->
      URI.parse("http://0x35480f4de422827d4fd80c47a5cf5f2f4622f2aa")

    [address] ->
      case URI.parse(address) do
        %URI{scheme: nil} -> URI.parse("http://" <> address)
        uri -> uri
      end
  end
  |> then(fn uri ->
    IO.puts("Connecting to #{uri.host}:#{uri.port}#{uri.path}")
    %URI{uri | path: uri.path || "/"}
  end)

{:ok, ref} =
  :hackney.connect(DiodeClient.Transport, dst.host, dst.port,
    connect_timeout: 60_000,
    recv_timeout: 60_000,
    connect_options: [local: false, access: "rwt"]
  )

{:ok, _status, _headers, ^ref} = :hackney.send_request(ref, {:get, dst.path, [], []})

{:ok, content} = :hackney.body(ref)
IO.puts(content)
