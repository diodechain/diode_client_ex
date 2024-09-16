# Client: Below enter your server address
DiodeClient.interface_add("example_client_interface")

IO.inspect(DiodeClient.Manager.get_peak(DiodeClient.Shell))
