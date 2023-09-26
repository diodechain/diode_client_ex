defmodule DiodeClient.MixProject do
  use Mix.Project

  @version "1.1.4"
  @name "Diode Client"
  @url "https://github.com/diodechain/diode_client_ex"
  @maintainers ["Dominic Letz"]
  def project do
    [
      app: :diode_client,
      version: @version,
      name: @name,
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      docs: docs(),
      package: package(),
      homepage_url: @url,
      description: """
        DiodeClient allows direct P2P connection to any other DiodeClient user on the planet
        using Ethereum Addresses (e.g. 0xb794f5ea0ba39494ce839613fffba74279579268) and BNS names
        (e.g. yourname.diode) instead of IPv4 or IPv6
      """,
      xref: [exclude: [:ranch_transport, Plug.Cowboy]]
    ]
  end

  defp aliases do
    [
      lint: [
        "compile",
        "format --check-formatted",
        "credo",
        "dialyzer"
      ]
    ]
  end

  defp docs do
    [
      main: "DiodeClient",
      source_ref: "v#{@version}",
      source_url: @url,
      authors: @maintainers
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["DIODE"],
      links: %{github: @url},
      files: ~w(lib LICENSE.md mix.exs README.md)
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {DiodeClient, []},
      extra_applications: [:logger, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:debouncer, "~> 0.1"},
      {:ex_sha3, "~> 0.1.1"},
      {:libsecp256k1, "~> 0.1", hex: :libsecp256k1_diode_fork},
      {:network_monitor, "~> 1.1"},
      # {:libsecp256k1, github: "diodechain/libsecp256k1"},

      # Linting
      {:credo, "~> 1.5", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
