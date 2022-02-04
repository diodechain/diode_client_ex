defmodule DiodeClient.MixProject do
  use Mix.Project

  @version "1.0.0"
  @name "Diode Client"
  @url "https://github.com/diodechain/diode_client"
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
        "credo --only warning",
        "dialyzer"
      ]
    ]
  end

  defp docs do
    [
      main: @name,
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
      {:poison, "~> 3.0"},
      {:keccakf1600, github: "diodechain/erlang-keccakf1600"},
      {:libsecp256k1, github: "diodechain/libsecp256k1"},
      {:debouncer, "~> 0.1"},

      # Linting
      {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
      {:credo, "~> 1.5", only: [:dev, :test], runtime: false}
    ]
  end
end
