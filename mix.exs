defmodule RustyCrypt.MixProject do
  use Mix.Project

  def project do
    [
      app: :rusty_crypt,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      preferred_cli_env: [
        "bench.sha": :bench,
        "bench.aes": :bench,
        "bench.random": :bench
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.25.0"},
      {:benchee, "~> 1.0", only: :bench},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      "bench.sha": "run bench/sha256.exs",
      "bench.aes": "run bench/aes256.exs",
      "bench.random": "run bench/random.exs"
    ]
  end
end
