defmodule Eyepatch.MixProject do
  use Mix.Project

  def project do
    [
      app: :eyepatch,
      version: "0.1.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [coveralls: :test, "coveralls.detail": :test, "coveralls.post": :test, "coveralls.html": :test],
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
      {:hackney, "~> 1.15", only: :test},
      {:ibrowse, "~> 4.4", only: :test},
      {:jason, "~> 1.1", only: :test},
      {:excoveralls, "~> 0.10", only: :test},
    ]
  end
end
