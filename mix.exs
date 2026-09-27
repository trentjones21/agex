defmodule ExAge.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/trentjones21/agex"

  def project do
    [
      app: :ex_age,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "age file encryption for Elixir, powered by the Rust age crate (rage).",
      source_url: @source_url,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler_precompiled, "~> 0.8"},
      {:rustler, "~> 0.36", optional: true},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => @source_url, "age" => "https://age-encryption.org"},
      files: [
        "lib",
        "native/ex_age/src",
        "native/ex_age/Cargo.toml",
        "native/ex_age/Cargo.lock",
        "native/ex_age/.cargo",
        "checksum-*.exs",
        "mix.exs",
        "README.md",
        "LICENSE*"
      ]
    ]
  end

  defp docs do
    [main: "readme", extras: ["README.md"], source_ref: "v#{@version}"]
  end
end
