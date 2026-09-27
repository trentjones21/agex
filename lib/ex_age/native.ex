defmodule ExAge.Native do
  @moduledoc false

  version = Mix.Project.config()[:version]
  source_url = Mix.Project.config()[:source_url]

  # Hex consumers compile this dependency in :prod and download a precompiled NIF.
  # Working in this repository (or setting EX_AGE_BUILD=1) compiles from source.
  use RustlerPrecompiled,
    otp_app: :ex_age,
    crate: "ex_age",
    base_url: "#{source_url}/releases/download/v#{version}",
    force_build: System.get_env("EX_AGE_BUILD") in ["1", "true"] or Mix.env() in [:dev, :test],
    version: version,
    nif_versions: ["2.15"],
    targets: ~w(
      aarch64-apple-darwin
      aarch64-unknown-linux-gnu
      aarch64-unknown-linux-musl
      x86_64-apple-darwin
      x86_64-pc-windows-gnu
      x86_64-pc-windows-msvc
      x86_64-unknown-linux-gnu
      x86_64-unknown-linux-musl
    )

  def generate_x25519, do: err()
  def x25519_to_recipient(_identity), do: err()
  def encrypt(_plaintext, _recipients, _armor), do: err()
  def decrypt(_ciphertext, _identities), do: err()
  def encrypt_passphrase(_plaintext, _passphrase, _armor, _work_factor), do: err()
  def decrypt_passphrase(_ciphertext, _passphrase, _max_work_factor), do: err()

  defp err, do: :erlang.nif_error(:nif_not_loaded)
end
