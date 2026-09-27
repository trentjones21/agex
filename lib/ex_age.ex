defmodule ExAge do
  @moduledoc """
  [age](https://age-encryption.org) file encryption for Elixir, backed by the Rust
  [`age`](https://crates.io/crates/age) crate (the library behind `rage`) via Rustler.

  Output is standard age v1, so files are interchangeable with the `age` and `rage`
  command-line tools and every other conforming implementation.

  ## Keys

  * **Identities** are secret keys (`AGE-SECRET-KEY-1...`), or unencrypted OpenSSH
    `ed25519`/`rsa` private keys.
  * **Recipients** are public keys (`age1...`), or `ssh-ed25519 ...`/`ssh-rsa ...`
    public keys.

  ## Example

      iex> {identity, recipient} = ExAge.generate_identity()
      iex> {:ok, ciphertext} = ExAge.encrypt("attack at dawn", recipient)
      iex> ExAge.decrypt(ciphertext, identity)
      {:ok, "attack at dawn"}

  All encryption and decryption runs on dirty CPU schedulers, so it never blocks
  the BEAM's normal schedulers, including the deliberately slow scrypt passphrase
  key derivation.
  """

  alias ExAge.Native

  @type identity :: String.t()
  @type recipient :: String.t()
  @type reason :: String.t()

  @armor_header "-----BEGIN AGE ENCRYPTED FILE-----"

  @doc """
  Generates a new X25519 key pair.

  Returns `{identity, recipient}`. Store the identity as a secret. Share the
  recipient freely.

      iex> {"AGE-SECRET-KEY-1" <> _, "age1" <> _} = ExAge.generate_identity()
  """
  @spec generate_identity() :: {identity(), recipient()}
  def generate_identity, do: Native.generate_x25519()

  @doc """
  Derives the public recipient for an X25519 identity.

      iex> {identity, recipient} = ExAge.generate_identity()
      iex> ExAge.to_recipient(identity) == {:ok, recipient}
      true
  """
  @spec to_recipient(identity()) :: {:ok, recipient()} | {:error, reason()}
  def to_recipient(identity) when is_binary(identity) do
    Native.x25519_to_recipient(identity)
  end

  @doc """
  Encrypts `plaintext` to one or more recipients.

  ## Options

    * `:armor` - when `true`, returns PEM-style ASCII-armored text instead of
      binary. Defaults to `false`.
  """
  @spec encrypt(iodata(), recipient() | [recipient()], keyword()) ::
          {:ok, binary()} | {:error, reason()}
  def encrypt(plaintext, recipients, opts \\ []) do
    with {:ok, recipients} <- key_list(recipients, "recipients") do
      Native.encrypt(to_binary(plaintext), recipients, armor?(opts))
    end
  end

  @doc """
  Decrypts an age file with one or more identities.

  Binary and ASCII-armored input are both accepted. Each identity may be a single
  key or the full contents of an identity file.
  """
  @spec decrypt(iodata(), identity() | [identity()]) :: {:ok, binary()} | {:error, reason()}
  def decrypt(ciphertext, identities) do
    with {:ok, identities} <- key_list(identities, "identities") do
      Native.decrypt(to_binary(ciphertext), identities)
    end
  end

  @doc """
  Encrypts `plaintext` with a passphrase, using scrypt.

  Only use this for passphrases chosen by a person. For programmatic use,
  generate a key pair with `generate_identity/0` instead.

  ## Options

    * `:armor` - return ASCII-armored text. Defaults to `false`.
    * `:work_factor` - the scrypt cost as log2(N). By default age picks a value
      that takes about one second on the current machine.
  """
  @spec encrypt_with_passphrase(iodata(), String.t(), keyword()) ::
          {:ok, binary()} | {:error, reason()}
  def encrypt_with_passphrase(plaintext, passphrase, opts \\ []) when is_binary(passphrase) do
    Native.encrypt_passphrase(
      to_binary(plaintext),
      passphrase,
      armor?(opts),
      Keyword.get(opts, :work_factor)
    )
  end

  @doc """
  Decrypts a passphrase-encrypted age file.

  ## Options

    * `:max_work_factor` - the highest scrypt cost as log2(N) to accept. This
      protects against files crafted to take hours to decrypt. By default age
      accepts up to about 16 times its local target.
  """
  @spec decrypt_with_passphrase(iodata(), String.t(), keyword()) ::
          {:ok, binary()} | {:error, reason()}
  def decrypt_with_passphrase(ciphertext, passphrase, opts \\ []) when is_binary(passphrase) do
    Native.decrypt_passphrase(
      to_binary(ciphertext),
      passphrase,
      Keyword.get(opts, :max_work_factor)
    )
  end

  @doc "Like `encrypt/3`, but raises `ExAge.Error` on failure."
  @spec encrypt!(iodata(), recipient() | [recipient()], keyword()) :: binary()
  def encrypt!(plaintext, recipients, opts \\ []), do: bang(encrypt(plaintext, recipients, opts))

  @doc "Like `decrypt/2`, but raises `ExAge.Error` on failure."
  @spec decrypt!(iodata(), identity() | [identity()]) :: binary()
  def decrypt!(ciphertext, identities), do: bang(decrypt(ciphertext, identities))

  @doc "Like `encrypt_with_passphrase/3`, but raises `ExAge.Error` on failure."
  @spec encrypt_with_passphrase!(iodata(), String.t(), keyword()) :: binary()
  def encrypt_with_passphrase!(plaintext, passphrase, opts \\ []),
    do: bang(encrypt_with_passphrase(plaintext, passphrase, opts))

  @doc "Like `decrypt_with_passphrase/3`, but raises `ExAge.Error` on failure."
  @spec decrypt_with_passphrase!(iodata(), String.t(), keyword()) :: binary()
  def decrypt_with_passphrase!(ciphertext, passphrase, opts \\ []),
    do: bang(decrypt_with_passphrase(ciphertext, passphrase, opts))

  @doc """
  Returns `true` if `data` looks like ASCII-armored age output.

      iex> ExAge.armored?("-----BEGIN AGE ENCRYPTED FILE-----\\n...")
      true
  """
  @spec armored?(binary()) :: boolean()
  def armored?(data) when is_binary(data) do
    data |> String.trim_leading() |> String.starts_with?(@armor_header)
  end

  defp key_list(key, _noun) when is_binary(key), do: {:ok, [key]}
  defp key_list([], noun), do: {:error, "no #{noun} provided"}

  defp key_list(keys, noun) when is_list(keys) do
    if Enum.all?(keys, &is_binary/1), do: {:ok, keys}, else: {:error, "#{noun} must be strings"}
  end

  defp key_list(_keys, noun), do: {:error, "#{noun} must be strings"}

  defp to_binary(data) when is_binary(data), do: data
  defp to_binary(data), do: IO.iodata_to_binary(data)

  defp armor?(opts), do: Keyword.get(opts, :armor, false) == true

  defp bang({:ok, value}), do: value
  defp bang({:error, reason}), do: raise(ExAge.Error, reason)
end
