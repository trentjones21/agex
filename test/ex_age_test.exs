defmodule ExAgeTest do
  use ExUnit.Case, async: true
  doctest ExAge

  # Low scrypt cost keeps passphrase tests fast. Real callers should use the default.
  @fast [work_factor: 10]

  describe "key generation" do
    test "produces a matching identity and recipient" do
      {identity, recipient} = ExAge.generate_identity()

      assert "AGE-SECRET-KEY-1" <> _ = identity
      assert "age1" <> _ = recipient
      assert ExAge.to_recipient(identity) == {:ok, recipient}
    end

    test "every call returns a fresh key" do
      refute ExAge.generate_identity() == ExAge.generate_identity()
    end

    test "rejects malformed identities" do
      assert {:error, "invalid identity"} = ExAge.to_recipient("not a key")
    end
  end

  describe "encrypt/3 and decrypt/2" do
    setup do
      {identity, recipient} = ExAge.generate_identity()
      %{identity: identity, recipient: recipient}
    end

    test "round-trips binary data", %{identity: identity, recipient: recipient} do
      plaintext = :crypto.strong_rand_bytes(100_000)

      assert {:ok, "age-encryption.org/v1\n" <> _ = ciphertext} =
               ExAge.encrypt(plaintext, recipient)

      assert ExAge.decrypt(ciphertext, identity) == {:ok, plaintext}
    end

    test "round-trips empty input", %{identity: identity, recipient: recipient} do
      assert {:ok, ciphertext} = ExAge.encrypt("", recipient)
      assert ExAge.decrypt(ciphertext, identity) == {:ok, ""}
    end

    test "accepts iodata", %{identity: identity, recipient: recipient} do
      assert {:ok, ciphertext} = ExAge.encrypt(["hello", ?\s, ["world"]], recipient)
      assert ExAge.decrypt(ciphertext, identity) == {:ok, "hello world"}
    end

    test "armor produces PEM text that decrypts", %{identity: identity, recipient: recipient} do
      assert {:ok, armored} = ExAge.encrypt("secret", recipient, armor: true)
      assert String.starts_with?(armored, "-----BEGIN AGE ENCRYPTED FILE-----")
      assert String.printable?(armored)
      assert ExAge.armored?(armored)
      assert ExAge.decrypt(armored, identity) == {:ok, "secret"}
    end

    test "any one of several recipients can decrypt" do
      {alice, alice_pub} = ExAge.generate_identity()
      {bob, bob_pub} = ExAge.generate_identity()
      {:ok, ciphertext} = ExAge.encrypt("shared", [alice_pub, bob_pub])

      assert ExAge.decrypt(ciphertext, alice) == {:ok, "shared"}
      assert ExAge.decrypt(ciphertext, bob) == {:ok, "shared"}
    end

    test "tries every supplied identity", %{identity: identity, recipient: recipient} do
      {other, _} = ExAge.generate_identity()
      {:ok, ciphertext} = ExAge.encrypt("data", recipient)

      assert ExAge.decrypt(ciphertext, [other, identity]) == {:ok, "data"}
    end

    test "accepts identity file contents", %{identity: identity, recipient: recipient} do
      file = """
      # created: 2026-09-27T00:00:00Z
      # public key: #{recipient}
      #{identity}
      """

      {:ok, ciphertext} = ExAge.encrypt("data", recipient)
      assert ExAge.decrypt(ciphertext, file) == {:ok, "data"}
    end

    test "fails with the wrong identity", %{recipient: recipient} do
      {other, _} = ExAge.generate_identity()
      {:ok, ciphertext} = ExAge.encrypt("data", recipient)

      assert {:error, "No matching keys found"} = ExAge.decrypt(ciphertext, other)
    end

    test "detects tampering", %{identity: identity, recipient: recipient} do
      {:ok, ciphertext} = ExAge.encrypt(String.duplicate("a", 1000), recipient)
      size = byte_size(ciphertext)
      <<head::binary-size(size - 10), byte, tail::binary>> = ciphertext
      tampered = <<head::binary, Bitwise.bxor(byte, 1), tail::binary>>

      assert {:error, _} = ExAge.decrypt(tampered, identity)
    end

    test "rejects bad inputs without leaking key material", %{identity: identity} do
      assert {:error, "invalid recipient: nope"} = ExAge.encrypt("x", "nope")
      assert {:error, "no recipients provided"} = ExAge.encrypt("x", [])
      assert {:error, "recipients must be strings"} = ExAge.encrypt("x", [:atom])
      assert {:error, "no identities provided"} = ExAge.decrypt("x", [])
      assert {:error, "invalid identity"} = ExAge.decrypt("x", "AGE-SECRET-KEY-1BOGUS")
      assert {:error, _} = ExAge.decrypt("not an age file", identity)
    end

    test "bang variants raise ExAge.Error", %{identity: identity, recipient: recipient} do
      assert ExAge.encrypt!("ok", recipient) |> ExAge.decrypt!(identity) == "ok"
      assert_raise ExAge.Error, "invalid recipient: nope", fn -> ExAge.encrypt!("x", "nope") end
    end
  end

  describe "passphrases" do
    test "round-trip" do
      {:ok, ciphertext} = ExAge.encrypt_with_passphrase("hunter2's data", "correct horse", @fast)

      assert ExAge.decrypt_with_passphrase(ciphertext, "correct horse") ==
               {:ok, "hunter2's data"}
    end

    test "round-trip with armor" do
      {:ok, armored} = ExAge.encrypt_with_passphrase("data", "pw", [armor: true] ++ @fast)

      assert ExAge.armored?(armored)
      assert ExAge.decrypt_with_passphrase!(armored, "pw") == "data"
    end

    test "fail with the wrong passphrase" do
      {:ok, ciphertext} = ExAge.encrypt_with_passphrase("data", "right", @fast)
      assert {:error, _} = ExAge.decrypt_with_passphrase(ciphertext, "wrong")
    end

    test "refuse files above the max work factor" do
      {:ok, ciphertext} = ExAge.encrypt_with_passphrase("data", "pw", work_factor: 12)

      assert {:error, reason} =
               ExAge.decrypt_with_passphrase(ciphertext, "pw", max_work_factor: 11)

      assert reason =~ "Excessive work parameter"
      refute reason =~ ~r/[\x{2066}-\x{2069}]/u
    end

    test "reject an out-of-range work factor instead of crashing" do
      assert {:error, "work factor must be between 1 and 63"} =
               ExAge.encrypt_with_passphrase("data", "pw", work_factor: 0)
    end

    test "cannot decrypt recipient-encrypted files" do
      {_identity, recipient} = ExAge.generate_identity()
      {:ok, ciphertext} = ExAge.encrypt("data", recipient)
      assert {:error, _} = ExAge.decrypt_with_passphrase(ciphertext, "pw")
    end
  end

  describe "concurrency" do
    test "many processes encrypt and decrypt in parallel" do
      {identity, recipient} = ExAge.generate_identity()

      1..200
      |> Task.async_stream(fn i ->
        msg = "message #{i}"
        {:ok, ct} = ExAge.encrypt(msg, recipient)
        {msg, ExAge.decrypt(ct, identity)}
      end)
      |> Enum.each(fn {:ok, {msg, result}} -> assert result == {:ok, msg} end)
    end
  end

  describe "ssh keys" do
    @describetag :ssh_keygen
    @describetag :tmp_dir

    for type <- ["ed25519", "rsa"] do
      test "#{type} keys round-trip", %{tmp_dir: dir} do
        key = Path.join(dir, "id")
        {_, 0} = System.cmd("ssh-keygen", ["-q", "-t", unquote(type), "-N", "", "-f", key])

        {:ok, ciphertext} = ExAge.encrypt("via ssh", File.read!(key <> ".pub"))
        assert ExAge.decrypt(ciphertext, File.read!(key)) == {:ok, "via ssh"}
      end
    end

    test "passphrase-protected keys are rejected clearly", %{tmp_dir: dir} do
      key = Path.join(dir, "id")
      {_, 0} = System.cmd("ssh-keygen", ["-q", "-t", "ed25519", "-N", "pw", "-f", key])
      {:ok, ciphertext} = ExAge.encrypt("x", File.read!(key <> ".pub"))

      assert ExAge.decrypt(ciphertext, File.read!(key)) ==
               {:error, "passphrase-protected SSH keys are not supported"}
    end
  end

  describe "interoperability with the reference age CLI" do
    @describetag :age_cli
    @describetag :tmp_dir

    test "the age CLI decrypts ExAge output", %{tmp_dir: dir} do
      {identity, recipient} = ExAge.generate_identity()
      key_file = Path.join(dir, "key.txt")
      File.write!(key_file, identity)

      for armor <- [false, true] do
        encrypted = Path.join(dir, "msg.age")
        File.write!(encrypted, ExAge.encrypt!("from elixir", recipient, armor: armor))
        assert {"from elixir", 0} = System.cmd("age", ["-d", "-i", key_file, encrypted])
      end
    end

    test "ExAge decrypts age CLI output", %{tmp_dir: dir} do
      key_file = Path.join(dir, "key.txt")
      {_, 0} = System.cmd("age-keygen", ["-o", key_file], stderr_to_stdout: true)
      {recipient, 0} = System.cmd("age-keygen", ["-y", key_file])
      recipient = String.trim(recipient)

      plain = Path.join(dir, "msg.txt")
      encrypted = Path.join(dir, "msg.age")
      File.write!(plain, "from the age CLI")
      {_, 0} = System.cmd("age", ["-a", "-r", recipient, "-o", encrypted, plain])

      assert ExAge.decrypt(File.read!(encrypted), File.read!(key_file)) ==
               {:ok, "from the age CLI"}
    end
  end
end
