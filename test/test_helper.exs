excluded =
  [age_cli: System.find_executable("age"), ssh_keygen: System.find_executable("ssh-keygen")]
  |> Enum.filter(fn {_tag, path} -> is_nil(path) end)
  |> Enum.map(fn {tag, _} -> {tag, true} end)

ExUnit.start(exclude: excluded)
