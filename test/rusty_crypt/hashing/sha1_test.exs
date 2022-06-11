defmodule RustyCrypt.Hashing.Sha1Test do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Hashing.Sha1

  alias RustyCrypt.Hashing.Sha1

  test "sha" do
    expected =
      <<73, 65, 121, 113, 74, 108, 214, 39, 35, 157, 254, 222, 223, 45, 233, 239, 153, 76, 175,
        3>>

    assert expected == Sha1.sha(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end
end
