defmodule RustyCryptTest do
  use ExUnit.Case
  doctest RustyCrypt

  test "sha256" do
    expected =
      <<31, 130, 90, 162, 240, 2, 14, 247, 207, 145, 223, 163, 13, 164, 102, 141, 121, 28, 93, 72,
        36, 252, 142, 65, 53, 75, 137, 236, 5, 121, 90, 179>>

    assert expected = RustyCrypt.sha256(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected = :crypto.hash(:sha256, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end
end
