defmodule RustyCrypt.Hashing.Sha2Test do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Hashing.Sha2

  alias RustyCrypt.Hashing.Sha2

  test "sha224" do
    expected =
      <<107, 83, 115, 197, 53, 164, 250, 93, 86, 214, 196, 149, 53, 117, 206, 100, 150, 128, 49,
        187, 1, 155, 144, 159, 143, 45, 185, 4>>

    assert expected == Sha2.sha224(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha224, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha256" do
    expected =
      <<31, 130, 90, 162, 240, 2, 14, 247, 207, 145, 223, 163, 13, 164, 102, 141, 121, 28, 93, 72,
        36, 252, 142, 65, 53, 75, 137, 236, 5, 121, 90, 179>>

    assert expected == Sha2.sha256(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha256, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha384" do
    expected =
      <<24, 46, 149, 38, 106, 223, 244, 144, 89, 231, 6, 198, 20, 131, 71, 143, 224, 104, 129, 80,
        200, 208, 139, 149, 250, 181, 207, 222, 150, 31, 18, 217, 3, 170, 244, 65, 4, 175, 76,
        231, 43, 166, 164, 191, 32, 48, 43, 46>>

    assert expected == Sha2.sha384(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha384, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha512" do
    expected =
      <<15, 137, 238, 31, 203, 123, 10, 79, 120, 9, 209, 38, 122, 2, 151, 25, 0, 76, 90, 94, 94,
        195, 35, 167, 195, 82, 58, 32, 151, 79, 154, 63, 32, 47, 86, 250, 219, 164, 205, 158, 141,
        101, 74, 185, 242, 233, 109, 197, 199, 149, 234, 23, 111, 162, 14, 222, 141, 133, 76, 52,
        47, 144, 53, 51>>

    assert expected == Sha2.sha512(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha512, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end
end
