defmodule RustyCrypt.Mac.Poly1305Test do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Mac

  alias RustyCrypt.Mac

  @secret <<-1::256>>

  @data <<15, 137, 238, 31, 203, 123, 10, 79, 120, 9, 209, 38, 122, 2, 151, 25, 0, 76, 90, 94, 94,
          195, 35, 167, 195, 82, 58, 32, 151, 79, 154, 63, 32, 47, 86, 250, 219, 164, 205, 158,
          141, 101, 74, 185, 242, 233, 109, 197, 199, 149, 234, 23, 111, 162, 14, 222, 141, 133,
          76, 52, 47, 144, 53, 51>>

  test "poly1305" do
    expected = <<84, 43, 67, 47, 215, 224, 106, 59, 180, 91, 141, 209, 127, 183, 35, 194>>

    assert expected == Mac.poly1305(@secret, @data)
    assert expected == :crypto.mac(:poly1305, @secret, @data)
  end

  test "poly1305, text" do
    expected = <<83, 151, 165, 208, 48, 159, 121, 165, 208, 154, 121, 165, 208, 154, 121, 165>>

    assert expected == Mac.poly1305(@secret, "tests")
    assert expected == :crypto.mac(:poly1305, @secret, "tests")
  end

  test "poly1305, empty" do
    expected = <<-1 :: 128>>

    assert expected == Mac.poly1305(@secret, "")
    assert expected == :crypto.mac(:poly1305, @secret, "")
  end

  test "poly1305, one" do
    expected = <<18, 255, 255, 15, 12, 252, 255, 15, 12, 252, 255, 15, 12, 252, 255, 15>>

    assert expected == Mac.poly1305(@secret, <<1>>)
    assert expected == :crypto.mac(:poly1305, @secret, <<1>>)
  end

  test "poly1305 invalid secret size" do
    assert {:error, :bad_key_length} == Mac.poly1305(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>, @data)
  end
end
