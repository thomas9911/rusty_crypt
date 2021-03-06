defmodule RustyCrypt.Mac.HmacTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Mac.Hmac

  alias RustyCrypt.Mac.Hmac

  @secret <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>

  @data <<15, 137, 238, 31, 203, 123, 10, 79, 120, 9, 209, 38, 122, 2, 151, 25, 0, 76, 90, 94, 94,
          195, 35, 167, 195, 82, 58, 32, 151, 79, 154, 63, 32, 47, 86, 250, 219, 164, 205, 158,
          141, 101, 74, 185, 242, 233, 109, 197, 199, 149, 234, 23, 111, 162, 14, 222, 141, 133,
          76, 52, 47, 144, 53, 51>>

  test "sha1" do
    expected =
      <<2, 63, 43, 55, 249, 120, 111, 185, 71, 172, 10, 109, 97, 149, 44, 20, 130, 100, 199, 37>>

    assert expected == Hmac.sha1(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha, @secret, @data)
  end

  test "sha2_224" do
    expected =
      <<209, 8, 202, 211, 28, 254, 147, 69, 96, 187, 162, 175, 83, 98, 209, 5, 55, 29, 82, 231,
        117, 111, 177, 45, 164, 13, 74, 141>>

    assert expected == Hmac.sha2_224(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha224, @secret, @data)
  end

  test "sha2_256" do
    expected =
      <<178, 69, 125, 109, 55, 97, 158, 177, 238, 0, 228, 156, 56, 58, 84, 228, 243, 236, 216,
        177, 194, 149, 192, 3, 84, 197, 29, 62, 235, 43, 209, 27>>

    assert expected == Hmac.sha2_256(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha256, @secret, @data)
  end

  test "sha2_384" do
    expected =
      <<182, 61, 11, 12, 121, 32, 179, 147, 41, 208, 165, 147, 222, 54, 175, 103, 217, 94, 248,
        175, 255, 207, 69, 201, 249, 161, 66, 163, 179, 229, 151, 137, 131, 63, 244, 9, 193, 251,
        131, 103, 253, 128, 245, 18, 18, 31, 21, 68>>

    assert expected == Hmac.sha2_384(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha384, @secret, @data)
  end

  test "sha2_512" do
    expected =
      <<106, 182, 136, 218, 34, 51, 106, 87, 140, 70, 99, 13, 143, 143, 224, 140, 145, 239, 237,
        54, 209, 120, 250, 160, 202, 175, 130, 75, 250, 238, 68, 175, 187, 121, 123, 19, 143, 133,
        219, 74, 230, 75, 150, 232, 218, 153, 85, 147, 57, 15, 7, 52, 110, 191, 167, 58, 154, 159,
        58, 239, 230, 113, 149, 249>>

    assert expected == Hmac.sha2_512(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha512, @secret, @data)
  end

  test "sha3_224" do
    expected =
      <<152, 13, 52, 123, 169, 219, 194, 184, 155, 19, 195, 97, 237, 66, 127, 141, 34, 220, 160,
        223, 231, 117, 214, 22, 200, 59, 235, 121>>

    assert expected == Hmac.sha3_224(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha3_224, @secret, @data)
  end

  test "sha3_256" do
    expected =
      <<67, 148, 155, 109, 139, 1, 173, 154, 174, 198, 39, 142, 48, 72, 224, 94, 171, 2, 52, 251,
        174, 182, 98, 231, 116, 218, 113, 253, 28, 104, 181, 103>>

    assert expected == Hmac.sha3_256(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha3_256, @secret, @data)
  end

  test "sha3_384" do
    expected =
      <<176, 21, 135, 16, 16, 214, 249, 248, 131, 236, 34, 109, 227, 110, 40, 208, 67, 87, 190,
        29, 162, 82, 210, 105, 147, 115, 141, 239, 132, 245, 57, 96, 129, 56, 123, 30, 252, 174,
        144, 159, 142, 239, 126, 12, 67, 142, 79, 229>>

    assert expected == Hmac.sha3_384(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha3_384, @secret, @data)
  end

  test "sha3_512" do
    expected =
      <<68, 193, 128, 0, 118, 253, 99, 244, 84, 141, 140, 139, 174, 241, 71, 73, 62, 138, 58, 232,
        15, 84, 0, 125, 130, 24, 125, 94, 237, 248, 127, 136, 44, 188, 57, 14, 16, 195, 88, 134,
        152, 162, 191, 54, 213, 225, 43, 14, 60, 143, 209, 124, 86, 170, 70, 45, 95, 50, 185, 145,
        192, 124, 183, 72>>

    assert expected == Hmac.sha3_512(@secret, @data)
    assert expected == :crypto.mac(:hmac, :sha3_512, @secret, @data)
  end
end
