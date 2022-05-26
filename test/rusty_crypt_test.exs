defmodule RustyCryptTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt

  describe "xor" do
    test "cancels" do
      assert <<0::48>> == RustyCrypt.xor(<<0, 1, 2, 3, 4, 5>>, <<0, 1, 2, 3, 4, 5>>)
    end

    test "works" do
      assert <<5, 5, 1, 1, 5, 5>> == RustyCrypt.xor(<<0, 1, 2, 3, 4, 5>>, <<5, 4, 3, 2, 1, 0>>)
    end

    test "raises on different lengths" do
      assert_raise ArgumentError, "argument error", fn ->
        RustyCrypt.xor(<<0, 1, 2, 3, 4, 5>>, <<5, 3>>)
      end
    end
  end

  describe "bytes to integer" do
    test "zeroes" do
      assert 0 == RustyCrypt.bytes_to_integer(<<0::128>>)
    end

    test "ones" do
      assert 340_282_366_920_938_463_463_374_607_431_768_211_455 ==
               RustyCrypt.bytes_to_integer(<<-1::128>>)
    end

    test "text" do
      assert 2_159_240_844_166_015_654_621_946_877_147_252 ==
               RustyCrypt.bytes_to_integer("just some text")
    end
  end

  describe "mod_pow" do
    test "works" do
      assert <<9>> = :crypto.mod_pow(3, 2, 100)
      assert <<9>> = RustyCrypt.mod_pow(3, 2, 100)
      assert <<4>> = :crypto.mod_pow(3, 2, 5)
      assert <<4>> = RustyCrypt.mod_pow(3, 2, 5)
    end

    test "zero is empty" do
      assert <<>> = :crypto.mod_pow(-1, 2, 5)
      assert <<>> = RustyCrypt.mod_pow(-1, 2, 5)
    end

    test "negative number" do
      assert <<64>> = :crypto.mod_pow(-1, 3, 251)
      assert <<64>> = RustyCrypt.mod_pow(-1, 3, 251)
    end

    test "large integer" do
      assert <<40, 222, 94, 217, 5, 62, 150, 152, 135, 240>> =
               :crypto.mod_pow(1_235_456, 12_388_481, 17 ** 19 - 1)

      assert <<40, 222, 94, 217, 5, 62, 150, 152, 135, 240>> =
               RustyCrypt.mod_pow(1_235_456, 12_388_481, 17 ** 19 - 1)
    end

    test "binaries" do
      assert <<77, 114, 135, 242, 67, 175, 102, 10>> =
               :crypto.mod_pow(
                 <<23, 15, 46, 234, 112, 93>>,
                 <<91, 222, 192, 104, 23, 1, 23>>,
                 <<-1::64>>
               )

      assert <<77, 114, 135, 242, 67, 175, 102, 10>> =
               RustyCrypt.mod_pow(
                 <<23, 15, 46, 234, 112, 93>>,
                 <<91, 222, 192, 104, 23, 1, 23>>,
                 <<-1::64>>
               )
    end

    test "empty mod" do
      assert_raise ArgumentError, fn -> RustyCrypt.mod_pow(15, 2, 0) end
      assert_raise ArgumentError, fn -> RustyCrypt.mod_pow(15, 2, <<>>) end
    end

    test "empty power" do
      assert <<1>> == :crypto.mod_pow(15, 0, 123)
      assert <<1>> == RustyCrypt.mod_pow(15, 0, 123)
    end

    test "empty number" do
      assert <<>> == :crypto.mod_pow(0, 23, 123)
      assert <<>> == RustyCrypt.mod_pow(0, 23, 123)
    end
  end
end
