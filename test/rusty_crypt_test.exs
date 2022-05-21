defmodule RustyCryptTest do
  use ExUnit.Case
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
end
