defmodule RustyCrypt.ErlangTest do
  use ExUnit.Case

  def assert_same_exception(module_one, module_two, method, args) do
    exception =
      try do
        apply(module_one, method, args)
        flunk("assert_same_exception: This should never be reached")
      rescue
        e ->
          e
      end

    try do
      apply(module_two, method, args)
      flunk("assert_same_exception: This should never be reached")
    rescue
      e ->
        assert e == exception
    end
  end

  def assert_same(module_one, module_two, method, args) do
    assert apply(module_one, method, args) == apply(module_two, method, args)
  end

  describe "hash" do
    test "sha224" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha224, <<0::64>>])
    end

    test "sha256" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha256, <<0::64>>])
    end

    test "sha384" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha384, <<0::64>>])
    end

    test "sha512" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha512, <<0::64>>])
    end

    test "sha3_224" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha3_224, <<0::64>>])
    end

    test "sha3_256" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha3_256, <<0::64>>])
    end

    test "sha3_384" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha3_384, <<0::64>>])
    end

    test "sha3_512" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha3_512, <<0::64>>])
    end

    test "invalid method" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :hash, [:testing, <<0::64>>])
    end
  end

  describe "crypto_one_time_aead" do
    test "aes_256_gcm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_gcm,
        <<0::256>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

    test "aes_256_gcm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_gcm,
        <<0::256>>,
        <<1::96>>,
        <<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>,
        <<>>,
        <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>,
        false
      ])
    end

    test "aes_256_ccm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_ccm,
        <<0::256>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

    test "aes_256_ccm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_ccm,
        <<0::256>>,
        <<1::96>>,
        <<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>,
        <<>>,
        <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>,
        false
      ])
    end

    test "chacha20_poly1305 true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :chacha20_poly1305,
        <<0::256>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

    test "chacha20_poly1305 false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :chacha20_poly1305,
        <<0::256>>,
        <<1::96>>,
        <<98, 64, 52, 151, 243, 160, 97, 141, 82, 60, 106, 5, 93, 139>>,
        <<>>,
        <<144, 70, 37, 214, 161, 8, 154, 151, 101, 195, 135, 97, 60, 226, 172, 76>>,
        false
      ])
    end

    test "raises on invalid key" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_gcm,
        <<>>,
        <<1::96>>,
        <<>>,
        <<>>,
        true
      ])
    end

    test "raises on invalid iv" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_256_gcm,
        <<0::256>>,
        <<>>,
        <<>>,
        <<>>,
        true
      ])
    end

    test "invalid method" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :testing,
        <<0::256>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end
  end
end
