defmodule RustyCrypt.ErlangTest do
  use ExUnit.Case, async: true

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

  describe "mac" do
    alias RustyCrypt.Random.Bytes

    setup do
      {:ok,
       %{
         key: Bytes.secure_random(24),
         data: Bytes.secure_random(4096)
       }}
    end

    test "hmac sha224", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha224, key, data])
    end

    test "hmac sha256", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha256, key, data])
    end

    test "hmac sha384", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha384, key, data])
    end

    test "hmac sha512", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha512, key, data])
    end

    test "hmac sha3_224", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha3_224, key, data])
    end

    test "hmac sha3_256", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha3_256, key, data])
    end

    test "hmac sha3_384", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha3_384, key, data])
    end

    test "hmac sha3_512", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha3_512, key, data])
    end

    test "hmac invalid method", %{key: key, data: data} do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :testing, key, data])
    end

    test "invalid method", %{key: key, data: data} do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :mac, [:testing, :testing, key, data])
    end
  end

  test "string_rand_bytes" do
    Enum.map([1, 12, 50, 100, 120, 512], fn amount ->
      erlang = :crypto.strong_rand_bytes(amount)
      output = RustyCrypt.Erlang.strong_rand_bytes(amount)

      assert byte_size(erlang) == byte_size(output)
    end)
  end

  test "bytes_to_integer" do
    assert_same(:crypto, RustyCrypt.Erlang, :bytes_to_integer, [
      <<255, 255, 255>>
    ])

    assert_same(:crypto, RustyCrypt.Erlang, :bytes_to_integer, [
      <<12, 12, 12, 23>>
    ])

    assert_same(:crypto, RustyCrypt.Erlang, :bytes_to_integer, [
      RustyCrypt.Erlang.strong_rand_bytes(512)
    ])
  end

  describe "exor" do
    test "same length binary" do
      assert_same(:crypto, RustyCrypt.Erlang, :exor, [
        <<255, 250, 195>>,
        <<4, 3, 1>>
      ])
    end

    test "diffent length binary" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :exor, [
        <<255, 250, 195>>,
        <<4, 3>>
      ])
    end

    test "same length list" do
      assert_same(:crypto, RustyCrypt.Erlang, :exor, [
        [255, 250, 195],
        [4, 3, 1]
      ])
    end

    test "diffent length list" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :exor, [
        [255, 250, 195],
        [4, 3]
      ])
    end

    test "same length mixed" do
      assert_same(:crypto, RustyCrypt.Erlang, :exor, [
        <<255, 250, 195>>,
        [4, 3, 1]
      ])
    end

    test "same length iolist" do
      assert_same(:crypto, RustyCrypt.Erlang, :exor, [
        [255, 250, [195]],
        [4, [3], 1]
      ])
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
