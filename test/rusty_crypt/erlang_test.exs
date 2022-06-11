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
      e in ErlangError ->
        case {e, exception} do
          {%ErlangError{
            original: {erlang_error, {file, _}, message},
            reason: reason
          },  %ErlangError{
            original: {erlang_error2, {file2, _}, message2},
            reason: reason2
          } } ->
            assert {erlang_error, file, message, reason} == {erlang_error2, file2, message2, reason2}

          {e, exception} ->
            assert e == exception
        end

      e ->
        assert e == exception
    end
  end

  def assert_same(module_one, module_two, method, args) do
    assert apply(module_one, method, args) == apply(module_two, method, args)
  end

  describe "hash" do
    test "sha" do
      assert_same(:crypto, RustyCrypt.Erlang, :hash, [:sha, <<0::64>>])
    end

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

    test "poly1305/3", %{data: data} do
      key = Bytes.secure_random(32)

      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:poly1305, key, data])
    end

    test "poly1305/4", %{data: data} do
      key = Bytes.secure_random(32)

      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:poly1305, nil, key, data])
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:poly1305, "whatever", key, data])
    end

    test "poly1305 invalid secret length", %{data: data} do
      key = Bytes.secure_random(15)

      assert_same_exception(:crypto, RustyCrypt.Erlang, :mac, [:poly1305, key, data])
    end

    test "hmac sha1", %{key: key, data: data} do
      assert_same(:crypto, RustyCrypt.Erlang, :mac, [:hmac, :sha, key, data])
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

  describe "mod_pow" do
    test "works" do
      assert_same(:crypto, RustyCrypt.Erlang, :mod_pow, [
        <<123, 123, 123>>,
        <<123, 123, 121>>,
        <<123, 123, 121, 123>>
      ])
    end

    test "raise on zero mod" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :mod_pow, [
        <<123, 123, 123>>,
        <<123, 123, 121>>,
        0
      ])
    end
  end

  describe "crypto_one_time_aead" do
    test "aes_gcm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_gcm,
        <<0::128>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])

      assert RustyCrypt.Erlang.crypto_one_time_aead(
               :aes_gcm,
               <<0::128>>,
               <<1::96>>,
               "Just some text",
               <<>>,
               true
             ) ==
               RustyCrypt.Erlang.crypto_one_time_aead(
                 :aes_128_gcm,
                 <<0::128>>,
                 <<1::96>>,
                 "Just some text",
                 <<>>,
                 true
               )
    end

    test "aes_128_gcm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_128_gcm,
        <<0::128>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

    test "aes_192_gcm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_192_gcm,
        <<0::192>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

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

    test "aes_gcm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_gcm,
        <<0::128>>,
        <<1::96>>,
        <<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>,
        <<>>,
        <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>,
        false
      ])

      assert RustyCrypt.Erlang.crypto_one_time_aead(
               :aes_128_gcm,
               <<0::128>>,
               <<1::96>>,
               <<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>,
               <<>>,
               <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>,
               false
             ) ==
               RustyCrypt.Erlang.crypto_one_time_aead(
                 :aes_gcm,
                 <<0::128>>,
                 <<1::96>>,
                 <<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>,
                 <<>>,
                 <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>,
                 false
               )
    end

    test "aes_128_gcm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_128_gcm,
        <<0::128>>,
        <<1::96>>,
        <<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>,
        <<>>,
        <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>,
        false
      ])
    end

    test "aes_192_gcm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_192_gcm,
        <<0::192>>,
        <<1::96>>,
        <<64, 93, 199, 214, 40, 197, 133, 94, 58, 117, 92, 84, 189, 234>>,
        <<>>,
        <<102, 38, 51, 89, 70, 77, 94, 194, 161, 198, 181, 23, 170, 174, 61, 27>>,
        false
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

    test "aes_ccm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_ccm,
        <<0::128>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])

      assert RustyCrypt.Erlang.crypto_one_time_aead(
               :aes_ccm,
               <<0::128>>,
               <<1::96>>,
               "Just some text",
               <<>>,
               true
             ) ==
               RustyCrypt.Erlang.crypto_one_time_aead(
                 :aes_128_ccm,
                 <<0::128>>,
                 <<1::96>>,
                 "Just some text",
                 <<>>,
                 true
               )
    end

    test "aes_128_ccm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_128_ccm,
        <<0::128>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
      ])
    end

    test "aes_192_ccm true" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_192_ccm,
        <<0::192>>,
        <<1::96>>,
        "Just some text",
        <<>>,
        true
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

    test "aes_ccm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_ccm,
        <<0::128>>,
        <<1::96>>,
        <<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>,
        <<>>,
        <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>,
        false
      ])

      assert RustyCrypt.Erlang.crypto_one_time_aead(
               :aes_ccm,
               <<0::128>>,
               <<1::96>>,
               <<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>,
               <<>>,
               <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>,
               false
             ) ==
               RustyCrypt.Erlang.crypto_one_time_aead(
                 :aes_128_ccm,
                 <<0::128>>,
                 <<1::96>>,
                 <<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>,
                 <<>>,
                 <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>,
                 false
               )
    end

    test "aes_128_ccm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_128_ccm,
        <<0::128>>,
        <<1::96>>,
        <<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>,
        <<>>,
        <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>,
        false
      ])
    end

    test "aes_192_ccm false" do
      assert_same(:crypto, RustyCrypt.Erlang, :crypto_one_time_aead, [
        :aes_192_ccm,
        <<0::192>>,
        <<1::96>>,
        <<60, 63, 243, 85, 24, 229, 137, 246, 180, 125, 102, 56, 131, 31>>,
        <<>>,
        <<220, 207, 91, 230, 5, 24, 35, 119, 242, 24, 63, 248>>,
        false
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

  describe "rand_uniform" do
    test "works" do
      assert RustyCrypt.Erlang.rand_uniform(0, 100) in 0..99
      # we call it in this weird way because otherwise it prints a deprecation warning
      # if this stops working call :rand.uniform(0, 100)
      assert apply(:crypto, :rand_uniform, [0, 100]) in 0..99
    end

    test "exclusive range" do
      assert_same(:crypto, RustyCrypt.Erlang, :rand_uniform, [
        0,
        1
      ])
    end

    test "reverse low, high" do
      assert_same_exception(:crypto, RustyCrypt.Erlang, :rand_uniform, [
        100,
        -100
      ])
    end
  end
end
