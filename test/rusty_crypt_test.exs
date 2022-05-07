defmodule RustyCryptTest do
  use ExUnit.Case
  doctest RustyCrypt

  test "sha224" do
    expected =
      <<107, 83, 115, 197, 53, 164, 250, 93, 86, 214, 196, 149, 53, 117, 206, 100, 150, 128, 49,
        187, 1, 155, 144, 159, 143, 45, 185, 4>>

    assert expected == RustyCrypt.sha224(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha224, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha256" do
    expected =
      <<31, 130, 90, 162, 240, 2, 14, 247, 207, 145, 223, 163, 13, 164, 102, 141, 121, 28, 93, 72,
        36, 252, 142, 65, 53, 75, 137, 236, 5, 121, 90, 179>>

    assert expected == RustyCrypt.sha256(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha256, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha384" do
    expected =
      <<24, 46, 149, 38, 106, 223, 244, 144, 89, 231, 6, 198, 20, 131, 71, 143, 224, 104, 129, 80,
        200, 208, 139, 149, 250, 181, 207, 222, 150, 31, 18, 217, 3, 170, 244, 65, 4, 175, 76,
        231, 43, 166, 164, 191, 32, 48, 43, 46>>

    assert expected == RustyCrypt.sha384(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha384, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  test "sha512" do
    expected =
      <<15, 137, 238, 31, 203, 123, 10, 79, 120, 9, 209, 38, 122, 2, 151, 25, 0, 76, 90, 94, 94,
        195, 35, 167, 195, 82, 58, 32, 151, 79, 154, 63, 32, 47, 86, 250, 219, 164, 205, 158, 141,
        101, 74, 185, 242, 233, 109, 197, 199, 149, 234, 23, 111, 162, 14, 222, 141, 133, 76, 52,
        47, 144, 53, 51>>

    assert expected == RustyCrypt.sha512(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha512, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
  end

  describe "aes256gcm_encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>,
         <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>}

      {:ok, {out, tag}} = RustyCrypt.aes256gcm_encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == RustyCrypt.aes256gcm_encrypt(<<0::256>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == RustyCrypt.aes256gcm_encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<83, 15, 138, 251, 199, 69, 54, 185, 169, 99, 180, 241, 196, 203, 115, 139>>}} ==
               RustyCrypt.aes256gcm_encrypt(<<0::256>>, <<0::96>>, "", "")
    end
  end

  describe "chacha20_poly1305_encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<98, 64, 52, 151, 243, 160, 97, 141, 82, 60, 106, 5, 93, 139>>,
         <<144, 70, 37, 214, 161, 8, 154, 151, 101, 195, 135, 97, 60, 226, 172, 76>>}

      {:ok, {out, tag}} = RustyCrypt.chacha20_poly1305_encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               RustyCrypt.chacha20_poly1305_encrypt(<<0::256>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               RustyCrypt.chacha20_poly1305_encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<78, 185, 114, 201, 168, 251, 58, 27, 56, 43, 180, 211, 111, 95, 250, 209>>}} ==
               RustyCrypt.chacha20_poly1305_encrypt(<<0::256>>, <<0::96>>, "", "")
    end
  end

  describe "aes256gcm_decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      data = <<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>
      aad = <<>>
      tag = <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>

      expected = "Just some text"

      assert {:ok, expected} == RustyCrypt.aes256gcm_decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               RustyCrypt.aes256gcm_decrypt(<<0::256>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               RustyCrypt.aes256gcm_decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               RustyCrypt.aes256gcm_decrypt(<<0::256>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               RustyCrypt.aes256gcm_decrypt(<<0::256>>, <<0::96>>, "", "", <<0::128>>)
    end
  end

  describe "chacha20_poly1305_decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      data = <<98, 64, 52, 151, 243, 160, 97, 141, 82, 60, 106, 5, 93, 139>>
      aad = <<>>
      tag = <<144, 70, 37, 214, 161, 8, 154, 151, 101, 195, 135, 97, 60, 226, 172, 76>>

      expected = "Just some text"

      assert {:ok, expected} == RustyCrypt.chacha20_poly1305_decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               RustyCrypt.chacha20_poly1305_decrypt(<<0::256>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               RustyCrypt.chacha20_poly1305_decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               RustyCrypt.chacha20_poly1305_decrypt(<<0::256>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               RustyCrypt.chacha20_poly1305_decrypt(<<0::256>>, <<0::96>>, "", "", <<0::128>>)
    end
  end
end
