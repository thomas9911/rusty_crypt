defmodule RustyCrypt.Cipher.Aes128gcmTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Aes128gcm

  alias RustyCrypt.Cipher.Aes128gcm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::128>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>,
         <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>}

      {:ok, {out, tag}} = Aes128gcm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_128_gcm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes128gcm.encrypt(<<0::128>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes128gcm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<88, 226, 252, 206, 250, 126, 48, 97, 54, 127, 29, 87, 164, 231, 69, 90>>}} ==
               Aes128gcm.encrypt(<<0::128>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::128>>
      data = <<36, 116, 170, 68, 39, 251, 29, 208, 62, 18, 152, 241, 29, 137>>
      aad = <<>>
      tag = <<253, 210, 77, 81, 182, 110, 51, 81, 68, 91, 116, 206, 64, 158, 31, 239>>

      expected = "Just some text"

      assert {:ok, expected} == Aes128gcm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_128_gcm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes128gcm.decrypt(<<0::128>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes128gcm.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes128gcm.decrypt(<<0::128>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes128gcm.decrypt(<<0::128>>, <<0::96>>, "", "", <<0::128>>)
    end
  end
end
