defmodule RustyCrypt.Cipher.Aes128ccmTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Aes128ccm

  alias RustyCrypt.Cipher.Aes128ccm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::128>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>,
         <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>}

      {:ok, {out, tag}} = Aes128ccm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_128_ccm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes128ccm.encrypt(<<0::128>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes128ccm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok, {"", <<56, 239, 23, 159, 166, 224, 159, 118, 200, 2, 123, 185>>}} ==
               Aes128ccm.encrypt(<<0::128>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::128>>
      data = <<56, 10, 131, 200, 231, 201, 206, 107, 193, 86, 243, 11, 54, 49>>
      aad = <<>>
      tag = <<180, 41, 191, 64, 33, 150, 161, 154, 111, 64, 128, 229>>

      expected = "Just some text"

      assert {:ok, expected} == Aes128ccm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_128_ccm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes128ccm.decrypt(<<0::128>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes128ccm.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes128ccm.decrypt(<<0::128>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes128ccm.decrypt(<<0::128>>, <<0::96>>, "", "", <<0::96>>)
    end
  end
end
