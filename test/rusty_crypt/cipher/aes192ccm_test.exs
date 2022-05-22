defmodule RustyCrypt.Cipher.Aes192ccmTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Aes192ccm

  alias RustyCrypt.Cipher.Aes192ccm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::192>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<60, 63, 243, 85, 24, 229, 137, 246, 180, 125, 102, 56, 131, 31>>,
         <<220, 207, 91, 230, 5, 24, 35, 119, 242, 24, 63, 248>>}

      {:ok, {out, tag}} = Aes192ccm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_192_ccm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes192ccm.encrypt(<<0::192>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes192ccm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok, {"", <<110, 222, 81, 146, 195, 174, 24, 53, 212, 200, 145, 26>>}} ==
               Aes192ccm.encrypt(<<0::192>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::192>>
      data = <<60, 63, 243, 85, 24, 229, 137, 246, 180, 125, 102, 56, 131, 31>>
      aad = <<>>
      tag = <<220, 207, 91, 230, 5, 24, 35, 119, 242, 24, 63, 248>>

      expected = "Just some text"

      assert {:ok, expected} == Aes192ccm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_192_ccm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes192ccm.decrypt(<<0::192>>, <<>>, "", "", <<0::192>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes192ccm.decrypt(<<>>, <<0::96>>, "", "", <<0::192>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes192ccm.decrypt(<<0::192>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes192ccm.decrypt(<<0::192>>, <<0::96>>, "", "", <<0::96>>)
    end
  end
end
