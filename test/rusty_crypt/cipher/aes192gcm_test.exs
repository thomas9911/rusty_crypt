defmodule RustyCrypt.Cipher.Aes192gcmTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Aes192gcm

  alias RustyCrypt.Cipher.Aes192gcm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::192>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<64, 93, 199, 214, 40, 197, 133, 94, 58, 117, 92, 84, 189, 234>>,
         <<102, 38, 51, 89, 70, 77, 94, 194, 161, 198, 181, 23, 170, 174, 61, 27>>}

      {:ok, {out, tag}} = Aes192gcm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_192_gcm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes192gcm.encrypt(<<0::192>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes192gcm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<205, 51, 178, 138, 199, 115, 247, 75, 160, 14, 209, 243, 18, 87, 36, 53>>}} ==
               Aes192gcm.encrypt(<<0::192>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::192>>
      data = <<64, 93, 199, 214, 40, 197, 133, 94, 58, 117, 92, 84, 189, 234>>
      aad = <<>>
      tag = <<102, 38, 51, 89, 70, 77, 94, 194, 161, 198, 181, 23, 170, 174, 61, 27>>

      expected = "Just some text"

      assert {:ok, expected} == Aes192gcm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_192_gcm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes192gcm.decrypt(<<0::192>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes192gcm.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes192gcm.decrypt(<<0::192>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes192gcm.decrypt(<<0::192>>, <<0::96>>, "", "", <<0::128>>)
    end
  end
end
