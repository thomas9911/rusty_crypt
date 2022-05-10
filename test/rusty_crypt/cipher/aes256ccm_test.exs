defmodule RustyCrypt.Cipher.Aes256ccmTest do
  use ExUnit.Case
  doctest RustyCrypt.Cipher.Aes256ccm

  alias RustyCrypt.Cipher.Aes256ccm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<184, 195, 116, 44, 205, 227, 34, 186, 31, 34, 128, 44, 162, 37>>,
         <<21, 46, 43, 122, 65, 93, 140, 62, 168, 110, 179, 146>>}

      {:ok, {out, tag}} = Aes256ccm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_256_ccm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes256ccm.encrypt(<<0::256>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes256ccm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok, {"", <<59, 153, 174, 101, 73, 68, 120, 152, 70, 178, 237, 190>>}} ==
               Aes256ccm.encrypt(<<0::256>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      data = <<184, 195, 116, 44, 205, 227, 34, 186, 31, 34, 128, 44, 162, 37>>
      aad = <<>>
      tag = <<21, 46, 43, 122, 65, 93, 140, 62, 168, 110, 179, 146>>

      expected = "Just some text"

      assert {:ok, expected} == Aes256ccm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_256_ccm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes256ccm.decrypt(<<0::256>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes256ccm.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes256ccm.decrypt(<<0::256>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes256ccm.decrypt(<<0::256>>, <<0::96>>, "", "", <<0::96>>)
    end
  end
end
