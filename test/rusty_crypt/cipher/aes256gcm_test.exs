defmodule RustyCrypt.Cipher.Aes256gcmTest do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Aes256gcm

  alias RustyCrypt.Cipher.Aes256gcm

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>,
         <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>}

      {:ok, {out, tag}} = Aes256gcm.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} == Aes256gcm.encrypt(<<0::256>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} == Aes256gcm.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<83, 15, 138, 251, 199, 69, 54, 185, 169, 99, 180, 241, 196, 203, 115, 139>>}} ==
               Aes256gcm.encrypt(<<0::256>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      data = <<99, 180, 87, 86, 212, 5, 8, 177, 204, 32, 41, 196, 233, 139>>
      aad = <<>>
      tag = <<236, 199, 6, 173, 88, 152, 242, 120, 175, 135, 64, 71, 169, 142, 109, 77>>

      expected = "Just some text"

      assert {:ok, expected} == Aes256gcm.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Aes256gcm.decrypt(<<0::256>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Aes256gcm.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Aes256gcm.decrypt(<<0::256>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Aes256gcm.decrypt(<<0::256>>, <<0::96>>, "", "", <<0::128>>)
    end
  end
end
