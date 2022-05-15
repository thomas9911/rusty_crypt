defmodule RustyCrypt.Cipher.Chacha20Poly1305Test do
  use ExUnit.Case, async: true
  doctest RustyCrypt.Cipher.Chacha20Poly1305

  alias RustyCrypt.Cipher.Chacha20Poly1305

  describe "encrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      text = "Just some text"
      aad = <<>>

      {expected_out, expected_tag} =
        {<<98, 64, 52, 151, 243, 160, 97, 141, 82, 60, 106, 5, 93, 139>>,
         <<144, 70, 37, 214, 161, 8, 154, 151, 101, 195, 135, 97, 60, 226, 172, 76>>}

      {:ok, {out, tag}} = Chacha20Poly1305.encrypt(key, iv, text, aad)

      {out_erlang, tag_erlang} =
        :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, text, aad, true)

      assert expected_out == out
      assert expected_tag == tag
      assert expected_out == out_erlang
      assert expected_tag == tag_erlang
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Chacha20Poly1305.encrypt(<<0::256>>, <<>>, "", "")
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Chacha20Poly1305.encrypt(<<>>, <<0::96>>, "", "")
    end

    test "empty data" do
      assert {:ok,
              {"", <<78, 185, 114, 201, 168, 251, 58, 27, 56, 43, 180, 211, 111, 95, 250, 209>>}} ==
               Chacha20Poly1305.encrypt(<<0::256>>, <<0::96>>, "", "")
    end
  end

  describe "decrypt" do
    test "works" do
      iv = <<1::96>>
      key = <<0::256>>
      data = <<98, 64, 52, 151, 243, 160, 97, 141, 82, 60, 106, 5, 93, 139>>
      aad = <<>>
      tag = <<144, 70, 37, 214, 161, 8, 154, 151, 101, 195, 135, 97, 60, 226, 172, 76>>

      expected = "Just some text"

      assert {:ok, expected} == Chacha20Poly1305.decrypt(key, iv, data, aad, tag)

      assert expected ==
               :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, data, aad, tag, false)
    end

    test "invalid iv" do
      assert {:error, :bad_iv_length} ==
               Chacha20Poly1305.decrypt(<<0::256>>, <<>>, "", "", <<0::128>>)
    end

    test "invalid key" do
      assert {:error, :bad_key_length} ==
               Chacha20Poly1305.decrypt(<<>>, <<0::96>>, "", "", <<0::128>>)
    end

    test "invalid tag" do
      assert {:error, :bad_tag_length} ==
               Chacha20Poly1305.decrypt(<<0::256>>, <<0::96>>, "", "", "")
    end

    test "invalid data" do
      assert {:error, :decrypt_failed} ==
               Chacha20Poly1305.decrypt(<<0::256>>, <<0::96>>, "", "", <<0::128>>)
    end
  end
end
