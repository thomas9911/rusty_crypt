defmodule RustyCryptTest do
  use ExUnit.Case
  doctest RustyCrypt

  test "sha256" do
    expected =
      <<31, 130, 90, 162, 240, 2, 14, 247, 207, 145, 223, 163, 13, 164, 102, 141, 121, 28, 93, 72,
        36, 252, 142, 65, 53, 75, 137, 236, 5, 121, 90, 179>>

    assert expected == RustyCrypt.sha256(<<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
    assert expected == :crypto.hash(:sha256, <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9>>)
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
  end
end
