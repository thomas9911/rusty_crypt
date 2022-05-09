defmodule RustyCrypt.Erlang do
  @moduledoc """
  Compatibilty interface with :crypto module.
  These functions should behave the same as the erlang functions
  (so functions, input and output should be the same)
  """
  def supports(:hashs) do
    [:sha224, :sha256, :sha384, :sha512]
  end

  def supports(:ciphers) do
    [:aes_256_ccm, :aes_256_gcm, :chacha20_poly1305]
  end

  def hash(:sha224, data) do
    RustyCrypt.Hashing.Sha2.sha224(data)
  end

  def hash(:sha256, data) do
    RustyCrypt.Hashing.Sha2.sha256(data)
  end

  def hash(:sha384, data) do
    RustyCrypt.Hashing.Sha2.sha384(data)
  end

  def hash(:sha512, data) do
    RustyCrypt.Hashing.Sha2.sha512(data)
  end

  def hash(_, _) do
    raise ArgumentError
  end

  def crypto_one_time_aead(:aes_256_gcm, key, iv, text, aad, true) do
    key
    |> RustyCrypt.Cipher.Aes256gcm.encrypt(iv, text, aad)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:aes_256_ccm, key, iv, text, aad, true) do
    key
    |> RustyCrypt.Cipher.Aes256ccm.encrypt(iv, text, aad)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:chacha20_poly1305, key, iv, text, aad, true) do
    key
    |> RustyCrypt.Cipher.Chacha20Poly1305.encrypt(iv, text, aad)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(_, _, _, _, _, _) do
    raise ArgumentError, message: "argument error: 'Not an AEAD cipher'"
  end

  def crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, tag, false) do
    key
    |> RustyCrypt.Cipher.Aes256gcm.decrypt(iv, data, aad, tag)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:aes_256_ccm, key, iv, data, aad, tag, false) do
    key
    |> RustyCrypt.Cipher.Aes256ccm.decrypt(iv, data, aad, tag)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:chacha20_poly1305, key, iv, data, aad, tag, false) do
    key
    |> RustyCrypt.Cipher.Chacha20Poly1305.decrypt(iv, data, aad, tag)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(_, _, _, _, _, _, _) do
    raise ArgumentError, message: "argument error: 'Not an AEAD cipher'"
  end

  defp unwrap_or_raise({:ok, out}), do: out

  defp unwrap_or_raise({:error, :bad_iv_length}) do
    :erlang.error({:badarg, {'aead.c', 109}, 'Bad IV length'})
  end

  defp unwrap_or_raise({:error, :bad_key_length}) do
    :erlang.error({:badarg, {'aead.c', 90}, 'Unknown cipher'})
  end

  defp unwrap_or_raise({:error, :bad_tag_length}), do: :error
  defp unwrap_or_raise({:error, :decrypt_failed}), do: :error
end
