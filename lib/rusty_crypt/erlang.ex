defmodule RustyCrypt.Erlang do
  @moduledoc """
  Compatibilty interface with :crypto module.
  These functions should behave the same as the erlang functions
  (so functions, input and output should be the same)
  """

  def hash(:sha256, data) do
    RustyCrypt.sha256(data)
  end

  def hash(:sha384, data) do
    RustyCrypt.sha384(data)
  end

  def hash(:sha512, data) do
    RustyCrypt.sha512(data)
  end

  def hash(_, _) do
    raise ArgumentError
  end

  def crypto_one_time_aead(:aes_256_gcm, key, iv, text, aad, true) do
    key
    |> RustyCrypt.aes256gcm_encrypt(iv, text, aad)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:chacha20_poly1305, key, iv, text, aad, true) do
    key
    |> RustyCrypt.chacha20_poly1305_encrypt(iv, text, aad)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(_, _, _, _, _, _) do
    raise ArgumentError, message: "argument error: 'Not an AEAD cipher'"
  end

  def crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, tag, false) do
    key
    |> RustyCrypt.aes256gcm_decrypt(iv, data, aad, tag)
    |> unwrap_or_raise()
  end

  def crypto_one_time_aead(:chacha20_poly1305, key, iv, data, aad, tag, false) do
    key
    |> RustyCrypt.chacha20_poly1305_decrypt(iv, data, aad, tag)
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
