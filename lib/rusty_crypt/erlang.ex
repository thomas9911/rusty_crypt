defmodule RustyCrypt.Erlang do
  @moduledoc """
  Compatibilty interface with :crypto module.
  These functions should behave the same as the erlang functions
  (so functions, input and output should be the same)
  """
  def supports(:hashs) do
    [:sha224, :sha256, :sha384, :sha512, :sha3_224, :sha3_256, :sha3_384, :sha3_512]
  end

  def supports(:ciphers) do
    [:aes_256_ccm, :aes_256_gcm, :chacha20_poly1305]
  end

  def hash(:sha, data) do
    RustyCrypt.Hashing.Sha1.sha(data)
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

  def hash(:sha3_224, data) do
    RustyCrypt.Hashing.Sha3.sha224(data)
  end

  def hash(:sha3_256, data) do
    RustyCrypt.Hashing.Sha3.sha256(data)
  end

  def hash(:sha3_384, data) do
    RustyCrypt.Hashing.Sha3.sha384(data)
  end

  def hash(:sha3_512, data) do
    RustyCrypt.Hashing.Sha3.sha512(data)
  end

  def hash(_, _) do
    raise ArgumentError
  end

  def mac(:poly1305, key, data) do
    mac(:poly1305, nil, key, data)
  end

  def mac(:poly1305, _, key, data) do
    key
    |> RustyCrypt.Mac.poly1305(data)
    |> unwrap_or_raise(:mac)
  end

  def mac(:hmac, :sha, key, data) do
    RustyCrypt.Mac.Hmac.sha1(key, data)
  end

  def mac(:hmac, :sha224, key, data) do
    RustyCrypt.Mac.Hmac.sha2_224(key, data)
  end

  def mac(:hmac, :sha256, key, data) do
    RustyCrypt.Mac.Hmac.sha2_256(key, data)
  end

  def mac(:hmac, :sha384, key, data) do
    RustyCrypt.Mac.Hmac.sha2_384(key, data)
  end

  def mac(:hmac, :sha512, key, data) do
    RustyCrypt.Mac.Hmac.sha2_512(key, data)
  end

  def mac(:hmac, :sha3_224, key, data) do
    RustyCrypt.Mac.Hmac.sha3_224(key, data)
  end

  def mac(:hmac, :sha3_256, key, data) do
    RustyCrypt.Mac.Hmac.sha3_256(key, data)
  end

  def mac(:hmac, :sha3_384, key, data) do
    RustyCrypt.Mac.Hmac.sha3_384(key, data)
  end

  def mac(:hmac, :sha3_512, key, data) do
    RustyCrypt.Mac.Hmac.sha3_512(key, data)
  end

  def mac(:hmac, _, _, _) do
    :erlang.error({:badarg, {'mac.c', 259}, 'Bad digest algorithm for HMAC'})
  end

  def mac(_, _, _, _) do
    :erlang.error({:badarg, {'mac.c', 229}, 'Unknown mac algorithm'})
  end

  @doc deprecated: """
       Use `RustyCrypt.Erlang.mac/4` instead. This function was removed in OTP 24
       (ofcourse we are not linked to OTP because we use Rust implementations)
       """
  def hmac(method, key, data) do
    mac(:hmac, method, key, data)
  end

  %{
    :aes_gcm => RustyCrypt.Cipher.Aes128gcm,
    :aes_128_gcm => RustyCrypt.Cipher.Aes128gcm,
    :aes_192_gcm => RustyCrypt.Cipher.Aes192gcm,
    :aes_256_gcm => RustyCrypt.Cipher.Aes256gcm,
    :aes_ccm => RustyCrypt.Cipher.Aes128ccm,
    :aes_128_ccm => RustyCrypt.Cipher.Aes128ccm,
    :aes_192_ccm => RustyCrypt.Cipher.Aes192ccm,
    :aes_256_ccm => RustyCrypt.Cipher.Aes256ccm,
    :chacha20_poly1305 => RustyCrypt.Cipher.Chacha20Poly1305
  }
  |> Enum.map(fn {method, module} ->
    def crypto_one_time_aead(unquote(method), key, iv, text, aad, true) do
      key
      |> unquote(module).encrypt(iv, text, aad)
      |> unwrap_or_raise()
    end

    def crypto_one_time_aead(unquote(method), key, iv, data, aad, tag, false) do
      key
      |> unquote(module).decrypt(iv, data, aad, tag)
      |> unwrap_or_raise()
    end
  end)

  def crypto_one_time_aead(_, _, _, _, _, _) do
    raise ArgumentError, message: "argument error: 'Not an AEAD cipher'"
  end

  def crypto_one_time_aead(_, _, _, _, _, _, _) do
    raise ArgumentError, message: "argument error: 'Not an AEAD cipher'"
  end

  defdelegate strong_rand_bytes(amount), to: RustyCrypt.Random.Bytes, as: :secure_random

  defdelegate bytes_to_integer(binary), to: RustyCrypt

  defdelegate exor(bin1, bin2), to: RustyCrypt, as: :xor

  defdelegate mod_pow(n, p, m), to: RustyCrypt

  defdelegate rand_uniform(low, high), to: RustyCrypt.Random, as: :uniform

  @spec unwrap_or_raise(any, atom) :: any
  defp unwrap_or_raise(result, path \\ :aead)
  defp unwrap_or_raise({:ok, out}, _), do: out

  defp unwrap_or_raise({:error, :bad_iv_length}, _) do
    :erlang.error({:badarg, {'aead.c', 109}, 'Bad IV length'})
  end

  defp unwrap_or_raise({:error, :bad_key_length}, :mac) do
    :erlang.error({:badarg, {'mac.c', 231}, 'Bad key length'})
  end

  defp unwrap_or_raise({:error, :bad_key_length}, _) do
    :erlang.error({:badarg, {'aead.c', 90}, 'Unknown cipher'})
  end

  defp unwrap_or_raise({:error, :bad_tag_length}, _), do: :error
  defp unwrap_or_raise({:error, :decrypt_failed}, _), do: :error
  defp unwrap_or_raise(result, :mac) when is_binary(result), do: result
end
